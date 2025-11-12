<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';
require_login();

$noteId = (int)($_GET['id'] ?? 0);
if ($noteId <= 0) {
    http_response_code(404);
    exit('Note not found.');
}

$note = notes_fetch($noteId);
if (!$note) {
    http_response_code(404);
    exit('Note not found.');
}

if (!notes_can_view($note)) {
    http_response_code(403);
    exit('You do not have access to this note.');
}

$meId = (int)(current_user()['id'] ?? 0);

function notes_edit_is_ajax(): bool
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower((string)$_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function notes_editor_parse_blocks(string $text): array
{
    $lines = preg_split('/\r?\n/', $text) ?: [];
    $blocks = [];
    $listMode = null;
    $listItems = [];

    $flushList = static function () use (&$blocks, &$listMode, &$listItems) {
        if ($listMode && $listItems) {
            $blocks[] = [
                'uid'   => notes_generate_block_uid(),
                'type'  => $listMode,
                'text'  => '',
                'items' => $listItems,
            ];
        }
        $listMode = null;
        $listItems = [];
    };

    foreach ($lines as $line) {
        $raw = rtrim((string)$line);
        $trim = trim($raw);
        if ($trim === '') {
            $flushList();
            continue;
        }
        if (preg_match('/^#\s+(.*)$/', $trim, $m)) {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'heading1', 'text' => $m[1]];
        } elseif (preg_match('/^##\s+(.*)$/', $trim, $m)) {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'heading2', 'text' => $m[1]];
        } elseif (preg_match('/^###\s+(.*)$/', $trim, $m)) {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'heading3', 'text' => $m[1]];
        } elseif (preg_match('/^-\s+\[( |x|X)\]\s*(.*)$/', $trim, $m)) {
            $flushList();
            $blocks[] = [
                'uid'     => notes_generate_block_uid(),
                'type'    => 'todo',
                'text'    => $m[2],
                'checked' => strtolower($m[1]) === 'x',
            ];
        } elseif (preg_match('/^-\s+(.*)$/', $trim, $m)) {
            if ($listMode !== 'bulleted') {
                $flushList();
                $listMode = 'bulleted';
            }
            $listItems[] = $m[1];
        } elseif (preg_match('/^\d+\.\s+(.*)$/', $trim, $m)) {
            if ($listMode !== 'numbered') {
                $flushList();
                $listMode = 'numbered';
            }
            $listItems[] = $m[1];
        } elseif (preg_match('/^>\s?(.*)$/', $trim, $m)) {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'quote', 'text' => $m[1]];
        } elseif (preg_match('/^!\s+(.*)$/', $trim, $m)) {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'callout', 'text' => $m[1], 'icon' => '💡'];
        } elseif ($trim === '---') {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'divider'];
        } else {
            $flushList();
            $blocks[] = ['uid' => notes_generate_block_uid(), 'type' => 'paragraph', 'text' => $raw];
        }
    }
    $flushList();

    return array_values(array_filter($blocks, static function ($block) {
        if (!is_array($block)) {
            return false;
        }
        $text = trim((string)($block['text'] ?? ''));
        if (($block['type'] ?? '') === 'divider') {
            return true;
        }
        if (in_array($block['type'] ?? '', ['bulleted','numbered'], true)) {
            return !empty($block['items']);
        }
        if (($block['type'] ?? '') === 'todo') {
            return $text !== '';
        }
        return $text !== '';
    }));
}

function notes_blocks_to_editor(array $blocks, string $fallback): string
{
    if (!$blocks) {
        return $fallback;
    }
    $lines = [];
    foreach ($blocks as $block) {
        $type = $block['type'] ?? 'paragraph';
        $text = (string)($block['text'] ?? '');
        switch ($type) {
            case 'heading1':
                $lines[] = '# ' . $text;
                break;
            case 'heading2':
                $lines[] = '## ' . $text;
                break;
            case 'heading3':
                $lines[] = '### ' . $text;
                break;
            case 'todo':
                $lines[] = '- [' . (!empty($block['checked']) ? 'x' : ' ') . '] ' . $text;
                break;
            case 'bulleted':
                foreach ($block['items'] ?? [] as $item) {
                    $lines[] = '- ' . $item;
                }
                break;
            case 'numbered':
                $idx = 0;
                foreach ($block['items'] ?? [] as $item) {
                    $idx++;
                    $lines[] = $idx . '. ' . $item;
                }
                break;
            case 'quote':
                $lines[] = '> ' . $text;
                break;
            case 'callout':
                $lines[] = '! ' . $text;
                break;
            case 'divider':
                $lines[] = '---';
                break;
            default:
                $lines[] = $text;
        }
        $lines[] = '';
    }
    return trim(implode("\n", $lines));
}

if (is_post()) {
    $isAjax = notes_edit_is_ajax();
    $error = '';
    $payload = null;

    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        $error = 'Security token expired. Please refresh and try again.';
    } elseif (isset($_POST['update_note_shares'])) {
        if (!notes_can_share($note)) {
            $error = 'You cannot change sharing on this note.';
        } else {
            $selected = array_map('intval', (array)($_POST['shared_ids'] ?? []));
            try {
                $result = notes_apply_shares($noteId, $selected, $note, true);
                $payload = [
                    'ok'       => true,
                    'note_id'  => $noteId,
                    'selected' => $result['after'],
                    'shares'   => notes_get_share_details($noteId),
                ];
            } catch (Throwable $e) {
                error_log('notes: share update failed (edit): ' . $e->getMessage());
                $error = 'Unable to update shares.';
            }
        }
    } elseif (isset($_POST['save_note'])) {
        $title    = trim((string)($_POST['title'] ?? 'Untitled note'));
        $noteDate = trim((string)($_POST['note_date'] ?? date('Y-m-d')));
        $status   = notes_normalize_status($_POST['status'] ?? NOTES_DEFAULT_STATUS);
        $icon     = trim((string)($_POST['icon'] ?? '')) ?: null;
        $cover    = trim((string)($_POST['cover_url'] ?? '')) ?: null;
        $project  = trim((string)($_POST['property_project'] ?? ''));
        $location = trim((string)($_POST['property_location'] ?? ''));
        $dueDate  = trim((string)($_POST['property_due_date'] ?? ''));
        $priority = trim((string)($_POST['property_priority'] ?? 'Medium'));
        $tagInput = trim((string)($_POST['tags'] ?? ''));
        $editor   = (string)($_POST['editor_content'] ?? '');

        if ($title === '') {
            $error = 'Title is required.';
        } elseif ($noteDate === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $noteDate)) {
            $error = 'Provide a valid date (YYYY-MM-DD).';
        } elseif ($dueDate !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $dueDate)) {
            $error = 'Due date must follow YYYY-MM-DD format.';
        } else {
            $blocks = notes_editor_parse_blocks($editor);
            $plainBody = $blocks ? notes_blocks_to_plaintext($blocks) : trim($editor);

            $properties = notes_normalize_properties([
                'project'  => $project,
                'location' => $location,
                'due_date' => $dueDate,
                'priority' => $priority,
            ]);

            $tags = [];
            if ($tagInput !== '') {
                $parts = preg_split('/[,;\n]/', $tagInput) ?: [];
                foreach ($parts as $part) {
                    $label = trim((string)$part);
                    if ($label !== '') {
                        $tags[] = ['label' => $label];
                    }
                }
            }

            try {
                notes_update($noteId, [
                    'note_date'  => $noteDate,
                    'title'      => $title,
                    'body'       => $plainBody,
                    'icon'       => $icon,
                    'cover_url'  => $cover,
                    'status'     => $status,
                    'properties' => $properties,
                    'tags'       => notes_normalize_tags_input($tags),
                    'blocks'     => $blocks,
                ]);
                redirect_with_message('edit.php?id=' . $noteId, 'Note updated.', 'success');
            } catch (Throwable $e) {
                error_log('notes: update failed: ' . $e->getMessage());
                $error = 'Unable to save note.';
            }
        }
    } elseif (isset($_POST['create_template'])) {
        $templateName = trim((string)($_POST['template_name'] ?? ''));
        if ($templateName === '') {
            $templateName = ($note['title'] ?? 'Untitled note') . ' template';
        }
        try {
            notes_create_template_from_note($noteId, $meId, $templateName);
            redirect_with_message('edit.php?id=' . $noteId, 'Template saved from this note.', 'success');
        } catch (Throwable $e) {
            error_log('notes: create template failed: ' . $e->getMessage());
            $error = 'Unable to create template.';
        }
    }

    if ($isAjax && isset($_POST['update_note_shares'])) {
        header('Content-Type: application/json; charset=utf-8');
        if ($error !== '') {
            http_response_code(400);
            echo json_encode(['ok' => false, 'message' => $error], JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode($payload ?? ['ok' => true], JSON_UNESCAPED_UNICODE);
        }
        exit;
    }

    if ($error !== '') {
        redirect_with_message('edit.php?id=' . $noteId, $error, 'error');
    }
}

$meta       = notes_fetch_page_meta($noteId);
$properties = notes_normalize_properties($meta['properties'] ?? []);
$tags       = notes_fetch_note_tags($noteId);
$blocks     = notes_fetch_blocks($noteId);
$bodyText   = trim((string)($note['body'] ?? ''));
$editorContent = notes_blocks_to_editor($blocks, $bodyText);
$statuses   = notes_available_statuses();
$shares     = notes_get_share_details($noteId);
$shareIds   = array_map(static fn($row) => (int)$row['id'], $shares);
$shareMap   = notes_fetch_users_map($shareIds);

$tagInputValue = implode(', ', array_map(static function ($tag) {
    return (string)($tag['label'] ?? '');
}, $tags));

$shareConfig = htmlspecialchars(json_encode([
    'noteId'   => $noteId,
    'selected' => $shareIds,
    'owner'    => (int)($note['user_id'] ?? 0),
], JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8');

$csrfToken = csrf_token();
$noteTitle = htmlspecialchars($note['title'] !== '' ? (string)$note['title'] : 'Untitled note', ENT_QUOTES, 'UTF-8');
$iconChar  = htmlspecialchars($meta['icon'] ?? '', ENT_QUOTES, 'UTF-8');
$coverUrl  = htmlspecialchars((string)($meta['cover_url'] ?? ''), ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Edit note · <?= $noteTitle ?></title>
    <style>
        :root {
            color-scheme: only light;
            --notes-bg: #f5f7fb;
            --notes-surface: #ffffff;
            --notes-border: #d8dee9;
            --notes-text: #111827;
            --notes-muted: #6b7280;
            --notes-accent: #2563eb;
            --notes-radius: 18px;
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--notes-bg);
            min-height: 100vh;
            color: var(--notes-text);
        }
        a { color: inherit; text-decoration: none; }
        .editor-shell {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px 24px 80px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        .editor-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .editor-header__actions {
            display: flex;
            gap: 10px;
        }
        .button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            border-radius: 999px;
            border: 1px solid transparent;
            padding: 10px 18px;
            font-weight: 600;
            cursor: pointer;
            background: var(--notes-accent);
            color: #fff;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        .button--ghost {
            background: transparent;
            color: var(--notes-accent);
            border-color: rgba(37, 99, 235, 0.3);
        }
        .button--subtle {
            background: rgba(15, 23, 42, 0.08);
            color: var(--notes-text);
        }
        .button:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 24px rgba(37, 99, 235, 0.2);
        }
        .panel {
            background: var(--notes-surface);
            border-radius: var(--notes-radius);
            border: 1px solid var(--notes-border);
            padding: 24px 28px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .panel h2 {
            margin: 0;
            font-size: 1.3rem;
        }
        .grid-two {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 18px;
        }
        .field {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .field label {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--notes-muted);
        }
        .field input,
        .field textarea,
        .field select {
            border-radius: 12px;
            border: 1px solid var(--notes-border);
            background: var(--notes-surface);
            padding: 12px 14px;
            font-size: 0.95rem;
        }
        .tags-hint {
            font-size: 0.8rem;
            color: var(--notes-muted);
        }
        .editor-body textarea {
            width: 100%;
            min-height: 320px;
            font-family: 'JetBrains Mono', 'SFMono-Regular', Menlo, monospace;
            line-height: 1.6;
            border-radius: 18px;
            border: 1px solid var(--notes-border);
            padding: 18px;
            resize: vertical;
        }
        .flash {
            padding: 12px 16px;
            border-radius: 12px;
            background: rgba(37, 99, 235, 0.12);
            color: var(--notes-accent);
        }
        .flash-error {
            background: rgba(220, 38, 38, 0.18);
            color: #b91c1c;
        }
        .note-shares {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .note-shares__label {
            color: var(--notes-muted);
            font-size: 0.85rem;
        }
        .note-shares__chips {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .note-shares__placeholder {
            color: var(--notes-muted);
            font-size: 0.85rem;
        }
        .avatar-chip {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: rgba(15, 23, 42, 0.08);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
        }
        .form-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .modal {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(15, 23, 42, 0.32);
            padding: 24px;
            z-index: 1000;
        }
        .modal--visible { display: flex; }
        .modal__panel {
            background: #fff;
            border-radius: 18px;
            max-width: 520px;
            width: 100%;
            display: flex;
            flex-direction: column;
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.28);
        }
        .modal__header { padding: 20px 24px 0; }
        .modal__body { padding: 16px 24px 8px; display:flex; flex-direction:column; gap:16px; }
        .modal__footer { padding: 16px 24px 24px; display:flex; gap:12px; justify-content:flex-end; }
        .share-picker { max-height:260px; overflow-y:auto; border:1px solid var(--notes-border); border-radius:12px; padding:12px; display:flex; flex-direction:column; gap:10px; }
        .share-picker__item { display:flex; gap:10px; align-items:center; }
        @media (max-width: 900px) {
            .editor-header { flex-direction: column; align-items: flex-start; }
            .editor-header__actions { flex-wrap: wrap; }
        }
    </style>
</head>
<body>
<div class="editor-shell">
    <header class="editor-header">
        <a class="button button--ghost" href="view.php?id=<?= $noteId ?>">← Back to note</a>
        <div class="editor-header__actions">
            <div class="note-shares">
                <span class="note-shares__label">Shared with</span>
                <div class="note-shares__chips" data-share-target="<?= $noteId ?>" data-share-allow-placeholder="1">
                    <?php if (!$shares): ?>
                        <span class="note-shares__placeholder" data-share-placeholder>Only you</span>
                    <?php else: ?>
                        <?php foreach ($shares as $share):
                            $rawLabel = (string)($share['label'] ?? '');
                            $label = htmlspecialchars($rawLabel, ENT_QUOTES, 'UTF-8');
                            $initialRaw = function_exists('mb_substr') ? mb_substr($rawLabel, 0, 2, 'UTF-8') : substr($rawLabel, 0, 2);
                            $initial = htmlspecialchars(strtoupper($initialRaw), ENT_QUOTES, 'UTF-8');
                            ?>
                            <span class="avatar-chip" title="<?= $label ?>"><?= $initial ?></span>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
            <?php if (notes_can_share($note)): ?>
                <button class="button button--ghost" data-modal-open="note-share" data-share-config="<?= $shareConfig ?>">Share</button>
            <?php endif; ?>
        </div>
    </header>

    <?php flash_message(); ?>

    <form method="post" class="panel">
        <h2>Details</h2>
        <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
        <input type="hidden" name="save_note" value="1">
        <div class="grid-two">
            <div class="field">
                <label for="title">Title</label>
                <input id="title" name="title" type="text" value="<?= $noteTitle ?>" required>
            </div>
            <div class="field">
                <label for="note_date">Date</label>
                <input id="note_date" name="note_date" type="date" value="<?= htmlspecialchars((string)($note['note_date'] ?? date('Y-m-d')), ENT_QUOTES, 'UTF-8') ?>" required>
            </div>
            <div class="field">
                <label for="status">Status</label>
                <select id="status" name="status">
                    <?php foreach ($statuses as $key => $label): ?>
                        <option value="<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>" <?= ($meta['status'] ?? NOTES_DEFAULT_STATUS) === $key ? 'selected' : '' ?>><?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="field">
                <label for="icon">Icon</label>
                <input id="icon" name="icon" type="text" value="<?= $iconChar ?>" placeholder="e.g. 📌">
            </div>
            <div class="field">
                <label for="cover_url">Cover image URL</label>
                <input id="cover_url" name="cover_url" type="url" value="<?= $coverUrl ?>" placeholder="https://...">
            </div>
        </div>
        <div class="grid-two">
            <div class="field">
                <label for="property_project">Project</label>
                <input id="property_project" name="property_project" type="text" value="<?= htmlspecialchars((string)$properties['project'], ENT_QUOTES, 'UTF-8') ?>">
            </div>
            <div class="field">
                <label for="property_location">Location</label>
                <input id="property_location" name="property_location" type="text" value="<?= htmlspecialchars((string)$properties['location'], ENT_QUOTES, 'UTF-8') ?>">
            </div>
            <div class="field">
                <label for="property_due_date">Due date</label>
                <input id="property_due_date" name="property_due_date" type="date" value="<?= htmlspecialchars((string)$properties['due_date'], ENT_QUOTES, 'UTF-8') ?>">
            </div>
            <div class="field">
                <label for="property_priority">Priority</label>
                <select id="property_priority" name="property_priority">
                    <?php foreach (notes_priority_options() as $option): ?>
                        <option value="<?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?>" <?= $properties['priority'] === $option ? 'selected' : '' ?>><?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <div class="field">
            <label for="tags">Tags</label>
            <input id="tags" name="tags" type="text" value="<?= htmlspecialchars($tagInputValue, ENT_QUOTES, 'UTF-8') ?>" placeholder="design, meeting, research">
            <span class="tags-hint">Separate tags with commas.</span>
        </div>
        <div class="field editor-body">
            <label for="editor_content">Content</label>
            <textarea id="editor_content" name="editor_content" spellcheck="false" placeholder="# Heading
- [ ] Todo item
Some narrative text here.
---
> Quote block
"><?= htmlspecialchars($editorContent, ENT_QUOTES, 'UTF-8') ?></textarea>
        </div>
        <div class="form-actions">
            <div class="field" style="flex:1;">
                <label for="template_name">Save as template</label>
                <div style="display:flex; gap:8px;">
                    <input id="template_name" name="template_name" type="text" placeholder="Template name" style="flex:1;">
                    <button type="submit" name="create_template" value="1" class="button button--subtle">Create</button>
                </div>
            </div>
            <button type="submit" class="button">Save note</button>
        </div>
    </form>
</div>

<div class="modal" data-modal="note-share">
    <div class="modal__panel">
        <div class="modal__header">
            <h2>Share note</h2>
        </div>
        <form method="post" data-share-form="note">
            <div class="modal__body">
                <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
                <input type="hidden" name="update_note_shares" value="1">
                <input type="hidden" name="note_id" value="<?= $noteId ?>">
                <div class="field">
                    <label for="share-filter">Find user</label>
                    <input id="share-filter" type="search" placeholder="Search collaborators" data-share-filter>
                </div>
                <div class="share-picker" data-share-picker>
                    <?php foreach (notes_all_users() as $user):
                        $uid = (int)($user['id'] ?? 0);
                        $label = trim((string)($user['email'] ?? $user['name'] ?? 'User #' . $uid));
                        $labelHtml = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
                        ?>
                        <label class="share-picker__item" data-share-user>
                            <input type="checkbox" name="shared_ids[]" value="<?= $uid ?>" <?= in_array($uid, $shareIds, true) ? 'checked' : '' ?> <?= ((int)$note['user_id'] === $uid) ? 'disabled' : '' ?>>
                            <span><?= $labelHtml ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="modal__footer">
                <button type="button" class="button button--ghost" data-modal-close>Cancel</button>
                <button type="submit" class="button">Save</button>
            </div>
        </form>
    </div>
</div>

<script>
    window.notesApp = window.notesApp || {};
    window.notesApp.shareMap = <?= json_encode($shareMap, JSON_UNESCAPED_UNICODE) ?>;
</script>
<script src="composer.js?v=<?= filemtime(__DIR__ . '/composer.js') ?>" defer></script>
</body>
</html>