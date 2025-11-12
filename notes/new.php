<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';
require_login();

$me      = current_user();
$meId    = (int)($me['id'] ?? 0);
$templateId = (int)($_GET['template_id'] ?? 0);
$template   = null;

if ($templateId > 0) {
    $maybeTemplate = notes_template_fetch($templateId);
    if ($maybeTemplate && notes_template_is_visible_to_user($maybeTemplate, $meId)) {
        $template = $maybeTemplate;
    }
}

function notes_new_parse_blocks(string $text): array
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

function notes_new_blocks_to_editor(array $blocks, string $fallback): string
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
    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        redirect_with_message('new.php', 'Security token expired. Please try again.', 'error');
    }

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
        redirect_with_message('new.php', 'Title is required.', 'error');
    }
    if ($noteDate === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $noteDate)) {
        redirect_with_message('new.php', 'Provide a valid date (YYYY-MM-DD).', 'error');
    }
    if ($dueDate !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $dueDate)) {
        redirect_with_message('new.php', 'Due date must follow YYYY-MM-DD.', 'error');
    }

    $blocks = notes_new_parse_blocks($editor);
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
        $noteId = notes_insert([
            'user_id'    => $meId,
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
        redirect_with_message('edit.php?id=' . $noteId, 'Note created.', 'success');
    } catch (Throwable $e) {
        error_log('notes: create failed: ' . $e->getMessage());
        redirect_with_message('new.php', 'Unable to create note.', 'error');
    }
}

$initial = [
    'title'      => $template['title'] ?? '',
    'note_date'  => date('Y-m-d'),
    'status'     => $template['status'] ?? NOTES_DEFAULT_STATUS,
    'icon'       => $template['icon'] ?? '',
    'cover_url'  => $template['coverUrl'] ?? '',
    'properties' => $template['properties'] ?? notes_default_properties(),
    'tags'       => $template['tags'] ?? [],
    'blocks'     => $template['blocks'] ?? [],
];

$bodyText = '';
$editorContent = notes_new_blocks_to_editor($initial['blocks'], $bodyText);
$tagInputValue = implode(', ', array_map(static function ($tag) {
    return (string)($tag['label'] ?? '');
}, $initial['tags']));

$statuses  = notes_available_statuses();
$templates = notes_fetch_templates_for_user($meId);
$csrfToken = csrf_token();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>New note</title>
    <style>
        :root {
            color-scheme: only light;
            --notes-bg: #f8fafc;
            --notes-surface: #ffffff;
            --notes-border: #dfe3ec;
            --notes-text: #0f172a;
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
        .new-shell {
            max-width: 1100px;
            margin: 0 auto;
            padding: 32px 24px 80px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
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
        }
        .button--ghost {
            background: transparent;
            color: var(--notes-accent);
            border-color: rgba(37, 99, 235, 0.3);
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
        .panel h2 { margin: 0; font-size: 1.3rem; }
        .grid-two {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 18px;
        }
        .field { display:flex; flex-direction:column; gap:6px; }
        .field label { font-size:0.85rem; font-weight:600; color:var(--notes-muted); }
        .field input,
        .field textarea,
        .field select {
            border-radius: 12px;
            border: 1px solid var(--notes-border);
            background: var(--notes-surface);
            padding: 12px 14px;
            font-size: 0.95rem;
        }
        .editor textarea {
            width: 100%;
            min-height: 280px;
            font-family: 'JetBrains Mono', 'SFMono-Regular', Menlo, monospace;
            line-height: 1.6;
            border-radius: 18px;
            border: 1px solid var(--notes-border);
            padding: 18px;
            resize: vertical;
        }
        .template-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 12px;
        }
        .template-card {
            border: 1px solid var(--notes-border);
            border-radius: 14px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            background: rgba(37, 99, 235, 0.04);
        }
        .template-card__name { font-weight: 600; }
        .template-card__meta { font-size: 0.75rem; color: var(--notes-muted); }
        .flash {
            padding: 12px 16px;
            border-radius: 12px;
            background: rgba(37, 99, 235, 0.12);
            color: var(--notes-accent);
        }
        .flash-error { background: rgba(220, 38, 38, 0.16); color: #b91c1c; }
    </style>
</head>
<body>
<div class="new-shell">
    <div class="header">
        <a class="button button--ghost" href="index.php">← Back to notes</a>
        <span style="color:var(--notes-muted);font-size:0.9rem;">Signed in as <?= htmlspecialchars((string)($me['email'] ?? ''), ENT_QUOTES, 'UTF-8') ?></span>
    </div>

    <?php flash_message(); ?>

    <section class="panel">
        <h2>Create note</h2>
        <form method="post">
            <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
            <div class="grid-two">
                <div class="field">
                    <label for="title">Title</label>
                    <input id="title" name="title" type="text" value="<?= htmlspecialchars($initial['title'], ENT_QUOTES, 'UTF-8') ?>" placeholder="Project kickoff" required>
                </div>
                <div class="field">
                    <label for="note_date">Date</label>
                    <input id="note_date" name="note_date" type="date" value="<?= htmlspecialchars($initial['note_date'], ENT_QUOTES, 'UTF-8') ?>" required>
                </div>
                <div class="field">
                    <label for="status">Status</label>
                    <select id="status" name="status">
                        <?php foreach ($statuses as $key => $label): ?>
                            <option value="<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>" <?= $initial['status'] === $key ? 'selected' : '' ?>><?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="field">
                    <label for="icon">Icon</label>
                    <input id="icon" name="icon" type="text" value="<?= htmlspecialchars((string)$initial['icon'], ENT_QUOTES, 'UTF-8') ?>" placeholder="🧠">
                </div>
                <div class="field">
                    <label for="cover_url">Cover image URL</label>
                    <input id="cover_url" name="cover_url" type="url" value="<?= htmlspecialchars((string)$initial['cover_url'], ENT_QUOTES, 'UTF-8') ?>" placeholder="https://...">
                </div>
            </div>
            <div class="grid-two">
                <div class="field">
                    <label for="property_project">Project</label>
                    <input id="property_project" name="property_project" type="text" value="<?= htmlspecialchars((string)$initial['properties']['project'], ENT_QUOTES, 'UTF-8') ?>">
                </div>
                <div class="field">
                    <label for="property_location">Location</label>
                    <input id="property_location" name="property_location" type="text" value="<?= htmlspecialchars((string)$initial['properties']['location'], ENT_QUOTES, 'UTF-8') ?>">
                </div>
                <div class="field">
                    <label for="property_due_date">Due date</label>
                    <input id="property_due_date" name="property_due_date" type="date" value="<?= htmlspecialchars((string)$initial['properties']['due_date'], ENT_QUOTES, 'UTF-8') ?>">
                </div>
                <div class="field">
                    <label for="property_priority">Priority</label>
                    <select id="property_priority" name="property_priority">
                        <?php foreach (notes_priority_options() as $option): ?>
                            <option value="<?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?>" <?= $initial['properties']['priority'] === $option ? 'selected' : '' ?>><?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div class="field">
                <label for="tags">Tags</label>
                <input id="tags" name="tags" type="text" value="<?= htmlspecialchars($tagInputValue, ENT_QUOTES, 'UTF-8') ?>" placeholder="docs, sprint">
                <span style="font-size:0.8rem;color:var(--notes-muted);">Separate tags with commas.</span>
            </div>
            <div class="field editor">
                <label for="editor_content">Content</label>
                <textarea id="editor_content" name="editor_content" spellcheck="false" placeholder="# Meeting notes
- [ ] Agenda item
Summary paragraphs here.
---
> Key insight
"><?= htmlspecialchars($editorContent, ENT_QUOTES, 'UTF-8') ?></textarea>
            </div>
            <div style="display:flex;justify-content:flex-end;">
                <button type="submit" class="button">Create note</button>
            </div>
        </form>
    </section>

    <section class="panel">
        <h2>Templates</h2>
        <?php if (!$templates): ?>
            <p style="margin:0;color:var(--notes-muted);">No templates yet. Save a note as a template to reuse structure.</p>
        <?php else: ?>
            <div class="template-list">
                <?php foreach ($templates as $tpl):
                    $tplId = (int)($tpl['id'] ?? 0);
                    $tplName = htmlspecialchars((string)($tpl['name'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $ownerLabel = notes_user_label((int)($tpl['owner_id'] ?? 0));
                    $ownerHtml  = htmlspecialchars($ownerLabel, ENT_QUOTES, 'UTF-8');
                    ?>
                    <div class="template-card">
                        <div class="template-card__name"><?= $tplName ?></div>
                        <div class="template-card__meta"><?= $tpl['is_owner'] ? 'You own this template' : ('Shared by ' . $ownerHtml) ?></div>
                        <a class="button button--ghost" href="new.php?template_id=<?= $tplId ?>">Apply</a>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </section>
</div>
</body>
</html>