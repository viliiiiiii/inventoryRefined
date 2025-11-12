<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';
require_login();

$me      = current_user();
$meId    = (int)($me['id'] ?? 0);
$meEmail = htmlspecialchars((string)($me['email'] ?? ''), ENT_QUOTES, 'UTF-8');

if ($meId <= 0) {
    http_response_code(403);
    exit('Not authorized.');
}

function notes_is_ajax_request(): bool
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower((string)$_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

if (is_post()) {
    $isAjax = notes_is_ajax_request();
    $error  = '';
    $payload = null;

    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        $error = 'Security token expired. Please refresh and try again.';
    } elseif (isset($_POST['update_note_shares'])) {
        $noteId = (int)($_POST['note_id'] ?? 0);
        $selected = array_map('intval', (array)($_POST['shared_ids'] ?? []));
        $note = notes_fetch($noteId);
        if (!$note || !notes_can_share($note)) {
            $error = 'You cannot change sharing on that note.';
        } else {
            try {
                $result = notes_apply_shares($noteId, $selected, $note, true);
                $payload = [
                    'ok'       => true,
                    'note_id'  => $noteId,
                    'selected' => $result['after'],
                    'shares'   => notes_get_share_details($noteId),
                ];
            } catch (Throwable $e) {
                error_log('notes: share update failed: ' . $e->getMessage());
                $error = 'Failed to update shares.';
            }
        }
    } elseif (isset($_POST['update_template_shares'])) {
        $templateId = (int)($_POST['template_id'] ?? 0);
        $selected   = array_map('intval', (array)($_POST['shared_ids'] ?? []));
        $template   = notes_template_fetch($templateId);
        if (!$template || !notes_template_can_share($template, $meId)) {
            $error = 'You cannot change template sharing.';
        } else {
            try {
                $result = notes_apply_template_shares($templateId, $selected, $template, true);
                $payload = [
                    'ok'          => true,
                    'template_id' => $templateId,
                    'selected'    => $result['after'],
                    'shares'      => notes_template_share_details($templateId),
                ];
            } catch (Throwable $e) {
                error_log('notes: template share update failed: ' . $e->getMessage());
                $error = 'Failed to update template sharing.';
            }
        }
    } elseif (isset($_POST['quick_note'])) {
        $title    = trim((string)($_POST['title'] ?? ''));
        $noteDate = trim((string)($_POST['note_date'] ?? date('Y-m-d')));
        $status   = notes_normalize_status($_POST['status'] ?? NOTES_DEFAULT_STATUS);
        $body     = trim((string)($_POST['body'] ?? ''));
        $tagsRaw  = trim((string)($_POST['quick_tags'] ?? ''));

        if ($title === '') {
            $error = 'Give the note a title.';
        } elseif ($noteDate === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $noteDate)) {
            $error = 'Provide a valid date (YYYY-MM-DD).';
        } else {
            $tagChunks = array_filter(array_map('trim', preg_split('/[,;\n]/', $tagsRaw) ?: []));
            $tags = [];
            foreach ($tagChunks as $chunk) {
                $tags[] = ['label' => $chunk];
            }

            try {
                $noteId = notes_insert([
                    'user_id'    => $meId,
                    'note_date'  => $noteDate,
                    'title'      => $title,
                    'body'       => $body,
                    'icon'       => null,
                    'cover_url'  => null,
                    'status'     => $status,
                    'properties' => notes_default_properties(),
                    'tags'       => notes_normalize_tags_input($tags),
                    'blocks'     => [],
                ]);
                $payload = [
                    'ok'       => true,
                    'redirect' => 'edit.php?id=' . $noteId,
                ];
            } catch (Throwable $e) {
                error_log('notes: quick note insert failed: ' . $e->getMessage());
                $error = 'Could not capture note.';
            }
        }
    }

    if ($isAjax) {
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
        redirect_with_message('index.php', $error, 'error');
    } else {
        redirect_with_message('index.php', 'Changes saved.', 'success');
    }
    exit;
}

$notes      = notes_list_for_user($meId);
$templates  = notes_fetch_templates_for_user($meId);
$ownedTpls  = array_filter($templates, static fn($tpl) => !empty($tpl['is_owner']));
$sharedTpls = array_filter($templates, static fn($tpl) => empty($tpl['is_owner']));
$statuses   = notes_available_statuses();
$users      = notes_all_users();

$shareIds = [];
$templateShareSelections = [];
foreach ($notes as $noteRow) {
    foreach ($noteRow['share_ids'] as $sid) {
        $shareIds[] = (int)$sid;
    }
}
foreach ($templates as $tplRow) {
    $tplId = (int)($tplRow['id'] ?? 0);
    if ($tplId <= 0) {
        continue;
    }
    $tplShares = notes_get_template_share_user_ids($tplId);
    $templateShareSelections[$tplId] = $tplShares;
    foreach ($tplShares as $sid) {
        $shareIds[] = (int)$sid;
    }
}
$shareMap = notes_fetch_users_map($shareIds);

function notes_render_note_snippet(array $note): string
{
    $plain = trim(strip_tags((string)($note['body'] ?? '')));
    if ($plain === '') {
        return 'No description yet.';
    }
    if (function_exists('mb_substr')) {
        $snippet = mb_substr($plain, 0, 160, 'UTF-8');
    } else {
        $snippet = substr($plain, 0, 160);
    }
    if (strlen($plain) > strlen($snippet)) {
        $snippet .= '…';
    }
    return htmlspecialchars($snippet, ENT_QUOTES, 'UTF-8');
}

$csrfToken = csrf_token();
$today     = date('Y-m-d');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Notes workspace</title>
    <style>
        :root {
            color-scheme: only light;
            --notes-bg: #f9fafb;
            --notes-sidebar: #ffffff;
            --notes-surface: #ffffff;
            --notes-border: #e5e7eb;
            --notes-text: #111827;
            --notes-muted: #6b7280;
            --notes-accent: #2563eb;
            --notes-accent-soft: rgba(37, 99, 235, 0.12);
            --notes-danger: #dc2626;
            --notes-radius: 12px;
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--notes-bg);
            color: var(--notes-text);
        }
        a { color: inherit; text-decoration: none; }
        .notes-shell {
            display: grid;
            grid-template-columns: 280px 1fr;
            min-height: 100vh;
        }
        .notes-sidebar {
            background: var(--notes-sidebar);
            border-right: 1px solid var(--notes-border);
            padding: 24px 20px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        .brand {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .brand__title {
            font-size: 1.125rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .brand__title span.icon {
            display: inline-flex;
            width: 32px;
            height: 32px;
            border-radius: 10px;
            align-items: center;
            justify-content: center;
            background: var(--notes-accent-soft);
            color: var(--notes-accent);
            font-weight: 600;
        }
        .stack {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            border: 1px solid transparent;
            background: var(--notes-accent);
            color: #fff;
            border-radius: 10px;
            padding: 10px 14px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        .button:focus-visible {
            outline: 2px solid var(--notes-accent);
            outline-offset: 2px;
        }
        .button:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 16px rgba(37, 99, 235, 0.18);
        }
        .button--ghost {
            background: transparent;
            color: var(--notes-accent);
            border-color: rgba(37, 99, 235, 0.32);
            box-shadow: none;
        }
        .button--subtle {
            background: rgba(15, 23, 42, 0.04);
            color: var(--notes-text);
            border-color: rgba(15, 23, 42, 0.08);
            box-shadow: none;
        }
        .button--danger {
            background: var(--notes-danger);
            border-color: var(--notes-danger);
        }
        .notes-sidebar__section {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .notes-sidebar__footer {
            margin-top: auto;
            padding-top: 16px;
            border-top: 1px solid var(--notes-border);
        }
        .notes-sidebar__heading {
            font-size: 0.75rem;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--notes-muted);
            font-weight: 600;
        }
        .button--full {
            width: 100%;
        }
        .template-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .template-card {
            padding: 12px 14px;
            border-radius: 10px;
            border: 1px solid var(--notes-border);
            background: var(--notes-surface);
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .template-card__name {
            font-weight: 600;
            font-size: 0.95rem;
        }
        .template-card__meta {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: var(--notes-muted);
        }
        .template-card__actions {
            display: flex;
            gap: 8px;
        }
        .notes-main {
            padding: 32px 40px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        header.notes-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .notes-header__title {
            display: flex;
            flex-direction: column;
        }
        .notes-header__title h1 {
            margin: 0;
            font-size: 1.8rem;
        }
        .notes-header__title span {
            font-size: 0.9rem;
            color: var(--notes-muted);
        }
        .search-box {
            position: relative;
            width: 260px;
        }
        .search-box input {
            width: 100%;
            border: 1px solid var(--notes-border);
            border-radius: 12px;
            padding: 10px 14px;
            font-size: 0.95rem;
            background: var(--notes-surface);
            color: var(--notes-text);
        }
        .search-box input::placeholder {
            color: var(--notes-muted);
        }
        .notes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            gap: 18px;
        }
        .note-card {
            background: var(--notes-surface);
            border-radius: var(--notes-radius);
            padding: 18px;
            border: 1px solid var(--notes-border);
            display: flex;
            flex-direction: column;
            gap: 14px;
            position: relative;
            min-height: 200px;
        }
        .note-card__head {
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }
        .note-card__icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            background: rgba(15, 23, 42, 0.05);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
        }
        .note-card__title {
            margin: 0;
            font-size: 1.05rem;
            font-weight: 600;
            line-height: 1.3;
        }
        .note-card__meta {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            font-size: 0.75rem;
            color: var(--notes-muted);
        }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.03em;
        }
        .badge--status {
            background: rgba(37, 99, 235, 0.12);
            color: var(--notes-accent);
        }
        .badge--priority {
            background: rgba(34, 197, 94, 0.14);
            color: #047857;
        }
        .note-card__body {
            font-size: 0.9rem;
            color: var(--notes-muted);
            line-height: 1.5;
        }
        .tag-chip {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 500;
            margin: 2px 6px 2px 0;
        }
        .note-card__footer {
            margin-top: auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }
        .note-card__footer-actions {
            display: flex;
            gap: 8px;
        }
        .note-card__shares {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }
        .avatar-chip {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: rgba(15, 23, 42, 0.08);
            color: var(--notes-text);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .note-card__empty {
            padding: 40px;
            text-align: center;
            color: var(--notes-muted);
            border: 1px dashed var(--notes-border);
            border-radius: var(--notes-radius);
        }
        .flash {
            padding: 12px 16px;
            border-radius: 12px;
            font-size: 0.95rem;
        }
        .flash-success {
            background: rgba(34, 197, 94, 0.12);
            color: #047857;
        }
        .flash-error {
            background: rgba(220, 38, 38, 0.14);
            color: #b91c1c;
        }
        .modal {
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.24);
            display: none;
            align-items: center;
            justify-content: center;
            padding: 24px;
            z-index: 1000;
        }
        .modal--visible {
            display: flex;
        }
        .modal__panel {
            background: #fff;
            border-radius: 18px;
            max-width: 520px;
            width: 100%;
            display: flex;
            flex-direction: column;
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.24);
        }
        .modal__header {
            padding: 20px 24px 0;
        }
        .modal__header h2 {
            margin: 0;
            font-size: 1.2rem;
        }
        .modal__body {
            padding: 16px 24px 8px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        .modal__footer {
            padding: 16px 24px 24px;
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }
        .modal__close {
            background: none;
            border: none;
            font-size: 1rem;
            cursor: pointer;
            color: var(--notes-muted);
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
            border: 1px solid var(--notes-border);
            border-radius: 10px;
            padding: 10px 12px;
            font-size: 0.95rem;
            background: var(--notes-surface);
        }
        .share-picker {
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-height: 260px;
            overflow-y: auto;
            border: 1px solid var(--notes-border);
            border-radius: 12px;
            padding: 12px;
        }
        .share-picker__item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .share-picker__item input {
            width: 16px;
            height: 16px;
        }
        .pill {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.7rem;
            background: rgba(37, 99, 235, 0.1);
            color: var(--notes-accent);
            gap: 6px;
        }
        .note-counter {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--notes-muted);
            font-size: 0.8rem;
        }
        @media (max-width: 1100px) {
            .notes-shell {
                grid-template-columns: 1fr;
            }
            .notes-sidebar {
                flex-direction: row;
                overflow-x: auto;
                gap: 16px;
                flex-wrap: wrap;
            }
            .notes-sidebar__footer {
                width: 100%;
                margin-top: 0;
                padding-top: 8px;
                border-top: none;
            }
        }
    </style>
</head>
<body>
<div class="notes-shell">
    <aside class="notes-sidebar">
        <div class="brand">
            <div class="brand__title"><span class="icon">✦</span>ABRM Notes</div>
            <div class="brand__subtitle" style="font-size:0.85rem;color:var(--notes-muted);">Signed in as <?= $meEmail ?></div>
            <div class="stack">
                <a class="button" href="new.php">✚ New note</a>
                <button class="button button--subtle" data-modal-open="quick-note">Quick capture</button>
            </div>
        </div>

        <div class="notes-sidebar__section">
            <div class="notes-sidebar__heading">Templates</div>
            <div class="template-list">
                <?php if (!$templates): ?>
                    <div class="template-card">
                        <div class="template-card__name">No templates yet</div>
                        <div class="template-card__meta">Create one from a note to reuse layouts.</div>
                        <div class="template-card__actions">
                            <a class="button button--ghost" href="new.php">Create note</a>
                        </div>
                    </div>
                <?php else: ?>
                    <?php foreach ($templates as $tpl):
                        $tplId   = (int)($tpl['id'] ?? 0);
                        $tplName = htmlspecialchars((string)($tpl['name'] ?? 'Untitled template'), ENT_QUOTES, 'UTF-8');
                        $tplOwner = notes_user_label((int)($tpl['owner_id'] ?? 0));
                        $tplOwnerHtml = htmlspecialchars($tplOwner, ENT_QUOTES, 'UTF-8');
                        $tplConfig = htmlspecialchars(json_encode([
                            'templateId' => $tplId,
                            'selected'   => $templateShareSelections[$tplId] ?? [],
                            'owner'      => (int)($tpl['owner_id'] ?? 0),
                        ], JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8');
                        $shareCount = (int)($tpl['share_count'] ?? 0);
                        ?>
                        <div class="template-card" data-template-id="<?= $tplId ?>">
                            <div class="template-card__name"><?= $tplName ?></div>
                            <div class="template-card__meta">
                                <span><?= $tpl['is_owner'] ? 'You own this' : ('Shared by ' . $tplOwnerHtml) ?></span>
                                <span><?= $shareCount ?> shared</span>
                            </div>
                            <div class="template-card__actions">
                                <a class="button button--ghost" href="new.php?template_id=<?= $tplId ?>">Use</a>
                                <?php if (notes_template_can_share($tpl, $meId)): ?>
                                    <button class="button button--subtle" data-modal-open="template-share" data-share-config="<?= $tplConfig ?>">Share</button>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <div class="notes-sidebar__footer">
            <a class="button button--subtle button--full" href="../index.php">← Back to dashboard</a>
        </div>
    </aside>

    <main class="notes-main">
        <header class="notes-header">
            <div class="notes-header__title">
                <h1>Workspace</h1>
                <span><?= count($notes) ?> notes, <?= count($templates) ?> templates</span>
            </div>
            <div class="search-box">
                <input type="search" id="notes-search" placeholder="Search notes" autocomplete="off">
            </div>
        </header>

        <?php flash_message(); ?>

        <section class="notes-grid" id="notes-grid">
            <?php if (!$notes): ?>
                <div class="note-card__empty">No notes yet. Capture your first one!</div>
            <?php else: ?>
                <?php foreach ($notes as $note):
                    $noteId     = (int)$note['id'];
                    $titlePlain = $note['title'] !== '' ? (string)$note['title'] : 'Untitled note';
                    $title      = htmlspecialchars($titlePlain, ENT_QUOTES, 'UTF-8');
                    $dataTitlePlain = function_exists('mb_strtolower') ? mb_strtolower($titlePlain, 'UTF-8') : strtolower($titlePlain);
                    $dataTitle = htmlspecialchars($dataTitlePlain, ENT_QUOTES, 'UTF-8');
                    $status   = htmlspecialchars(notes_status_label($note['meta']['status'] ?? null), ENT_QUOTES, 'UTF-8');
                    $priority = htmlspecialchars((string)($note['meta']['properties']['priority'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $noteDate = htmlspecialchars((string)($note['note_date'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $owner    = htmlspecialchars($note['owner_label'] ?? '', ENT_QUOTES, 'UTF-8');
                    $shares   = $note['share_ids'];
                    $shareConfig = htmlspecialchars(json_encode([
                        'noteId'   => $noteId,
                        'selected' => $shares,
                        'owner'    => (int)$note['owner_id'],
                    ], JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8');
                    $comments = (int)$note['comment_count'];
                    $iconChar = $note['meta']['icon'] ?? '';
                    $iconChar = $iconChar !== '' ? $iconChar : '🗒️';
                    $iconHtml = htmlspecialchars($iconChar, ENT_QUOTES, 'UTF-8');
                    $noteRecord = ['id' => $noteId, 'user_id' => (int)$note['owner_id']];
                    $canEdit  = notes_can_edit($noteRecord);
                    $canShare = notes_can_share($noteRecord);
                    ?>
                    <article class="note-card" data-note-id="<?= $noteId ?>" data-note-title="<?= $dataTitle ?>">
                        <div class="note-card__head">
                            <div class="note-card__icon"><?= $iconHtml ?></div>
                            <div class="note-card__head-inner" style="flex:1;">
                                <h2 class="note-card__title"><?= $title ?></h2>
                                <div class="note-card__meta">
                                    <span><?= $noteDate ?: 'No date' ?></span>
                                    <span>Owner · <?= $owner ?></span>
                                    <span class="badge badge--status"><?= $status ?></span>
                                    <?php if ($priority !== ''): ?>
                                        <span class="badge badge--priority">Priority · <?= $priority ?></span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        <div class="note-card__body"><?= notes_render_note_snippet($note) ?></div>
                        <div>
                            <?php foreach ($note['tags'] as $tag):
                                $label = htmlspecialchars((string)($tag['label'] ?? ''), ENT_QUOTES, 'UTF-8');
                                $color = htmlspecialchars((string)($tag['color'] ?? '#e5e7eb'), ENT_QUOTES, 'UTF-8');
                                ?>
                                <span class="tag-chip" style="background: <?= $color ?>20; color: <?= $color ?>; border: 1px solid <?= $color ?>33;">#<?= $label ?></span>
                            <?php endforeach; ?>
                        </div>
                        <div class="note-card__footer">
                            <div class="note-card__shares" data-share-target="<?= $noteId ?>">
                                <span class="note-counter">💬 <?= $comments ?></span>
                                <?php foreach ($shares as $uid):
                                    $label = $shareMap[$uid] ?? ('User #' . $uid);
                                    $initial = function_exists('mb_substr') ? mb_substr($label, 0, 2, 'UTF-8') : substr($label, 0, 2);
                                    $initial = strtoupper($initial);
                                    ?>
                                    <span class="avatar-chip" title="<?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($initial, ENT_QUOTES, 'UTF-8') ?></span>
                                <?php endforeach; ?>
                            </div>
                            <div class="note-card__footer-actions">
                                <a class="button button--subtle" href="view.php?id=<?= $noteId ?>">Open</a>
                                <?php if ($canEdit): ?>
                                    <a class="button button--subtle" href="edit.php?id=<?= $noteId ?>">Edit</a>
                                <?php endif; ?>
                                <?php if ($canShare): ?>
                                    <button class="button button--ghost" data-modal-open="note-share" data-share-config="<?= $shareConfig ?>">Share</button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </article>
                <?php endforeach; ?>
            <?php endif; ?>
        </section>
    </main>
</div>

<div class="modal" data-modal="quick-note">
    <div class="modal__panel">
        <div class="modal__header">
            <h2>Quick capture</h2>
        </div>
        <form class="quick-note-form" method="post">
            <div class="modal__body">
                <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
                <input type="hidden" name="quick_note" value="1">
                <div class="field">
                    <label for="quick-title">Title</label>
                    <input id="quick-title" name="title" type="text" required maxlength="180" placeholder="Project kickoff notes">
                </div>
                <div class="field">
                    <label for="quick-date">Date</label>
                    <input id="quick-date" name="note_date" type="date" value="<?= $today ?>" required>
                </div>
                <div class="field">
                    <label for="quick-status">Status</label>
                    <select id="quick-status" name="status">
                        <?php foreach ($statuses as $statusKey => $statusLabel): ?>
                            <option value="<?= htmlspecialchars($statusKey, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($statusLabel, ENT_QUOTES, 'UTF-8') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="field">
                    <label for="quick-tags">Tags</label>
                    <input id="quick-tags" name="quick_tags" type="text" placeholder="product, research">
                </div>
                <div class="field">
                    <label for="quick-body">Summary</label>
                    <textarea id="quick-body" name="body" rows="4" placeholder="Highlights, ideas, todos…"></textarea>
                </div>
            </div>
            <div class="modal__footer">
                <button type="button" class="modal__close" data-modal-close>Cancel</button>
                <button type="submit" class="button">Save &amp; open</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" data-modal="note-share">
    <div class="modal__panel">
        <div class="modal__header">
            <h2>Share note</h2>
        </div>
        <form class="share-form" method="post" data-share-form="note">
            <div class="modal__body">
                <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
                <input type="hidden" name="update_note_shares" value="1">
                <input type="hidden" name="note_id" value="">
                <div class="field">
                    <label for="note-share-filter">Find user</label>
                    <input id="note-share-filter" type="search" placeholder="Search collaborators" data-share-filter>
                </div>
                <div class="share-picker" data-share-picker>
                    <?php foreach ($users as $user):
                        $uid = (int)($user['id'] ?? 0);
                        $label = trim((string)($user['email'] ?? $user['name'] ?? 'User #' . $uid));
                        $labelHtml = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
                        ?>
                        <label class="share-picker__item" data-share-user>
                            <input type="checkbox" name="shared_ids[]" value="<?= $uid ?>">
                            <span><?= $labelHtml ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="modal__footer">
                <button type="button" class="modal__close" data-modal-close>Cancel</button>
                <button type="submit" class="button">Save</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" data-modal="template-share">
    <div class="modal__panel">
        <div class="modal__header">
            <h2>Share template</h2>
        </div>
        <form class="share-form" method="post" data-share-form="template">
            <div class="modal__body">
                <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
                <input type="hidden" name="update_template_shares" value="1">
                <input type="hidden" name="template_id" value="">
                <div class="field">
                    <label for="template-share-filter">Find user</label>
                    <input id="template-share-filter" type="search" placeholder="Search collaborators" data-share-filter>
                </div>
                <div class="share-picker" data-share-picker>
                    <?php foreach ($users as $user):
                        $uid = (int)($user['id'] ?? 0);
                        $label = trim((string)($user['email'] ?? $user['name'] ?? 'User #' . $uid));
                        $labelHtml = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
                        ?>
                        <label class="share-picker__item" data-share-user>
                            <input type="checkbox" name="shared_ids[]" value="<?= $uid ?>">
                            <span><?= $labelHtml ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="modal__footer">
                <button type="button" class="modal__close" data-modal-close>Cancel</button>
                <button type="submit" class="button">Save</button>
            </div>
        </form>
    </div>
</div>

<script>
    window.notesApp = {
        shareMap: <?= json_encode($shareMap, JSON_UNESCAPED_UNICODE) ?>,
        messages: {
            saveError: 'Unable to save changes. Please try again.',
        }
    };
</script>
<script src="composer.js?v=<?= filemtime(__DIR__ . '/composer.js') ?>" defer></script>
</body>
</html>