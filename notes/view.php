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

function notes_view_is_ajax(): bool
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower((string)$_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

if (is_post()) {
    $isAjax = notes_view_is_ajax();
    $error  = '';
    $payload = null;

    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        $error = 'Security token expired. Please refresh and try again.';
    } elseif (isset($_POST['update_note_shares'])) {
        $selected = array_map('intval', (array)($_POST['shared_ids'] ?? []));
        if (!notes_can_share($note)) {
            $error = 'You cannot change sharing on this note.';
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
                error_log('notes: share update failed (view): ' . $e->getMessage());
                $error = 'Unable to update sharing.';
            }
        }
    } elseif (isset($_POST['create_comment'])) {
        $body = trim((string)($_POST['body'] ?? ''));
        $parentId = isset($_POST['parent_id']) ? (int)$_POST['parent_id'] : null;
        if ($body === '') {
            $error = 'Comment cannot be empty.';
        } else {
            try {
                notes_comment_insert($noteId, $meId, $body, $parentId ?: null);
            } catch (Throwable $e) {
                error_log('notes: comment insert failed: ' . $e->getMessage());
                $error = 'Unable to save comment.';
            }
        }
    } elseif (isset($_POST['delete_comment'])) {
        $commentId = (int)($_POST['comment_id'] ?? 0);
        $comment = notes_comment_fetch($commentId);
        if (!$comment || (int)$comment['note_id'] !== $noteId) {
            $error = 'Comment not found.';
        } elseif (!notes_comment_can_delete($comment, $note)) {
            $error = 'You cannot delete this comment.';
        } else {
            notes_comment_delete($commentId);
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
        redirect_with_message('view.php?id=' . $noteId, $error, 'error');
    } else {
        $message = isset($_POST['update_note_shares']) ? 'Sharing updated.' : 'Changes saved.';
        redirect_with_message('view.php?id=' . $noteId, $message, 'success');
    }
    exit;
}

$meta       = notes_fetch_page_meta($noteId);
$properties = notes_normalize_properties($meta['properties'] ?? []);
$tags       = notes_fetch_note_tags($noteId);
$blocks     = notes_fetch_blocks($noteId);
$bodyText   = trim((string)($note['body'] ?? ''));
$photos     = notes_fetch_photos($noteId);
$shares     = notes_get_share_details($noteId);
$shareIds   = array_map(static fn($row) => (int)$row['id'], $shares);
$shareMap   = notes_fetch_users_map($shareIds);
$comments   = notes_fetch_comment_threads($noteId);

$iconChar = $meta['icon'] ?? '';
if ($iconChar === null || $iconChar === '') {
    $iconChar = '🗒️';
}

$coverUrl = $meta['cover_url'] ?? null;
$status   = notes_status_label($meta['status'] ?? null);
$priority = $properties['priority'] ?? 'Medium';
$owner    = notes_user_label((int)($note['user_id'] ?? 0));
$canEdit  = notes_can_edit($note);
$canShare = notes_can_share($note);
$csrfToken = csrf_token();

function notes_render_block(array $block): string
{
    $type = $block['type'] ?? 'paragraph';
    $text = htmlspecialchars((string)($block['text'] ?? ''), ENT_QUOTES, 'UTF-8');
    $color = $block['color'] ?? null;
    $colorStyle = $color ? ' style="border-left-color:' . htmlspecialchars($color, ENT_QUOTES, 'UTF-8') . ';"' : '';

    switch ($type) {
        case 'heading1':
            return '<h2 class="block block--h1">' . $text . '</h2>';
        case 'heading2':
            return '<h3 class="block block--h2">' . $text . '</h3>';
        case 'heading3':
            return '<h4 class="block block--h3">' . $text . '</h4>';
        case 'quote':
            return '<blockquote class="block block--quote"' . $colorStyle . '>' . $text . '</blockquote>';
        case 'callout':
            $icon = htmlspecialchars((string)($block['icon'] ?? '💡'), ENT_QUOTES, 'UTF-8');
            return '<div class="block block--callout"' . $colorStyle . '><span class="block__callout-icon">' . $icon . '</span><span>' . $text . '</span></div>';
        case 'todo':
            $checked = !empty($block['checked']);
            return '<label class="block block--todo"><input type="checkbox" disabled ' . ($checked ? 'checked' : '') . '><span>' . $text . '</span></label>';
        case 'bulleted':
            $items = $block['items'] ?? [];
            $lis = '';
            foreach ($items as $item) {
                $lis .= '<li>' . htmlspecialchars((string)$item, ENT_QUOTES, 'UTF-8') . '</li>';
            }
            return '<ul class="block block--list">' . $lis . '</ul>';
        case 'numbered':
            $items = $block['items'] ?? [];
            $lis = '';
            foreach ($items as $item) {
                $lis .= '<li>' . htmlspecialchars((string)$item, ENT_QUOTES, 'UTF-8') . '</li>';
            }
            return '<ol class="block block--list block--list-numbered">' . $lis . '</ol>';
        case 'divider':
            return '<hr class="block block--divider">';
        default:
            return '<p class="block">' . $text . '</p>';
    }
}

function notes_render_blocks(array $blocks, string $fallback): string
{
    if ($blocks) {
        $out = '';
        foreach ($blocks as $block) {
            $out .= notes_render_block($block);
        }
        return $out;
    }
    if ($fallback !== '') {
        return '<p class="block">' . nl2br(htmlspecialchars($fallback, ENT_QUOTES, 'UTF-8')) . '</p>';
    }
    return '<p class="block block--empty">No content yet.</p>';
}

function notes_render_comments(array $threads, string $csrfToken, array $note): string
{
    if (!$threads) {
        return '<p class="comment-empty">No discussions yet. Start one below.</p>';
    }
    $out = '';
    foreach ($threads as $comment) {
        $out .= notes_render_comment_item($comment, $csrfToken, $note);
    }
    return $out;
}

function notes_render_comment_item(array $comment, string $csrfToken, array $note): string
{
    $id     = (int)($comment['id'] ?? 0);
    $author = htmlspecialchars((string)($comment['author_label'] ?? ''), ENT_QUOTES, 'UTF-8');
    $body   = nl2br(htmlspecialchars((string)($comment['body'] ?? ''), ENT_QUOTES, 'UTF-8'));
    $timestamp = htmlspecialchars((string)($comment['created_at'] ?? ''), ENT_QUOTES, 'UTF-8');
    $children = $comment['children'] ?? [];
    $canDelete = $id > 0 && notes_comment_can_delete($comment, $note);

    $html = '<article class="comment" data-comment-id="' . $id . '">';
    $html .= '<header class="comment__header"><span class="comment__author">' . $author . '</span>'; 
    if ($timestamp !== '') {
        $html .= '<span class="comment__time">' . $timestamp . '</span>';
    }
    $html .= '</header>';
    $html .= '<div class="comment__body">' . $body . '</div>';
    $html .= '<div class="comment__actions">';
    $html .= '<button class="comment__action" data-reply-toggle="' . $id . '">Reply</button>';
    if ($canDelete) {
        $html .= '<form method="post" class="comment__action-form" onsubmit="return confirm(\'Delete this comment?\');">';
        $html .= '<input type="hidden" name="' . CSRF_TOKEN_NAME . '" value="' . $csrfToken . '">';
        $html .= '<input type="hidden" name="delete_comment" value="1">';
        $html .= '<input type="hidden" name="comment_id" value="' . $id . '">';
        $html .= '<button type="submit" class="comment__action comment__action--danger">Delete</button>';
        $html .= '</form>';
    }
    $html .= '</div>';
    $html .= '<form method="post" class="comment__reply" data-reply-form="' . $id . '" hidden>';
    $html .= '<input type="hidden" name="' . CSRF_TOKEN_NAME . '" value="' . $csrfToken . '">';
    $html .= '<input type="hidden" name="create_comment" value="1">';
    $html .= '<input type="hidden" name="parent_id" value="' . $id . '">';
    $html .= '<textarea name="body" rows="3" placeholder="Reply to ' . $author . '"></textarea>';
    $html .= '<div class="comment__reply-actions">';
    $html .= '<button type="submit" class="button">Reply</button>';
    $html .= '<button type="button" class="comment__action" data-reply-cancel="' . $id . '">Cancel</button>';
    $html .= '</div>';
    $html .= '</form>';

    if ($children) {
        $html .= '<div class="comment__children">';
        foreach ($children as $child) {
            $html .= notes_render_comment_item($child, $csrfToken, $note);
        }
        $html .= '</div>';
    }

    $html .= '</article>';
    return $html;
}

$shareConfig = htmlspecialchars(json_encode([
    'noteId'   => $noteId,
    'selected' => $shareIds,
    'owner'    => (int)($note['user_id'] ?? 0),
], JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8');

$noteTitle = htmlspecialchars($note['title'] !== '' ? (string)$note['title'] : 'Untitled note', ENT_QUOTES, 'UTF-8');
$noteDate  = htmlspecialchars((string)($note['note_date'] ?? ''), ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $noteTitle ?> · Notes</title>
    <style>
        :root {
            color-scheme: only light;
            --notes-bg: #f8fafc;
            --notes-surface: #ffffff;
            --notes-border: #e2e8f0;
            --notes-text: #0f172a;
            --notes-muted: #64748b;
            --notes-accent: #2563eb;
            --notes-accent-soft: rgba(37, 99, 235, 0.12);
            --notes-radius: 16px;
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: linear-gradient(180deg, rgba(148, 163, 184, 0.08), transparent 320px) var(--notes-bg);
            min-height: 100vh;
            color: var(--notes-text);
        }
        a { color: inherit; text-decoration: none; }
        .view-shell {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px 28px 80px;
            display: flex;
            flex-direction: column;
            gap: 28px;
        }
        .view-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
        }
        .view-header__actions {
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
            border-color: rgba(37, 99, 235, 0.32);
        }
        .button--subtle {
            background: rgba(15, 23, 42, 0.06);
            color: var(--notes-text);
        }
        .button:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 24px rgba(37, 99, 235, 0.18);
        }
        .note-hero {
            position: relative;
            background: var(--notes-surface);
            border-radius: var(--notes-radius);
            border: 1px solid var(--notes-border);
            overflow: hidden;
        }
        .note-cover {
            height: 180px;
            background-size: cover;
            background-position: center;
        }
        .note-header {
            display: flex;
            gap: 20px;
            padding: 24px 24px 12px;
            align-items: center;
        }
        .note-icon {
            width: 72px;
            height: 72px;
            border-radius: 24px;
            background: var(--notes-accent-soft);
            font-size: 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .note-meta {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .note-meta h1 {
            margin: 0;
            font-size: 2rem;
        }
        .note-meta span {
            color: var(--notes-muted);
        }
        .note-properties {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px;
            padding: 0 24px 24px;
        }
        .property-card {
            padding: 12px;
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.04);
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .property-card span.label {
            font-size: 0.75rem;
            color: var(--notes-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .property-card span.value {
            font-weight: 600;
        }
        .note-tags {
            padding: 0 24px 18px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .tag-chip {
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 500;
            border: 1px solid var(--notes-border);
        }
        .note-body {
            background: var(--notes-surface);
            border-radius: var(--notes-radius);
            border: 1px solid var(--notes-border);
            padding: 32px;
            display: flex;
            flex-direction: column;
            gap: 18px;
            line-height: 1.65;
        }
        .block {
            margin: 0;
        }
        .block + .block {
            margin-top: 14px;
        }
        .block--h1 { font-size: 1.6rem; font-weight: 700; }
        .block--h2 { font-size: 1.35rem; font-weight: 650; }
        .block--h3 { font-size: 1.2rem; font-weight: 600; }
        .block--quote {
            padding: 12px 18px;
            border-left: 4px solid rgba(37, 99, 235, 0.3);
            background: rgba(37, 99, 235, 0.08);
            border-radius: 10px;
        }
        .block--callout {
            display: flex;
            gap: 12px;
            padding: 14px 16px;
            border-left: 4px solid rgba(37, 99, 235, 0.35);
            border-radius: 12px;
            background: rgba(37, 99, 235, 0.08);
        }
        .block__callout-icon { font-size: 1.4rem; }
        .block--todo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1rem;
        }
        .block--list {
            padding-left: 24px;
        }
        .block--list-numbered { list-style: decimal; }
        .block--divider {
            border: none;
            border-top: 1px solid var(--notes-border);
        }
        .attachments {
            background: var(--notes-surface);
            border-radius: var(--notes-radius);
            border: 1px solid var(--notes-border);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        .attachments-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
        }
        .attachments-grid img {
            width: 100%;
            border-radius: 12px;
            object-fit: cover;
        }
        .comment-panel {
            background: var(--notes-surface);
            border-radius: var(--notes-radius);
            border: 1px solid var(--notes-border);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .comment-form textarea {
            width: 100%;
            border-radius: 12px;
            border: 1px solid var(--notes-border);
            padding: 12px 14px;
            font-size: 1rem;
            min-height: 96px;
            resize: vertical;
        }
        .comment-list {
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .comment {
            border: 1px solid var(--notes-border);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background: rgba(15, 23, 42, 0.02);
        }
        .comment__header {
            display: flex;
            gap: 12px;
            align-items: baseline;
        }
        .comment__author {
            font-weight: 600;
        }
        .comment__time {
            font-size: 0.8rem;
            color: var(--notes-muted);
        }
        .comment__actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .comment__action,
        .comment__action button {
            border: none;
            background: none;
            color: var(--notes-accent);
            font-weight: 600;
            cursor: pointer;
            padding: 0;
        }
        .comment__action--danger {
            color: #dc2626;
        }
        .comment__children {
            border-left: 2px solid var(--notes-border);
            margin-left: 12px;
            padding-left: 14px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .comment__reply[hidden] {
            display: none;
        }
        .comment__reply textarea {
            width: 100%;
            border-radius: 12px;
            border: 1px solid var(--notes-border);
            padding: 10px;
            resize: vertical;
        }
        .comment__reply-actions {
            display: flex;
            gap: 12px;
            margin-top: 8px;
        }
        .comment-empty {
            color: var(--notes-muted);
        }
        .flash {
            padding: 12px 16px;
            border-radius: 12px;
            background: rgba(37, 99, 235, 0.12);
            color: var(--notes-accent);
        }
        .flash-error {
            background: rgba(220, 38, 38, 0.14);
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
        .field { display:flex; flex-direction:column; gap:6px; }
        .field label { font-size:0.85rem; font-weight:600; color:var(--notes-muted); }
        .field input, .field textarea { border:1px solid var(--notes-border); border-radius:10px; padding:10px 12px; }
        .share-picker { max-height:260px; overflow-y:auto; border:1px solid var(--notes-border); border-radius:12px; padding:12px; display:flex; flex-direction:column; gap:10px; }
        .share-picker__item { display:flex; gap:10px; align-items:center; }
        @media (max-width: 900px) {
            .view-header { flex-direction: column; align-items: flex-start; }
            .view-header__actions { width: 100%; flex-wrap: wrap; }
            .view-header__actions .button { flex: 1 1 auto; justify-content: center; }
        }
    </style>
</head>
<body>
<div class="view-shell">
    <header class="view-header">
        <div class="view-header__nav">
            <a class="button button--ghost" href="index.php">← Back to notes</a>
        </div>
        <div class="view-header__actions">
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
            <?php if ($canShare): ?>
                <button class="button button--ghost" data-modal-open="note-share" data-share-config="<?= $shareConfig ?>">Share</button>
            <?php endif; ?>
            <?php if ($canEdit): ?>
                <a class="button" href="edit.php?id=<?= $noteId ?>">Edit note</a>
            <?php endif; ?>
        </div>
    </header>

    <?php flash_message(); ?>

    <section class="note-hero">
        <?php if ($coverUrl): ?>
            <div class="note-cover" style="background-image:url('<?= htmlspecialchars($coverUrl, ENT_QUOTES, 'UTF-8') ?>');"></div>
        <?php endif; ?>
        <div class="note-header">
            <div class="note-icon"><?= htmlspecialchars($iconChar, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="note-meta">
                <h1><?= $noteTitle ?></h1>
                <span><?= $noteDate ?: 'No date' ?> · Owner <?= htmlspecialchars($owner, ENT_QUOTES, 'UTF-8') ?> · Status <?= htmlspecialchars($status, ENT_QUOTES, 'UTF-8') ?></span>
            </div>
        </div>
        <div class="note-properties">
            <?php foreach ($properties as $key => $value):
                $labelMap = notes_property_labels();
                $label = $labelMap[$key] ?? ucfirst(str_replace('_', ' ', $key));
                $display = $value !== '' ? htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8') : '—';
                ?>
                <div class="property-card">
                    <span class="label"><?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?></span>
                    <span class="value"><?= $display ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <div class="note-tags">
            <?php if (!$tags): ?>
                <span style="color:var(--notes-muted);">No tags yet.</span>
            <?php else: ?>
                <?php foreach ($tags as $tag):
                    $label = htmlspecialchars((string)($tag['label'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $color = htmlspecialchars((string)($tag['color'] ?? '#d1d5db'), ENT_QUOTES, 'UTF-8');
                    ?>
                    <span class="tag-chip" style="background: <?= $color ?>22; border-color: <?= $color ?>55; color: <?= $color ?>;">#<?= $label ?></span>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </section>

    <article class="note-body">
        <?= notes_render_blocks($blocks, $bodyText) ?>
    </article>

    <?php if ($photos): ?>
        <section class="attachments">
            <h2 style="margin:0;">Attachments</h2>
            <div class="attachments-grid">
                <?php foreach ($photos as $photo):
                    $url = htmlspecialchars((string)($photo['url'] ?? ''), ENT_QUOTES, 'UTF-8');
                    ?>
                    <img src="<?= $url ?>" alt="Note attachment">
                <?php endforeach; ?>
            </div>
        </section>
    <?php endif; ?>

    <section class="comment-panel">
        <div>
            <h2 style="margin:0 0 8px;">Discussion</h2>
            <p style="margin:0;color:var(--notes-muted);">Collaborate with your team directly in this note.</p>
        </div>
        <form method="post" class="comment-form">
            <input type="hidden" name="<?= CSRF_TOKEN_NAME ?>" value="<?= $csrfToken ?>">
            <input type="hidden" name="create_comment" value="1">
            <textarea name="body" placeholder="Leave a comment…"></textarea>
            <div style="margin-top:12px;display:flex;justify-content:flex-end;">
                <button type="submit" class="button">Post comment</button>
            </div>
        </form>
        <div class="comment-list">
            <?= notes_render_comments($comments, $csrfToken, $note) ?>
        </div>
    </section>
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