<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers.php';

/**
 * Notes library (owner + explicit shares)
 * Tables expected (in your APP DB):
 *  - notes(id, user_id, note_date, title, body, created_at, updated_at)
 *  - note_photos(id, note_id, position, s3_key, url, created_at)
 *  - notes_shares(id, note_id, user_id, created_at)
 *
 * Optional: if your shares table still uses `shared_with`, detection below handles it.
 */

const NOTES_MAX_MB = 70;
const NOTES_ALLOWED_MIMES = [
    'image/jpeg'          => 'jpg',
    'image/png'           => 'png',
    'image/webp'          => 'webp',
    'image/heic'          => 'heic',
    'image/heif'          => 'heic',
    'image/heic-sequence' => 'heic',
    'image/heif-sequence' => 'heic',
    'application/octet-stream' => null, // fallback by filename
];

const NOTES_DEFAULT_STATUS = 'in_progress';

function notes_available_statuses(): array {
    return [
        'idea'         => 'Idea',
        'in_progress'  => 'In Progress',
        'review'       => 'In Review',
        'blocked'      => 'Blocked',
        'complete'     => 'Complete',
        'archived'     => 'Archived',
    ];
}

function notes_status_label(?string $status): string {
    $status = notes_normalize_status($status);
    $map    = notes_available_statuses();
    return $map[$status] ?? ucwords(str_replace('_', ' ', (string)$status));
}

function notes_normalize_status(?string $status): string {
    $map = notes_available_statuses();
    $status = trim((string)$status);
    if ($status === '') {
        return NOTES_DEFAULT_STATUS;
    }
    $key = strtolower(str_replace([' ', '-'], '_', $status));
    if (isset($map[$key])) {
        return $key;
    }
    foreach ($map as $slug => $label) {
        if (strcasecmp($label, $status) === 0) {
            return $slug;
        }
    }
    return NOTES_DEFAULT_STATUS;
}

function notes_status_badge_class(?string $status): string {
    $status = notes_normalize_status($status);
    $map = [
        'idea'        => 'badge--blue',
        'in_progress' => 'badge--indigo',
        'review'      => 'badge--purple',
        'blocked'     => 'badge--orange',
        'complete'    => 'badge--green',
        'archived'    => 'badge--slate',
    ];
    return $map[$status] ?? 'badge--indigo';
}

function notes_random_tag_color(): string {
    $palette = ['#6366F1', '#0EA5E9', '#10B981', '#F59E0B', '#EC4899', '#F97316', '#14B8A6', '#A855F7', '#8B5CF6', '#EF4444'];
    return $palette[array_rand($palette)];
}

function notes_default_properties(): array {
    return [
        'project'  => '',
        'location' => '',
        'due_date' => '',
        'priority' => 'Medium',
    ];
}

function notes_property_labels(): array {
    return [
        'project'  => 'Project',
        'location' => 'Location',
        'due_date' => 'Due date',
        'priority' => 'Priority',
    ];
}

function notes_priority_options(): array {
    return ['High', 'Medium', 'Low'];
}

function notes_priority_badge_class(?string $priority): string {
    $priority = trim((string)$priority);
    $map = [
        'High'   => 'badge--danger',
        'Medium' => 'badge--amber',
        'Low'    => 'badge--teal',
    ];
    return $map[$priority] ?? 'badge--slate';
}

function notes_normalize_properties($props): array {
    $defaults = notes_default_properties();
    if (!is_array($props)) {
        return $defaults;
    }
    $normalized = $defaults;
    foreach ($defaults as $key => $default) {
        $val = $props[$key] ?? $default;
        if ($key === 'due_date') {
            $val = trim((string)$val);
            if ($val !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $val)) {
                $val = '';
            }
        } elseif ($key === 'priority') {
            $val = in_array($val, notes_priority_options(), true) ? $val : $default;
        } else {
            $val = trim((string)$val);
        }
        $normalized[$key] = $val;
    }
    return $normalized;
}
function notes__is_safe_identifier(string $name): bool {
    return (bool)preg_match('/^[A-Za-z0-9_]+$/', $name);
}


/* ---------- tiny schema helpers (tolerant) ---------- */
function notes__col_exists(PDO $pdo, string $table, string $col): bool {
    try {
        $st = $pdo->prepare("SHOW COLUMNS FROM `$table` LIKE ?");
        $st->execute([$col]);
        if ($st->fetchColumn()) {
            return true;
        }
    } catch (Throwable $e) {
        // hosts may block SHOW commands; fall through to SELECT-based probe
    }

    if (!notes__is_safe_identifier($table) || !notes__is_safe_identifier($col)) {
        return false;
    }

    try {
        $pdo->query("SELECT `$col` FROM `$table` LIMIT 0");
        return true;
    } catch (Throwable $e) {
        return false;
    }
}
function notes__table_exists(PDO $pdo, string $table): bool {
    try {
        $st = $pdo->prepare("SHOW TABLES LIKE ?");
        $st->execute([$table]);
        if ($st->fetchColumn()) {
            return true;
        }
    } catch (Throwable $e) {
        // fall through to SELECT-based probe
    }

    if (!notes__is_safe_identifier($table)) {
        return false;
    }

    try {
        $pdo->query("SELECT 1 FROM `$table` LIMIT 1");
        return true;
    } catch (Throwable $e) {
        return false;
    }
}
function notes__shares_column(PDO $pdo): ?string {
    // Prefer `user_id` (current schema). Fall back to legacy `shared_with`.
    if (!notes__table_exists($pdo, 'notes_shares')) return null;
    if (notes__col_exists($pdo, 'notes_shares', 'user_id')) return 'user_id';
    if (notes__col_exists($pdo, 'notes_shares', 'shared_with')) return 'shared_with';
    return null;
}
function notes__ensure_shares_schema(PDO $pdo): ?string {
    $col = notes__shares_column($pdo);
    if ($col) {
        return $col;
    }

    try {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS notes_shares (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                note_id BIGINT UNSIGNED NOT NULL,
                user_id BIGINT UNSIGNED NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_note_user (note_id, user_id),
                INDEX idx_user (user_id),
                CONSTRAINT fk_notes_shares_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
    } catch (Throwable $e) {
        return null;
    }

    $col = notes__shares_column($pdo);
    if ($col) {
        return $col;
    }

    // Table exists but without expected columns: try adding a `user_id` column.
    try {
        $pdo->exec('ALTER TABLE notes_shares ADD COLUMN user_id BIGINT UNSIGNED NULL');
        $pdo->exec('CREATE INDEX idx_user ON notes_shares (user_id)');
    } catch (Throwable $e) {
        // ignore; best effort
    }

    return notes__shares_column($pdo);
}

function notes__ensure_pages_meta_schema(PDO $pdo): bool {
    if (notes__table_exists($pdo, 'note_pages_meta')) {
        return true;
    }
    try {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS note_pages_meta (
                note_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
                icon VARCHAR(32) NULL,
                cover_url VARCHAR(1000) NULL,
                status VARCHAR(32) NULL,
                properties LONGTEXT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_note_pages_meta_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        return true;
    } catch (Throwable $e) {
        error_log('Failed ensuring note_pages_meta: '.$e->getMessage());
        return false;
    }
}

function notes__ensure_blocks_schema(PDO $pdo): bool {
    if (notes__table_exists($pdo, 'note_blocks')) {
        return true;
    }
    try {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS note_blocks (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                note_id BIGINT UNSIGNED NOT NULL,
                block_uid VARCHAR(64) NOT NULL,
                position INT UNSIGNED NOT NULL,
                block_type VARCHAR(32) NOT NULL,
                payload LONGTEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_block_uid (block_uid),
                INDEX idx_note (note_id),
                INDEX idx_note_pos (note_id, position),
                CONSTRAINT fk_note_blocks_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        return true;
    } catch (Throwable $e) {
        error_log('Failed ensuring note_blocks: '.$e->getMessage());
        return false;
    }
}

function notes__ensure_note_tags_schema(PDO $pdo): bool {
    if (notes__table_exists($pdo, 'note_tags_catalog') && notes__table_exists($pdo, 'note_tag_assignments')) {
        return true;
    }
    try {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS note_tags_catalog (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                label VARCHAR(100) NOT NULL,
                color VARCHAR(24) NOT NULL DEFAULT '#6366F1',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_label (label)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS note_tag_assignments (
                note_id BIGINT UNSIGNED NOT NULL,
                tag_id BIGINT UNSIGNED NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (note_id, tag_id),
                INDEX idx_tag (tag_id),
                CONSTRAINT fk_note_tag_assign_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
                CONSTRAINT fk_note_tag_assign_tag FOREIGN KEY (tag_id) REFERENCES note_tags_catalog(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        return true;
    } catch (Throwable $e) {
        error_log('Failed ensuring note tag schema: '.$e->getMessage());
        return false;
    }
}

function notes__ensure_templates_schema(PDO $pdo): bool {
    if (notes__table_exists($pdo, 'note_templates')) {
        return true;
    }
    try {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS note_templates (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                name VARCHAR(200) NOT NULL,
                title VARCHAR(200) NULL,
                icon VARCHAR(32) NULL,
                cover_url VARCHAR(1000) NULL,
                status VARCHAR(32) NULL,
                properties LONGTEXT NULL,
                tags LONGTEXT NULL,
                blocks LONGTEXT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_name (user_id, name),
                INDEX idx_template_user (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        return true;
    } catch (Throwable $e) {
        error_log('Failed ensuring note_templates: ' . $e->getMessage());
        return false;
    }
}

function notes__ensure_template_shares_schema(PDO $pdo): bool {
    if (notes__table_exists($pdo, 'note_template_shares')) {
        return true;
    }
    try {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS note_template_shares (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                template_id BIGINT UNSIGNED NOT NULL,
                user_id BIGINT UNSIGNED NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_template_user (template_id, user_id),
                INDEX idx_template_share_user (user_id),
                CONSTRAINT fk_template_shares_template FOREIGN KEY (template_id) REFERENCES note_templates(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        return true;
    } catch (Throwable $e) {
        error_log('Failed ensuring note_template_shares: ' . $e->getMessage());
        return false;
    }
}

/* ---------- MIME/extension helpers ---------- */
function notes_ext_for_mime(string $mime): ?string {
    return NOTES_ALLOWED_MIMES[$mime] ?? null;
}
function notes_resolve_ext_and_mime(string $tmpPath, string $origName): array {
    $mime = 'application/octet-stream';
    $fi   = @finfo_open(FILEINFO_MIME_TYPE);
    if ($fi) {
        $mm = @finfo_file($fi, $tmpPath);
        if (is_string($mm) && $mm !== '') $mime = $mm;
        @finfo_close($fi);
    }
    $ext = notes_ext_for_mime($mime);
    if ($ext === null) {
        $fnExt = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
        if (in_array($fnExt, ['jpg','jpeg','png','webp','heic','heif'], true)) {
            $ext = $fnExt === 'jpeg' ? 'jpg' : ($fnExt === 'heif' ? 'heic' : $fnExt);
            if ($mime === 'application/octet-stream') {
                $mime = [
                    'jpg'  => 'image/jpeg',
                    'png'  => 'image/png',
                    'webp' => 'image/webp',
                    'heic' => 'image/heic',
                ][$ext] ?? 'application/octet-stream';
            }
        }
    }
    return [$ext, $mime];
}

/* ---------- CRUD ---------- */
function notes_save_page_meta_internal(PDO $pdo, int $noteId, array $meta): void {
    if (!notes__ensure_pages_meta_schema($pdo)) {
        return;
    }

    $icon       = trim((string)($meta['icon'] ?? '')) ?: null;
    $coverUrl   = trim((string)($meta['cover_url'] ?? '')) ?: null;
    $status     = notes_normalize_status($meta['status'] ?? null);
    $properties = $meta['properties'] ?? null;
    if (is_array($properties)) {
        $properties = json_encode(notes_normalize_properties($properties), JSON_UNESCAPED_UNICODE);
    } elseif (is_string($properties) && $properties !== '') {
        $decoded = json_decode($properties, true);
        $properties = json_encode(notes_normalize_properties($decoded), JSON_UNESCAPED_UNICODE);
    } else {
        $properties = json_encode(notes_default_properties(), JSON_UNESCAPED_UNICODE);
    }

    $sql = "INSERT INTO note_pages_meta (note_id, icon, cover_url, status, properties)
            VALUES (:note_id, :icon, :cover_url, :status, :properties)
            ON DUPLICATE KEY UPDATE icon=VALUES(icon), cover_url=VALUES(cover_url), status=VALUES(status), properties=VALUES(properties), updated_at=CURRENT_TIMESTAMP";
    $st = $pdo->prepare($sql);
    $st->execute([
        ':note_id'    => $noteId,
        ':icon'       => $icon,
        ':cover_url'  => $coverUrl,
        ':status'     => $status,
        ':properties' => $properties,
    ]);
}

function notes_save_page_meta(int $noteId, array $meta): void {
    $pdo = get_pdo();
    notes_save_page_meta_internal($pdo, $noteId, $meta);
}

function notes_fetch_page_meta(int $noteId): array {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_pages_meta')) {
        return [
            'icon'       => null,
            'cover_url'  => null,
            'status'     => NOTES_DEFAULT_STATUS,
            'properties' => notes_default_properties(),
        ];
    }
    $st = $pdo->prepare('SELECT icon, cover_url, status, properties FROM note_pages_meta WHERE note_id = ? LIMIT 1');
    $st->execute([$noteId]);
    $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];
    $properties = notes_default_properties();
    if (!empty($row['properties'])) {
        $decoded = json_decode((string)$row['properties'], true);
        $properties = notes_normalize_properties($decoded);
    }
    $status = $row['status'] ?? NOTES_DEFAULT_STATUS;
    return [
        'icon'       => $row['icon'] ?? null,
        'cover_url'  => $row['cover_url'] ?? null,
        'status'     => $status,
        'properties' => $properties,
    ];
}

function notes_fetch_page_meta_bulk(array $noteIds): array {
    $noteIds = array_values(array_unique(array_filter(array_map('intval', $noteIds))));
    if (!$noteIds) return [];
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_pages_meta')) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($noteIds), '?'));
    $st = $pdo->prepare("SELECT note_id, icon, cover_url, status, properties FROM note_pages_meta WHERE note_id IN ($placeholders)");
    $st->execute($noteIds);
    $out = [];
    while ($row = $st->fetch(PDO::FETCH_ASSOC)) {
        $nid = (int)($row['note_id'] ?? 0);
        if ($nid <= 0) continue;
        $props = notes_default_properties();
        if (!empty($row['properties'])) {
            $props = notes_normalize_properties(json_decode((string)$row['properties'], true));
        }
        $out[$nid] = [
            'icon'       => $row['icon'] ?? null,
            'cover_url'  => $row['cover_url'] ?? null,
            'status'     => $row['status'] ?? NOTES_DEFAULT_STATUS,
            'properties' => $props,
        ];
    }
    return $out;
}

function notes_validate_color(?string $color): ?string {
    $color = trim((string)$color);
    if ($color === '') {
        return null;
    }
    if (preg_match('/^#?[0-9a-fA-F]{6}$/', $color)) {
        return '#' . ltrim($color, '#');
    }
    return null;
}

function notes_normalize_tags_input(array $tags): array {
    $normalized = [];
    foreach ($tags as $tag) {
        if (is_array($tag)) {
            $label = trim((string)($tag['label'] ?? ''));
            $color = notes_validate_color($tag['color'] ?? null);
        } else {
            $label = trim((string)$tag);
            $color = null;
        }
        if ($label === '') {
            continue;
        }
        $key = mb_strtolower($label, 'UTF-8');
        if (!isset($normalized[$key])) {
            $normalized[$key] = ['label' => $label, 'color' => $color];
        } elseif ($color && !$normalized[$key]['color']) {
            $normalized[$key]['color'] = $color;
        }
    }
    return array_values($normalized);
}

function notes_catalog_id_for_label(PDO $pdo, string $label, ?string $color = null): ?int {
    if (!notes__ensure_note_tags_schema($pdo)) {
        return null;
    }
    $label = trim($label);
    if ($label === '') {
        return null;
    }
    $color = notes_validate_color($color) ?? notes_random_tag_color();
    $select = $pdo->prepare('SELECT id, color FROM note_tags_catalog WHERE label = ? LIMIT 1');
    $select->execute([$label]);
    $row = $select->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        $id = (int)$row['id'];
        if ($color && (!isset($row['color']) || $row['color'] !== $color)) {
            $upd = $pdo->prepare('UPDATE note_tags_catalog SET color = :color WHERE id = :id');
            $upd->execute([':color' => $color, ':id' => $id]);
        }
        return $id;
    }
    $insert = $pdo->prepare('INSERT INTO note_tags_catalog (label, color) VALUES (:label, :color)');
    try {
        $insert->execute([':label' => $label, ':color' => $color]);
        return (int)$pdo->lastInsertId();
    } catch (Throwable $e) {
        // Unique constraint: try select again (possible race)
        $select->execute([$label]);
        $row = $select->fetch(PDO::FETCH_ASSOC);
        return $row ? (int)$row['id'] : null;
    }
}

function notes_assign_tags_internal(PDO $pdo, int $noteId, array $tags): void {
    if (!notes__ensure_note_tags_schema($pdo)) {
        return;
    }
    $normalized = notes_normalize_tags_input($tags);
    $pdo->prepare('DELETE FROM note_tag_assignments WHERE note_id = ?')->execute([$noteId]);
    if (!$normalized) {
        return;
    }
    $ins = $pdo->prepare('INSERT INTO note_tag_assignments (note_id, tag_id) VALUES (:note_id, :tag_id)');
    foreach ($normalized as $tag) {
        $tagId = notes_catalog_id_for_label($pdo, $tag['label'], $tag['color'] ?? null);
        if ($tagId) {
            $ins->execute([':note_id' => $noteId, ':tag_id' => $tagId]);
        }
    }
}

function notes_assign_tags(int $noteId, array $tags): void {
    $pdo = get_pdo();
    notes_assign_tags_internal($pdo, $noteId, $tags);
}

function notes_fetch_note_tags(int $noteId): array {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_tag_assignments')) {
        return [];
    }
    $sql = "SELECT c.id, c.label, c.color
            FROM note_tag_assignments nta
            JOIN note_tags_catalog c ON c.id = nta.tag_id
            WHERE nta.note_id = ?
            ORDER BY c.label";
    $st = $pdo->prepare($sql);
    $st->execute([$noteId]);
    return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
}

function notes_fetch_tags_for_notes(array $noteIds): array {
    $noteIds = array_values(array_unique(array_filter(array_map('intval', $noteIds))));
    if (!$noteIds) {
        return [];
    }
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_tag_assignments')) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($noteIds), '?'));
    $sql = "SELECT nta.note_id, c.id, c.label, c.color
            FROM note_tag_assignments nta
            JOIN note_tags_catalog c ON c.id = nta.tag_id
            WHERE nta.note_id IN ($placeholders)
            ORDER BY c.label";
    $st = $pdo->prepare($sql);
    $st->execute($noteIds);
    $map = [];
    while ($row = $st->fetch(PDO::FETCH_ASSOC)) {
        $nid = (int)($row['note_id'] ?? 0);
        if ($nid <= 0) {
            continue;
        }
        $map[$nid][] = [
            'id'    => (int)($row['id'] ?? 0),
            'label' => $row['label'] ?? '',
            'color' => $row['color'] ?? notes_random_tag_color(),
        ];
    }
    return $map;
}

function notes_all_tag_options(): array {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_tags_catalog')) {
        return [];
    }
    $rows = $pdo->query('SELECT id, label, color FROM note_tags_catalog ORDER BY label')->fetchAll(PDO::FETCH_ASSOC) ?: [];
    return array_map(static function ($row) {
        return [
            'id'    => (int)($row['id'] ?? 0),
            'label' => (string)($row['label'] ?? ''),
            'color' => (string)($row['color'] ?? notes_random_tag_color()),
        ];
    }, $rows);
}

/* ---------- templates ---------- */
function notes_templates_table_exists(?PDO $pdo = null): bool {
    $pdo = $pdo ?: get_pdo();
    return notes__table_exists($pdo, 'note_templates');
}

function notes_template_shares_table_exists(?PDO $pdo = null): bool {
    $pdo = $pdo ?: get_pdo();
    return notes__table_exists($pdo, 'note_template_shares');
}

function notes__normalize_template_row(array $row): array {
    $properties = notes_default_properties();
    if (!empty($row['properties'])) {
        $decoded = json_decode((string)$row['properties'], true);
        $properties = notes_normalize_properties(is_array($decoded) ? $decoded : []);
    }
    $tags = [];
    if (!empty($row['tags'])) {
        $decoded = json_decode((string)$row['tags'], true);
        $tags = notes_normalize_tags_input(is_array($decoded) ? $decoded : []);
    }
    $blocks = [];
    if (!empty($row['blocks'])) {
        $decoded = json_decode((string)$row['blocks'], true);
        if (is_array($decoded)) {
            foreach ($decoded as $entry) {
                if (!is_array($entry)) {
                    continue;
                }
                $normalized = notes_normalize_block($entry, count($blocks) + 1);
                if ($normalized) {
                    unset($normalized['position']);
                    $blocks[] = $normalized;
                }
            }
        }
    }

    return [
        'id'         => (int)($row['id'] ?? 0),
        'name'       => (string)($row['name'] ?? ''),
        'title'      => (string)($row['title'] ?? ''),
        'icon'       => $row['icon'] ?? null,
        'coverUrl'   => $row['cover_url'] ?? null,
        'status'     => notes_normalize_status($row['status'] ?? NOTES_DEFAULT_STATUS),
        'properties' => $properties,
        'tags'       => $tags,
        'blocks'     => $blocks,
    ];
}

function notes_template_fetch(int $templateId): ?array {
    $templateId = (int)$templateId;
    if ($templateId <= 0) {
        return null;
    }
    $pdo = get_pdo();
    if (!notes_templates_table_exists($pdo)) {
        return null;
    }
    $st = $pdo->prepare('SELECT * FROM note_templates WHERE id = :id LIMIT 1');
    $st->execute([':id' => $templateId]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return null;
    }
    $normalized = notes__normalize_template_row($row);
    $normalized['owner_id'] = (int)($row['user_id'] ?? 0);
    $normalized['share_count'] = 0;
    if (notes_template_shares_table_exists($pdo)) {
        $countSt = $pdo->prepare('SELECT COUNT(*) FROM note_template_shares WHERE template_id = :id');
        $countSt->execute([':id' => $templateId]);
        $normalized['share_count'] = (int)$countSt->fetchColumn();
    }
    return $normalized;
}

function notes_fetch_templates_for_user(int $userId): array {
    $userId = (int)$userId;
    if ($userId <= 0) {
        return [];
    }
    $pdo = get_pdo();
    if (!notes__ensure_templates_schema($pdo)) {
        return [];
    }
    $shareReady = notes_template_shares_table_exists($pdo) || notes__ensure_template_shares_schema($pdo);

    $templates = [];
    $seen      = [];

    $ownedSql = 'SELECT t.*, 0 AS share_count FROM note_templates t WHERE t.user_id = :user ORDER BY t.name';
    if ($shareReady) {
        $ownedSql = 'SELECT t.*, (SELECT COUNT(*) FROM note_template_shares s WHERE s.template_id = t.id) AS share_count
                     FROM note_templates t
                     WHERE t.user_id = :user
                     ORDER BY t.name';
    }
    $owned = $pdo->prepare($ownedSql);
    $owned->execute([':user' => $userId]);
    while ($row = $owned->fetch(PDO::FETCH_ASSOC)) {
        $normalized = notes__normalize_template_row($row);
        $normalized['owner_id']   = (int)($row['user_id'] ?? 0);
        $normalized['is_owner']   = true;
        $normalized['shared_from']= null;
        $normalized['share_count']= (int)($row['share_count'] ?? 0);
        $templates[] = $normalized;
        $seen[$normalized['id']] = true;
    }

    if ($shareReady) {
        $sharedIds = [];
        $sharedIdStmt = $pdo->prepare('SELECT DISTINCT template_id FROM note_template_shares WHERE user_id = :user');
        $sharedIdStmt->execute([':user' => $userId]);
        while ($row = $sharedIdStmt->fetch(PDO::FETCH_ASSOC)) {
            $tid = (int)($row['template_id'] ?? 0);
            if ($tid > 0 && !isset($seen[$tid])) {
                $sharedIds[] = $tid;
            }
        }
        if ($sharedIds) {
            $placeholders = implode(',', array_fill(0, count($sharedIds), '?'));
            $sharedSql = 'SELECT t.*, (SELECT COUNT(*) FROM note_template_shares s WHERE s.template_id = t.id) AS share_count
                          FROM note_templates t
                          WHERE t.id IN (' . $placeholders . ')
                          ORDER BY t.name';
            $sharedStmt = $pdo->prepare($sharedSql);
            $sharedStmt->execute($sharedIds);
            while ($row = $sharedStmt->fetch(PDO::FETCH_ASSOC)) {
                $normalized = notes__normalize_template_row($row);
                $normalized['owner_id']    = (int)($row['user_id'] ?? 0);
                $normalized['is_owner']    = ((int)($row['user_id'] ?? 0) === $userId);
                $normalized['shared_from'] = $normalized['is_owner'] ? null : notes_user_label((int)($row['user_id'] ?? 0));
                $normalized['share_count'] = (int)($row['share_count'] ?? 0);
                $templates[] = $normalized;
                $seen[$normalized['id']] = true;
            }
        }
    }

    usort($templates, static function ($a, $b) {
        return strcasecmp($a['name'] ?? '', $b['name'] ?? '');
    });

    return $templates;
}

function notes_fetch_templates_owned(int $userId): array {
    return array_values(array_filter(
        notes_fetch_templates_for_user($userId),
        static fn($tpl) => !empty($tpl['is_owner'])
    ));
}

function notes_get_template_share_user_ids(int $templateId): array {
    $templateId = (int)$templateId;
    if ($templateId <= 0) {
        return [];
    }
    $pdo = get_pdo();
    if (!notes_template_shares_table_exists($pdo)) {
        return [];
    }
    $st = $pdo->prepare('SELECT user_id FROM note_template_shares WHERE template_id = :id');
    $st->execute([':id' => $templateId]);
    return array_map('intval', array_column($st->fetchAll(PDO::FETCH_ASSOC) ?: [], 'user_id'));
}

function notes_template_share_details(int $templateId): array {
    $ids = notes_get_template_share_user_ids($templateId);
    if (!$ids) {
        return [];
    }
    $labels = notes_fetch_users_map($ids);
    $out = [];
    foreach ($ids as $id) {
        $out[] = [
            'id'    => $id,
            'label' => $labels[$id] ?? ('User #' . $id),
        ];
    }
    return $out;
}

function notes_update_template_shares(int $templateId, array $userIds): void {
    $templateId = (int)$templateId;
    $userIds = array_values(array_unique(array_filter(array_map('intval', $userIds))));
    if ($templateId <= 0) {
        return;
    }
    $pdo = get_pdo();
    if (!notes_template_shares_table_exists($pdo) && !notes__ensure_template_shares_schema($pdo)) {
        throw new RuntimeException('note_template_shares table not available.');
    }
    $pdo->beginTransaction();
    try {
        $pdo->prepare('DELETE FROM note_template_shares WHERE template_id = :id')->execute([':id' => $templateId]);
        if ($userIds) {
            $ins = $pdo->prepare('INSERT INTO note_template_shares (template_id, user_id) VALUES (:tid, :uid)');
            foreach ($userIds as $uid) {
                $ins->execute([':tid' => $templateId, ':uid' => $uid]);
            }
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function notes_apply_template_shares(int $templateId, array $userIds, array $template, bool $notify = true): array {
    $before = notes_get_template_share_user_ids($templateId);
    notes_update_template_shares($templateId, $userIds);
    $after = notes_get_template_share_user_ids($templateId);

    $added   = array_values(array_diff($after, $before));
    $removed = array_values(array_diff($before, $after));

    if ($notify && $added) {
        $ownerId = (int)($template['owner_id'] ?? ($template['user_id'] ?? 0));
        $title   = trim((string)($template['name'] ?? 'Template'));
        $who     = notes_user_label($ownerId);
        $link    = '/notes/new.php?template=' . (int)$templateId;
        $titleMsg= 'A note template was shared with you';
        $bodyMsg = "“{$title}” — shared by {$who}";
        $payload = ['template_id' => (int)$templateId];
        try {
            notify_users($added, 'note.template.share', $titleMsg, $bodyMsg, $link, $payload);
        } catch (Throwable $e) {
            error_log('Failed notifying template share: ' . $e->getMessage());
        }
    }

    log_event('note.template.share', 'note_template', (int)$templateId, [
        'added'   => $added,
        'removed' => $removed,
    ]);

    return [
        'before' => array_map('intval', $before),
        'after'  => array_map('intval', $after),
        'added'  => $added,
        'removed'=> $removed,
    ];
}

function notes_template_can_share(array $template, ?int $userId = null): bool {
    $userId = $userId ?? (int)(current_user()['id'] ?? 0);
    if ($userId <= 0) {
        return false;
    }
    $owner = (int)($template['owner_id'] ?? ($template['user_id'] ?? 0));
    return $owner === $userId;
}

function notes_template_is_visible_to_user(array $template, int $userId): bool {
    $userId = (int)$userId;
    if ($userId <= 0) {
        return false;
    }
    if (notes_template_can_share($template, $userId)) {
        return true;
    }
    $templateId = (int)($template['id'] ?? 0);
    if ($templateId <= 0) {
        return false;
    }
    $shares = notes_get_template_share_user_ids($templateId);
    return in_array($userId, $shares, true);
}

function notes_create_template_from_note(int $noteId, int $userId, string $name): int {
    $userId = (int)$userId;
    $name   = trim($name);
    if ($userId <= 0) {
        throw new InvalidArgumentException('Missing template owner.');
    }
    if ($name === '') {
        throw new InvalidArgumentException('Template name required.');
    }

    $pdo = get_pdo();
    if (!notes__ensure_templates_schema($pdo)) {
        throw new RuntimeException('Templates storage unavailable.');
    }

    $note = notes_fetch($noteId);
    if (!$note) {
        throw new RuntimeException('Note not found.');
    }

    $meta    = notes_fetch_page_meta($noteId);
    $blocks  = notes_fetch_blocks($noteId);
    $tags    = notes_fetch_note_tags($noteId);
    $payloadBlocks = [];
    foreach ($blocks as $block) {
        if (!is_array($block)) {
            continue;
        }
        $normalized = notes_normalize_block($block, count($payloadBlocks) + 1);
        if ($normalized) {
            unset($normalized['position']);
            $payloadBlocks[] = $normalized;
        }
    }
    $payloadTags = [];
    foreach ($tags as $tag) {
        $label = trim((string)($tag['label'] ?? ''));
        if ($label === '') {
            continue;
        }
        $payloadTags[] = [
            'label' => $label,
            'color' => notes_validate_color($tag['color'] ?? null),
        ];
    }

    $sql = 'INSERT INTO note_templates (user_id, name, title, icon, cover_url, status, properties, tags, blocks)
            VALUES (:user_id, :name, :title, :icon, :cover_url, :status, :properties, :tags, :blocks)
            ON DUPLICATE KEY UPDATE
              title = VALUES(title),
              icon = VALUES(icon),
              cover_url = VALUES(cover_url),
              status = VALUES(status),
              properties = VALUES(properties),
              tags = VALUES(tags),
              blocks = VALUES(blocks),
              updated_at = CURRENT_TIMESTAMP,
              id = LAST_INSERT_ID(id)';

    $st = $pdo->prepare($sql);
    $st->execute([
        ':user_id'    => $userId,
        ':name'       => $name,
        ':title'      => (string)($note['title'] ?? ''),
        ':icon'       => $meta['icon'] ?? null,
        ':cover_url'  => $meta['cover_url'] ?? null,
        ':status'     => $meta['status'] ?? NOTES_DEFAULT_STATUS,
        ':properties' => json_encode($meta['properties'] ?? notes_default_properties(), JSON_UNESCAPED_UNICODE),
        ':tags'       => json_encode($payloadTags, JSON_UNESCAPED_UNICODE),
        ':blocks'     => json_encode($payloadBlocks, JSON_UNESCAPED_UNICODE),
    ]);

    return (int)$pdo->lastInsertId();
}

function notes_insert(array $data): int {
    $pdo = get_pdo();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            "INSERT INTO notes (user_id, note_date, title, body)
             VALUES (:user_id, :note_date, :title, :body)"
        );
        $stmt->execute([
            ':user_id'   => (int)$data['user_id'],
            ':note_date' => $data['note_date'],
            ':title'     => $data['title'],
            ':body'      => ($data['body'] ?? '') !== '' ? $data['body'] : null,
        ]);
        $noteId = (int)$pdo->lastInsertId();

        notes_save_page_meta_internal($pdo, $noteId, [
            'icon'       => $data['icon'] ?? null,
            'cover_url'  => $data['cover_url'] ?? null,
            'status'     => $data['status'] ?? NOTES_DEFAULT_STATUS,
            'properties' => $data['properties'] ?? notes_default_properties(),
        ]);

        if (!empty($data['tags']) && is_array($data['tags'])) {
            notes_assign_tags_internal($pdo, $noteId, $data['tags']);
        }
        if (!empty($data['blocks']) && is_array($data['blocks'])) {
            notes_replace_blocks_internal($pdo, $noteId, $data['blocks']);
        }

        $pdo->commit();
        return $noteId;
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function notes_update(int $id, array $data): void {
    $pdo = get_pdo();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            "UPDATE notes SET note_date=:note_date, title=:title, body=:body WHERE id=:id"
        );
        $stmt->execute([
            ':note_date' => $data['note_date'],
            ':title'     => $data['title'],
            ':body'      => ($data['body'] ?? '') !== '' ? $data['body'] : null,
            ':id'        => $id,
        ]);

        notes_save_page_meta_internal($pdo, $id, [
            'icon'       => $data['icon'] ?? null,
            'cover_url'  => $data['cover_url'] ?? null,
            'status'     => $data['status'] ?? NOTES_DEFAULT_STATUS,
            'properties' => $data['properties'] ?? notes_default_properties(),
        ]);

        if (array_key_exists('tags', $data)) {
            notes_assign_tags_internal($pdo, $id, (array)$data['tags']);
        }
        if (array_key_exists('blocks', $data) && is_array($data['blocks'])) {
            notes_replace_blocks_internal($pdo, $id, $data['blocks']);
        }

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function notes_delete(int $id): void {
    // delete photos and object storage, then note
    $photos = notes_fetch_photos($id);
    foreach ($photos as $p) {
        try { s3_client()->deleteObject(['Bucket'=>S3_BUCKET,'Key'=>$p['s3_key']]); } catch (Throwable $e) {}
    }
    $pdo = get_pdo();
    if (notes__table_exists($pdo, 'note_photos')) {
        $pdo->prepare("DELETE FROM note_photos WHERE note_id=?")->execute([$id]);
    }
    if (notes__table_exists($pdo, 'note_comments')) {
        $pdo->prepare("DELETE FROM note_comments WHERE note_id=?")->execute([$id]);
    }
    if (notes__table_exists($pdo, 'notes_shares')) {
        $pdo->prepare("DELETE FROM notes_shares WHERE note_id=?")->execute([$id]);
    }
    $pdo->prepare("DELETE FROM notes WHERE id=?")->execute([$id]);
}

function notes_fetch(int $id): ?array {
    $pdo = get_pdo();
    $st = $pdo->prepare("SELECT * FROM notes WHERE id=? LIMIT 1");
    $st->execute([$id]);
    $row = $st->fetch();
    return $row ?: null;
}

function notes_list_for_user(int $userId): array {
    $pdo  = get_pdo();
    $role = current_user_role_key();

    $sql    = 'SELECT n.* FROM notes n';
    $params = [];

    if (!in_array($role, ['root', 'admin'], true)) {
        $params[':viewer_id'] = $userId;
        $shareCol = notes__ensure_shares_schema($pdo);
        if ($shareCol) {
            $sql .= " WHERE n.user_id = :viewer_id OR EXISTS (SELECT 1 FROM notes_shares s WHERE s.note_id = n.id AND s.`{$shareCol}` = :viewer_id)";
        } else {
            $sql .= ' WHERE n.user_id = :viewer_id';
        }
    }

    $sql .= ' ORDER BY n.updated_at DESC, n.id DESC';

    $st = $pdo->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
    if (!$rows) {
        return [];
    }

    $noteIds = [];
    foreach ($rows as $row) {
        $nid = (int)($row['id'] ?? 0);
        if ($nid > 0) {
            $noteIds[] = $nid;
        }
    }

    $metaMap = notes_fetch_page_meta_bulk($noteIds);
    $tagMap  = notes_fetch_tags_for_notes($noteIds);

    $result = [];
    foreach ($rows as $row) {
        $nid = (int)($row['id'] ?? 0);
        if ($nid <= 0) {
            continue;
        }

        $meta = $metaMap[$nid] ?? [
            'icon'       => null,
            'cover_url'  => null,
            'status'     => NOTES_DEFAULT_STATUS,
            'properties' => notes_default_properties(),
        ];

        $result[] = [
            'id'            => $nid,
            'title'         => trim((string)($row['title'] ?? '')),
            'note_date'     => $row['note_date'] ?? null,
            'body'          => (string)($row['body'] ?? ''),
            'created_at'    => $row['created_at'] ?? null,
            'updated_at'    => $row['updated_at'] ?? null,
            'owner_id'      => (int)($row['user_id'] ?? 0),
            'owner_label'   => notes_user_label((int)($row['user_id'] ?? 0)),
            'meta'          => $meta,
            'tags'          => $tagMap[$nid] ?? [],
            'share_ids'     => notes_get_share_user_ids($nid),
            'comment_count' => notes_comment_count($nid),
        ];
    }

    return $result;
}

function notes_allowed_block_types(): array {
    return ['heading1','heading2','heading3','paragraph','todo','bulleted','numbered','quote','callout','divider'];
}

function notes_generate_block_uid(): string {
    return 'blk_' . bin2hex(random_bytes(6));
}

function notes_normalize_block(array $block, int $position = 0): ?array {
    $types = notes_allowed_block_types();
    $type  = strtolower(trim((string)($block['type'] ?? 'paragraph')));
    if (!in_array($type, $types, true)) {
        $type = 'paragraph';
    }
    $uid = trim((string)($block['uid'] ?? ''));
    if ($uid === '') {
        $uid = notes_generate_block_uid();
    }
    $text = trim((string)($block['text'] ?? ''));
    $checked = !empty($block['checked']);
    $icon = isset($block['icon']) ? trim((string)$block['icon']) : '';
    if ($icon !== '') {
        $icon = mb_substr($icon, 0, 4, 'UTF-8');
    } else {
        $icon = null;
    }
    $color = null;
    if (isset($block['color'])) {
        $color = notes_validate_color($block['color']);
    }

    $items = [];
    if (in_array($type, ['bulleted','numbered'], true)) {
        $itemsSrc = $block['items'] ?? [];
        if (is_array($itemsSrc)) {
            foreach ($itemsSrc as $it) {
                $val = trim((string)$it);
                if ($val !== '') {
                    $items[] = $val;
                }
            }
        }
    }

    if ($type === 'divider') {
        $text = '';
        $checked = false;
        $items = [];
    }
    if ($type === 'todo' && $text === '') {
        return null;
    }

    return [
        'uid'     => $uid,
        'type'    => $type,
        'text'    => $text,
        'checked' => $checked,
        'items'   => $items,
        'icon'    => $icon,
        'color'   => $color,
        'position'=> $position,
    ];
}

function notes_replace_blocks_internal(PDO $pdo, int $noteId, array $blocks): void {
    if (!notes__ensure_blocks_schema($pdo)) {
        return;
    }
    $pdo->prepare('DELETE FROM note_blocks WHERE note_id = ?')->execute([$noteId]);
    if (!$blocks) {
        return;
    }
    $ins = $pdo->prepare('INSERT INTO note_blocks (note_id, block_uid, position, block_type, payload) VALUES (:note_id,:block_uid,:position,:block_type,:payload)');
    $position = 0;
    foreach ($blocks as $rawBlock) {
        $position++;
        $normalized = notes_normalize_block($rawBlock, $position);
        if (!$normalized) {
            continue;
        }
        $payload = $normalized;
        unset($payload['position']);
        $ins->execute([
            ':note_id'    => $noteId,
            ':block_uid'  => $normalized['uid'],
            ':position'   => $position,
            ':block_type' => $normalized['type'],
            ':payload'    => json_encode($payload, JSON_UNESCAPED_UNICODE),
        ]);
    }
}

function notes_replace_blocks(int $noteId, array $blocks): void {
    $pdo = get_pdo();
    notes_replace_blocks_internal($pdo, $noteId, $blocks);
}

function notes_fetch_blocks(int $noteId): array {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_blocks')) {
        return [];
    }
    $st = $pdo->prepare('SELECT block_uid, block_type, payload FROM note_blocks WHERE note_id = ? ORDER BY position');
    $st->execute([$noteId]);
    $blocks = [];
    $position = 0;
    while ($row = $st->fetch(PDO::FETCH_ASSOC)) {
        $payload = json_decode((string)($row['payload'] ?? ''), true);
        if (!is_array($payload)) {
            $payload = [];
        }
        $payload['uid'] = $row['block_uid'] ?? ($payload['uid'] ?? notes_generate_block_uid());
        $payload['type'] = $row['block_type'] ?? ($payload['type'] ?? 'paragraph');
        $position++;
        $normalized = notes_normalize_block($payload, $position);
        if ($normalized) {
            $blocks[] = $normalized;
        }
    }
    return $blocks;
}

function notes_block_plaintext(array $block): string {
    $type = $block['type'] ?? 'paragraph';
    $text = trim((string)($block['text'] ?? ''));
    if ($type === 'divider') {
        return '';
    }
    if (in_array($type, ['bulleted','numbered'], true)) {
        $items = $block['items'] ?? [];
        if (is_array($items) && $items) {
            return implode("\n", array_map(static function ($item) {
                return '• ' . trim((string)$item);
            }, $items));
        }
    }
    return $text;
}

function notes_blocks_to_plaintext(array $blocks): string {
    $parts = [];
    foreach ($blocks as $block) {
        $plain = notes_block_plaintext($block);
        if ($plain !== '') {
            $parts[] = $plain;
        }
    }
    return trim(implode("\n\n", $parts));
}

function notes_toggle_block_checkbox(int $noteId, string $blockUid, bool $checked): bool {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_blocks')) {
        return false;
    }
    $st = $pdo->prepare('SELECT note_id, block_uid, block_type, payload FROM note_blocks WHERE block_uid = ? LIMIT 1');
    $st->execute([$blockUid]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return false;
    }
    if ((int)($row['note_id'] ?? 0) !== $noteId) {
        return false;
    }
    if (($row['block_type'] ?? '') !== 'todo') {
        return false;
    }
    $payload = json_decode((string)($row['payload'] ?? ''), true);
    if (!is_array($payload)) {
        $payload = [];
    }
    $payload['checked'] = $checked ? true : false;
    $payload['type'] = 'todo';
    $upd = $pdo->prepare('UPDATE note_blocks SET payload = :payload, updated_at = CURRENT_TIMESTAMP WHERE block_uid = :uid AND note_id = :note_id');
    $upd->execute([
        ':payload' => json_encode($payload, JSON_UNESCAPED_UNICODE),
        ':uid'     => $blockUid,
        ':note_id' => $noteId,
    ]);
    return true;
}

function notes_parse_blocks_payload(?string $json, string $fallbackBody): array {
    $json = trim((string)$json);
    if ($json === '') {
        $fallback = trim($fallbackBody);
        if ($fallback === '') {
            return [[], ''];
        }
        $block = notes_normalize_block([
            'type' => 'paragraph',
            'text' => $fallback,
        ], 1);
        return $block ? [[$block], $fallback] : [[], $fallback];
    }
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        $fallback = trim($fallbackBody);
        if ($fallback === '') {
            return [[], ''];
        }
        $block = notes_normalize_block([
            'type' => 'paragraph',
            'text' => $fallback,
        ], 1);
        return $block ? [[$block], $fallback] : [[], $fallback];
    }
    $blocks = [];
    foreach ($decoded as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $normalized = notes_normalize_block($entry, count($blocks) + 1);
        if ($normalized) {
            $blocks[] = $normalized;
        }
    }
    $plaintext = $blocks ? notes_blocks_to_plaintext($blocks) : trim($fallbackBody);
    return [$blocks, $plaintext];
}

/* ---------- photos ---------- */
function notes_fetch_photos(int $noteId): array {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_photos')) return [];
    $st = $pdo->prepare("SELECT * FROM note_photos WHERE note_id=? ORDER BY position");
    $st->execute([$noteId]);
    $out = [];
    while ($r = $st->fetch()) { $out[(int)$r['position']] = $r; }
    return $out;
}

function notes_upsert_photo(int $noteId, int $position, string $key, string $url): void {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_photos')) return;
    $sql = "INSERT INTO note_photos (note_id,position,s3_key,url)
            VALUES (:note_id,:position,:s3_key,:url)
            ON DUPLICATE KEY UPDATE s3_key=VALUES(s3_key), url=VALUES(url), created_at=NOW()";
    $st = $pdo->prepare($sql);
    $st->execute([
        ':note_id'  => $noteId,
        ':position' => $position,
        ':s3_key'   => $key,
        ':url'      => $url,
    ]);
}

function notes_remove_photo_by_id(int $photoId): void {
    $pdo = get_pdo();
    if (!notes__table_exists($pdo, 'note_photos')) return;
    $st = $pdo->prepare("SELECT * FROM note_photos WHERE id=?");
    $st->execute([$photoId]);
    if ($row = $st->fetch()) {
        try { s3_client()->deleteObject(['Bucket'=>S3_BUCKET,'Key'=>$row['s3_key']]); } catch (Throwable $e) {}
        $pdo->prepare("DELETE FROM note_photos WHERE id=?")->execute([$photoId]);
    }
}

/** Save uploaded photo (field name -> e.g. 'photo', 'photo1' etc.). Returns [url,key,mime]. */
function notes_save_uploaded_photo(int $noteId, int $position, string $fieldName): array {
    if (!isset($_FILES[$fieldName]) || ($_FILES[$fieldName]['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        throw new RuntimeException("No file for $fieldName");
    }
    $err = (int)$_FILES[$fieldName]['error'];
    if ($err !== UPLOAD_ERR_OK) {
        $map = [
            UPLOAD_ERR_INI_SIZE=>'file exceeds upload_max_filesize',
            UPLOAD_ERR_FORM_SIZE=>'file exceeds MAX_FILE_SIZE',
            UPLOAD_ERR_PARTIAL=>'partial upload',
            UPLOAD_ERR_NO_TMP_DIR=>'missing tmp dir',
            UPLOAD_ERR_CANT_WRITE=>'disk write failed',
            UPLOAD_ERR_EXTENSION=>'blocked by extension',
        ];
        throw new RuntimeException("Upload error: " . ($map[$err] ?? "code $err"));
    }

    $tmp   = (string)$_FILES[$fieldName]['tmp_name'];
    $size  = (int)($_FILES[$fieldName]['size'] ?? 0);
    $oname = (string)($_FILES[$fieldName]['name'] ?? '');
    if ($size <= 0) throw new RuntimeException('Empty file');
    if ($size > NOTES_MAX_MB * 1024 * 1024) throw new RuntimeException('File too large (max '.NOTES_MAX_MB.'MB)');

    [$ext, $mime] = notes_resolve_ext_and_mime($tmp, $oname);
    if (!$ext) throw new RuntimeException("Unsupported type");

    $uuid = bin2hex(random_bytes(8));
    $key  = sprintf('notes/%d/%s-%d.%s', $noteId, $uuid, $position, $ext);

    $url = null;
    $s3Available = class_exists(\Aws\S3\S3Client::class) && S3_BUCKET !== '' && S3_ENDPOINT !== '';
    if ($s3Available) {
        try {
            s3_client()->putObject([
                'Bucket'      => S3_BUCKET,
                'Key'         => $key,
                'SourceFile'  => $tmp,
                'ContentType' => $mime,
            ]);
            $url = s3_object_url($key);
        } catch (Throwable $e) {
            $s3Available = false; // fallback to local
        }
    }
    if (!$s3Available) {
        $base = __DIR__ . '/../uploads';
        $dir  = $base . '/notes/' . $noteId;
        if (!is_dir($dir) && !@mkdir($dir, 0775, true)) {
            throw new RuntimeException('Failed to create uploads directory');
        }
        $dest = $dir . '/' . basename($key);
        if (!@move_uploaded_file($tmp, $dest)) {
            $bytes = @file_get_contents($tmp);
            if ($bytes === false || !@file_put_contents($dest, $bytes)) {
                throw new RuntimeException('Failed to write local file');
            }
        }
        $url = '/uploads/notes/' . $noteId . '/' . basename($dest);
    }

    notes_upsert_photo($noteId, $position, $key, $url);
    return ['url' => $url, 'key' => $key, 'mime' => $mime];
}

/* ---------- shares & authorization ---------- */
function notes_all_users(): array {
    $pdo = get_pdo('core'); // your CORE users
    try {
        $st = $pdo->query('SELECT id, email FROM users ORDER BY email');
        return $st->fetchAll() ?: [];
    } catch (Throwable $e) {
        // try app DB as fallback
        $pdo = get_pdo();
        $st = $pdo->query('SELECT id, email FROM users ORDER BY email');
        return $st->fetchAll() ?: [];
    }
}

function notes_get_share_user_ids(int $noteId): array {
    $pdo = get_pdo();
    $col = notes__shares_column($pdo);
    if (!$col) return [];
    $st = $pdo->prepare("SELECT $col AS user_id FROM notes_shares WHERE note_id = ?");
    $st->execute([$noteId]);
    return array_map('intval', array_column($st->fetchAll() ?: [], 'user_id'));
}

function notes_update_shares(int $noteId, array $userIds): void {
    $pdo = get_pdo();
    $col = notes__shares_column($pdo);
    if (!$col) {
        $col = notes__ensure_shares_schema($pdo);
    }
    if (!$col) {
        throw new RuntimeException('notes_shares table/column not present.');
    }
    if ($col === 'user_id') {
        $userIds = array_values(array_unique(array_filter(array_map('intval', $userIds))));
    } else {
        $userIds = array_values(array_unique(array_filter(array_map('strval', $userIds), fn($v) => $v !== '')));
    }
    $pdo->beginTransaction();
    try {
        $pdo->prepare('DELETE FROM notes_shares WHERE note_id = ?')->execute([$noteId]);
        if ($userIds) {
            $sql = "INSERT INTO notes_shares (note_id, $col) VALUES (?, ?)";
            $ins = $pdo->prepare($sql);
            foreach ($userIds as $uid) {
                $ins->execute([$noteId, $uid]);
            }
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function notes_apply_shares(int $noteId, array $userIds, array $note, bool $notify = true): array {
    $ownerId = (int)($note['user_id'] ?? 0);
    $selected = array_values(array_unique(array_filter(array_map('intval', $userIds))));
    if ($ownerId > 0) {
        $selected = array_values(array_diff($selected, [$ownerId]));
    }

    $before = array_map('intval', notes_get_share_user_ids($noteId) ?: []);

    notes_update_shares($noteId, $selected);

    $after  = array_map('intval', notes_get_share_user_ids($noteId) ?: []);
    $added  = array_values(array_diff($after, $before));
    $removed= array_values(array_diff($before, $after));

    if ($notify && $added) {
        try {
            $me   = current_user();
            $who  = trim((string)($me['email'] ?? 'Someone')) ?: 'Someone';
            $title= trim((string)($note['title'] ?? 'Untitled')) ?: 'Untitled';
            $date = (string)($note['note_date'] ?? '');
            $titleMsg = 'A note was shared with you';
            $bodyMsg  = "“{$title}” {$date} — shared by {$who}";
            $link     = '/notes/view.php?id=' . (int)$noteId;
            $payload  = ['note_id' => (int)$noteId, 'by' => $who];

            if (function_exists('notify_users')) {
                notify_users($added, 'note.shared', $titleMsg, $bodyMsg, $link, $payload);
            }
        } catch (Throwable $e) {
            error_log('notify_users failed: ' . $e->getMessage());
        }
    }

    try {
        log_event('note.share', 'note', (int)$noteId, ['added' => $added, 'removed' => $removed]);
    } catch (Throwable $e) {
        // logging optional; ignore
    }

    return [
        'before'  => $before,
        'after'   => $after,
        'added'   => $added,
        'removed' => $removed,
    ];
}
function notes_fetch_users_from(PDO $pdo, array $ids): array {
    if (!$ids) return [];
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    try {
        $st = $pdo->prepare("SELECT id, email FROM users WHERE id IN ($placeholders)");
        $st->execute($ids);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        return [];
    }
    $map = [];
    foreach ($rows as $row) {
        $uid = (int)($row['id'] ?? 0);
        if ($uid <= 0) continue;
        $label = trim((string)($row['email'] ?? ''));
        $map[$uid] = $label !== '' ? $label : ('User #'.$uid);
    }
    return $map;
}

function notes_fetch_users_map(array $ids): array {
    $ids = array_values(array_unique(array_filter(array_map('intval', $ids))));
    if (!$ids) return [];

    $map = [];
    $remaining = $ids;

    try {
        $core = get_pdo('core');
        $coreMap = notes_fetch_users_from($core, $remaining);
        $map = $coreMap;
        if ($coreMap) {
            $remaining = array_values(array_diff($remaining, array_keys($coreMap)));
        }
    } catch (Throwable $e) {
        // ignore; fall back to apps DB
    }

    if ($remaining) {
        try {
            $appsMap = notes_fetch_users_from(get_pdo(), $remaining);
            $map = $map + $appsMap;
            if ($appsMap) {
                $remaining = array_values(array_diff($remaining, array_keys($appsMap)));
            }
        } catch (Throwable $e) {
            // ignore
        }
    }

    if ($remaining) {
        foreach ($remaining as $id) {
            $map[$id] = 'User #'.$id;
        }
    }

    return $map;
}

function notes_user_label(int $userId): string {
    static $cache = null;
    if ($cache === null) {
        $cache = [];
        $users = notes_all_users();
        foreach ($users as $user) {
            $uid = (int)($user['id'] ?? 0);
            if ($uid <= 0) {
                continue;
            }
            $label = trim((string)($user['email'] ?? ''));
            $cache[$uid] = $label !== '' ? $label : ('User #' . $uid);
        }
    }
    if (isset($cache[$userId])) {
        return $cache[$userId];
    }
    return 'User #' . $userId;
}

function notes_get_share_details(int $noteId): array {
    $ids = notes_get_share_user_ids($noteId);
    if (!$ids) return [];
    $labels = notes_fetch_users_map($ids);
    $out = [];
    foreach ($ids as $id) {
        $out[] = [
            'id'    => $id,
            'label' => $labels[$id] ?? ('User #'.$id),
        ];
    }
    return $out;
}

function notes_can_view(array $note): bool {
    $role = current_user_role_key();
    if ($role === 'root' || $role === 'admin') return true;

    $meId = (int)(current_user()['id'] ?? 0);
    if ($meId <= 0) return false;

    // Owner?
    if ((int)($note['user_id'] ?? 0) === $meId) return true;

    // Shared with me?
    if (!isset($note['id'])) return false;
    try {
        $pdo = get_pdo();
        $col = notes__shares_column($pdo);
        if (!$col) {
            return false;
        }
        $value = $col === 'user_id' ? $meId : (string)$meId;
        $st = $pdo->prepare("SELECT 1 FROM notes_shares WHERE note_id = ? AND $col = ? LIMIT 1");
        $st->execute([(int)$note['id'], $value]);
        return (bool)$st->fetchColumn();
    } catch (Throwable $e) {
        return false;
    }
}


function notes_can_edit(array $note): bool {
    if (!can('edit')) return false;
    $role = current_user_role_key();
    if ($role === 'root' || $role === 'admin') return true;
    $meId = (int)(current_user()['id'] ?? 0);
    return (int)($note['user_id'] ?? 0) === $meId;
}

function notes_can_share(array $note): bool {
    $role = current_user_role_key();
    if (in_array($role, ['root','admin'], true)) return true;
    $meId = (int)(current_user()['id'] ?? 0);
    return (int)($note['user_id'] ?? 0) === $meId;
}

/* ---------- comments ---------- */

function notes__ensure_comment_table(PDO $pdo): void {
    if (notes__table_exists($pdo, 'note_comments')) {
        return;
    }

    $attempts = [
        <<<SQL
CREATE TABLE IF NOT EXISTS note_comments (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  note_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  parent_id BIGINT UNSIGNED NULL,
  body LONGTEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_note_comments_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
  CONSTRAINT fk_note_comments_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_note_comments_parent FOREIGN KEY (parent_id) REFERENCES note_comments(id) ON DELETE CASCADE,
  INDEX idx_note_created (note_id, created_at),
  INDEX idx_note_parent (note_id, parent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL,
        <<<SQL
CREATE TABLE IF NOT EXISTS note_comments (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  note_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  parent_id BIGINT UNSIGNED NULL,
  body LONGTEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_note_created (note_id, created_at),
  INDEX idx_note_parent (note_id, parent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL,
    ];

    foreach ($attempts as $idx => $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            error_log('notes: unable to ensure note_comments table (attempt ' . ($idx + 1) . '): ' . $e->getMessage());
        }

        if (notes__table_exists($pdo, 'note_comments')) {
            return;
        }
    }
}

function notes_comments_table_exists(?PDO $pdo = null): bool {
    $pdo = $pdo ?: get_pdo();
    notes__ensure_comment_table($pdo);
    return notes__table_exists($pdo, 'note_comments');
}

function notes_comment_fetch(int $commentId): ?array {
    $pdo = get_pdo();
    if (!notes_comments_table_exists($pdo)) return null;
    $st = $pdo->prepare('SELECT * FROM note_comments WHERE id = ?');
    $st->execute([$commentId]);
    $row = $st->fetch();
    return $row ?: null;
}

function notes_comment_insert(int $noteId, int $userId, string $body, ?int $parentId = null): int {
    $pdo = get_pdo();
    if (!notes_comments_table_exists($pdo)) {
        throw new RuntimeException('Comments table not available.');
    }

    $parentId = $parentId ? (int)$parentId : null;
    if ($parentId) {
        $parent = notes_comment_fetch($parentId);
        if (!$parent || (int)$parent['note_id'] !== $noteId) {
            throw new RuntimeException('Invalid parent comment.');
        }
    }

    $st = $pdo->prepare(
        'INSERT INTO note_comments (note_id, user_id, parent_id, body)
         VALUES (:note_id, :user_id, :parent_id, :body)'
    );
    $st->execute([
        ':note_id'  => $noteId,
        ':user_id'  => $userId,
        ':parent_id'=> $parentId,
        ':body'     => $body,
    ]);

    return (int)$pdo->lastInsertId();
}

function notes_comment_delete(int $commentId): void {
    $pdo = get_pdo();
    if (!notes_comments_table_exists($pdo)) return;
    $st = $pdo->prepare('DELETE FROM note_comments WHERE id = ?');
    $st->execute([$commentId]);
}

function notes_comment_can_delete(array $comment, array $note): bool {
    $role = current_user_role_key();
    if (in_array($role, ['root','admin'], true)) return true;
    $meId = (int)(current_user()['id'] ?? 0);
    if ($meId <= 0) return false;
    if ((int)$comment['user_id'] === $meId) return true;
    return (int)($note['user_id'] ?? 0) === $meId;
}

function notes_fetch_comments(int $noteId): array {
    $pdo = get_pdo();
    if (!notes_comments_table_exists($pdo)) return [];

    $st = $pdo->prepare('SELECT * FROM note_comments WHERE note_id = ? ORDER BY created_at ASC, id ASC');
    $st->execute([$noteId]);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
    if (!$rows) return [];

    $userIds = [];
    foreach ($rows as $row) {
        $userIds[] = (int)($row['user_id'] ?? 0);
    }
    $userMap = notes_fetch_users_map($userIds);

    foreach ($rows as &$row) {
        $uid = (int)($row['user_id'] ?? 0);
        $row['author_label'] = $userMap[$uid] ?? ('User #'.$uid);
    }
    unset($row);

    return $rows;
}

function notes_fetch_comment_threads(int $noteId): array {
    $rows = notes_fetch_comments($noteId);
    if (!$rows) return [];

    $byId = [];
    foreach ($rows as $row) {
        $row['children'] = [];
        $byId[(int)$row['id']] = $row;
    }

    $tree = [];
    foreach ($byId as $id => &$row) {
        $parentId = (int)($row['parent_id'] ?? 0);
        if ($parentId && isset($byId[$parentId])) {
            $byId[$parentId]['children'][] = &$row;
        } else {
            $tree[] = &$row;
        }
    }
    unset($row);

    return $tree;
}

function notes_comment_count(int $noteId): int {
    $pdo = get_pdo();
    if (!notes_comments_table_exists($pdo)) return 0;
    $st = $pdo->prepare('SELECT COUNT(*) FROM note_comments WHERE note_id = ?');
    $st->execute([$noteId]);
    return (int)$st->fetchColumn();
}