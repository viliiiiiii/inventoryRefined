<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers.php';
require_login();
require_once __DIR__ . '/../includes/notifications.php';

/* ---------- Data source detection ---------- */
function profile_resolve_user_store(): array {
    static $store = null;
    if ($store !== null) {
        return $store;
    }

    // Force "core" as the authoritative users DB.
    // Assumes get_pdo('core') is configured for your core_db database.
    $pdo = get_pdo('core');

    // Sanity check: make sure core.users looks like we expect
    $cols = [];
    try {
        $cols = $pdo->query('SHOW COLUMNS FROM `users`')->fetchAll(PDO::FETCH_COLUMN) ?: [];
        $cols = array_map('strval', $cols);
    } catch (Throwable $e) {
        throw new RuntimeException('Could not read columns from core.users');
    }

    if (!in_array('pass_hash', $cols, true)) {
        throw new RuntimeException('core.users is missing expected column pass_hash');
    }

    // Cache the chosen store
    $store = [
        'db_key'          => 'core',
        'schema'          => 'core',
        'password_column' => 'pass_hash',
        'role_column'     => 'role_id',
        'pdo'             => $pdo,
        'columns'         => $cols,
    ];
    return $store;
}


function pick_users_pdo(): PDO
{
    $store = profile_resolve_user_store();
    return $store['pdo'];
}

function profile_store_schema(): string
{
    $store = profile_resolve_user_store();
    return (string)$store['schema'];
}

function profile_password_column(): string
{
    $store = profile_resolve_user_store();
    return (string)$store['password_column'];
}

function fetch_user(PDO $pdo, int $id): ?array
{
    $store = profile_resolve_user_store();
    if ($store['schema'] === 'core') {
        $sql = 'SELECT u.id, u.email, u.pass_hash AS password_hash, u.role_id, u.created_at, '
             . 'u.suspended_at, u.suspended_by, u.sector_id, '
             . 'r.label AS role_label, r.key_slug AS role_key, s.name AS sector_name '
             . 'FROM users u '
             . 'LEFT JOIN roles r   ON r.id = u.role_id '
             . 'LEFT JOIN sectors s ON s.id = u.sector_id '
             . 'WHERE u.id = ?';
    } else {
        $sql = 'SELECT id, email, password_hash, role, created_at FROM users WHERE id = ?';
    }

    $st = $pdo->prepare($sql);
    $st->execute([$id]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return null;
    }

    if ($store['schema'] === 'core') {
        if (isset($row['role_label']) && $row['role_label'] !== null) {
            $row['role'] = $row['role_label'];
        } elseif (isset($row['role_key'])) {
            $row['role'] = ucfirst(str_replace('_', ' ', (string)$row['role_key']));
        }
    } else {
        $role = (string)($row['role'] ?? '');
        $row['role_label'] = $role === '' ? '' : ucfirst(str_replace('_', ' ', $role));
        $row['role_key']   = $role;
    }

    return $row;
}

function profile_sync_shadow_email(int $userId, string $email, string $sourceSchema): void
{
    if ($sourceSchema !== 'core') {
        try {
            $core = get_pdo('core');
            $stmt = $core->prepare('UPDATE `users` SET `email` = ? WHERE `id` = ?');
            $stmt->execute([$email, $userId]);
        } catch (Throwable $e) {
        }
    }
    if ($sourceSchema !== 'punchlist') {
        try {
            $apps = get_pdo();
            $stmt = $apps->prepare('UPDATE `users` SET `email` = ? WHERE `id` = ?');
            $stmt->execute([$email, $userId]);
        } catch (Throwable $e) {
        }
    }
}

function profile_sync_shadow_password(int $userId, string $hash, string $sourceSchema): void
{
    if ($sourceSchema !== 'core') {
        try {
            $core = get_pdo('core');
            $stmt = $core->prepare('UPDATE `users` SET `pass_hash` = ? WHERE `id` = ?');
            $stmt->execute([$hash, $userId]);
        } catch (Throwable $e) {
        }
    }
    if ($sourceSchema !== 'punchlist') {
        try {
            $apps = get_pdo();
            $stmt = $apps->prepare('UPDATE `users` SET `password_hash` = ? WHERE `id` = ?');
            $stmt->execute([$hash, $userId]);
        } catch (Throwable $e) {
        }
    }
}

function profile_avatar_initial(?string $email): string
{
    $email = trim((string)$email);
    if ($email === '') {
        return 'U';
    }
    $first = strtoupper($email[0]);
    if (!preg_match('/[A-Z0-9]/', $first)) {
        $first = '#';
    }
    return $first;
}

function profile_format_datetime(?string $timestamp): string
{
    if (!$timestamp) {
        return '';
    }
    try {
        $dt = new DateTimeImmutable((string)$timestamp);
        return $dt->format('M j, Y · H:i');
    } catch (Throwable $e) {
        return (string)$timestamp;
    }
}

function profile_relative_time(?string $timestamp): string
{
    if (!$timestamp) {
        return '';
    }
    try {
        $dt  = new DateTimeImmutable((string)$timestamp);
        $now = new DateTimeImmutable('now');
    } catch (Throwable $e) {
        return '';
    }

    $diff = $now->getTimestamp() - $dt->getTimestamp();
    $suffix = $diff >= 0 ? 'ago' : 'from now';
    $diff = abs($diff);

    $units = [
        31536000 => 'year',
        2592000  => 'month',
        604800   => 'week',
        86400    => 'day',
        3600     => 'hour',
        60       => 'minute',
        1        => 'second',
    ];

    foreach ($units as $secs => $label) {
        if ($diff >= $secs) {
            $value = (int)floor($diff / $secs);
            if ($value > 1) {
                $label .= 's';
            }
            return $value . ' ' . $label . ' ' . $suffix;
        }
    }

    return 'just now';
}

function profile_format_ip($raw): ?string
{
    if ($raw === null || $raw === '') {
        return null;
    }
    if (function_exists('inet_ntop')) {
        $ip = @inet_ntop((string)$raw);
        if ($ip !== false) {
            return $ip;
        }
    }
    if (is_string($raw) && preg_match('/^[0-9.]+$/', $raw)) {
        return $raw;
    }
    return null;
}

function profile_summarize_user_agent(?string $ua): string
{
    $ua = trim((string)$ua);
    if ($ua === '') {
        return 'Unknown device';
    }

    $uaLower = strtolower($ua);
    $browser = 'Browser';
    if (str_contains($uaLower, 'edg/')) {
        $browser = 'Edge';
    } elseif (str_contains($uaLower, 'chrome')) {
        $browser = 'Chrome';
    } elseif (str_contains($uaLower, 'firefox')) {
        $browser = 'Firefox';
    } elseif (str_contains($uaLower, 'safari')) {
        $browser = 'Safari';
    } elseif (str_contains($uaLower, 'opera') || str_contains($uaLower, 'opr/')) {
        $browser = 'Opera';
    }

    $os = '';
    if (str_contains($uaLower, 'iphone') || str_contains($uaLower, 'ipad')) {
        $os = 'iOS';
    } elseif (str_contains($uaLower, 'android')) {
        $os = 'Android';
    } elseif (str_contains($uaLower, 'windows')) {
        $os = 'Windows';
    } elseif (str_contains($uaLower, 'mac os')) {
        $os = 'macOS';
    } elseif (str_contains($uaLower, 'linux')) {
        $os = 'Linux';
    }

    $parts = array_filter([$browser, $os]);
    return implode(' · ', $parts) ?: $browser;
}

function fetch_recent_security_events(int $userId, int $limit = 6): array
{
    try {
        $pdo = get_pdo('core');
    } catch (Throwable $e) {
        return [];
    }

    try {
        $sql = 'SELECT ts, action, meta, ip, ua FROM activity_log '
             . 'WHERE user_id = :uid AND action IN ("login","logout","user.password_change","user.email_change") '
             . 'ORDER BY ts DESC LIMIT :lim';
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return [];
    }

    $events = [];
    foreach ($rows as $row) {
        $events[] = profile_describe_security_event($row);
    }
    return $events;
}

function profile_describe_security_event(array $row): array
{
    $action = (string)($row['action'] ?? '');
    $ts     = $row['ts'] ?? null;
    $title  = match ($action) {
        'login'               => 'Signed in',
        'logout'              => 'Signed out',
        'user.password_change'=> 'Password updated',
        'user.email_change'   => 'Email updated',
        default               => ucfirst(str_replace('_', ' ', $action)),
    };

    $ip    = profile_format_ip($row['ip'] ?? null);
    $agent = profile_summarize_user_agent($row['ua'] ?? '');
    $metaParts = [];
    if ($ip) {
        $metaParts[] = $ip;
    }
    if ($agent) {
        $metaParts[] = $agent;
    }

    $details = '';
    if (!empty($row['meta'])) {
        $decoded = json_decode((string)$row['meta'], true);
        if (is_array($decoded)) {
            if (isset($decoded['old'], $decoded['new'])) {
                $details = 'Changed ' . (string)$decoded['old'] . ' → ' . (string)$decoded['new'];
            } elseif (isset($decoded['email'])) {
                $details = (string)$decoded['email'];
            }
        }
    }

    return [
        'title'       => $title,
        'meta'        => implode(' • ', $metaParts),
        'details'     => $details,
        'ts'          => $ts,
        'relative'    => profile_relative_time($ts),
        'formatted'   => profile_format_datetime($ts),
    ];
}

function profile_notification_types(): array
{
    return [
        'task.assigned'   => [
            'label'       => 'Task assignments',
            'description' => 'Alerts when someone assigns a task to you or your team.',
        ],
        'task.updated'    => [
            'label'       => 'Task progress',
            'description' => 'Heads-up when priority, due dates, or status change on tasks you follow.',
        ],
        'note.activity'   => [
            'label'       => 'Note collaboration',
            'description' => 'Comments, mentions, and edits on notes you created or follow.',
        ],
        'system.broadcast'=> [
            'label'       => 'System announcements',
            'description' => 'Release notes and scheduled maintenance updates from the team.',
        ],
        'security.login_alert' => [
            'label'       => 'Sign-in alerts',
            'description' => 'Ping me when a new device signs in with my account.',
        ],
        'digest.weekly' => [
            'label'       => 'Weekly digest',
            'description' => 'Friday recap email with overdue tasks and unread notes.',
        ],
    ];
}

function profile_fetch_notification_devices(int $localUserId): array
{
    try {
        $pdo = notif_pdo();
        $stmt = $pdo->prepare('SELECT id, kind, user_agent, created_at, last_used_at '
                             . 'FROM notification_devices WHERE user_id = :u '
                             . 'ORDER BY COALESCE(last_used_at, created_at) DESC');
        $stmt->execute([':u' => $localUserId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        return [];
    }
}

function profile_membership_summary(?string $createdAt): array
{
    $summary = [
        'short' => '—',
        'long'  => 'Join date not available.',
    ];

    if (!$createdAt) {
        return $summary;
    }

    try {
        $start = new DateTimeImmutable($createdAt);
        $now   = new DateTimeImmutable('now');
    } catch (Throwable $e) {
        return $summary;
    }

    if ($start > $now) {
        $summary['short'] = 'Pending access';
        $summary['long']  = 'Account activates ' . $start->format('M j, Y');
        return $summary;
    }

    $diff   = $start->diff($now);
    $parts  = [];
    if ($diff->y > 0) {
        $parts[] = $diff->y . ' yr' . ($diff->y === 1 ? '' : 's');
    }
    if ($diff->m > 0 && count($parts) < 2) {
        $parts[] = $diff->m . ' mo' . ($diff->m === 1 ? '' : 's');
    }
    if ($diff->d > 0 && count($parts) < 2) {
        $parts[] = $diff->d . ' day' . ($diff->d === 1 ? '' : 's');
    }
    if (!$parts) {
        $parts[] = 'Today';
    }

    $summary['short'] = implode(' ', array_slice($parts, 0, 2));
    $summary['long']  = 'Joined ' . $start->format('M j, Y');
    return $summary;
}

function profile_notification_summary(array $notificationPrefs): array
{
    $channels = [
        'in-app' => 0,
        'email'  => 0,
        'push'   => 0,
    ];
    $snoozed = 0;

    foreach ($notificationPrefs as $pref) {
        if (!empty($pref['allow_web'])) {
            $channels['in-app']++;
        }
        if (!empty($pref['allow_email'])) {
            $channels['email']++;
        }
        if (!empty($pref['allow_push'])) {
            $channels['push']++;
        }
        if (!empty($pref['mute_until'])) {
            $snoozed++;
        }
    }

    return [
        'channels'        => $channels,
        'active_channels' => count(array_filter($channels)),
        'total_types'     => count($notificationPrefs),
        'snoozed'         => $snoozed,
    ];
}

function profile_notification_counts(int $localUserId): array
{
    try {
        $pdo = notif_pdo();
    } catch (Throwable $e) {
        return [];
    }

    try {
        $stmt = $pdo->prepare('SELECT
                SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) AS unread,
                COUNT(*) AS total,
                MAX(created_at) AS last_created,
                SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS recent
            FROM notifications
            WHERE user_id = :uid');
        $stmt->execute([':uid' => $localUserId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        return [];
    }

    $lastCreated = $row['last_created'] ?? null;
    return [
        'unread'                 => (int)($row['unread'] ?? 0),
        'recent'                 => (int)($row['recent'] ?? 0),
        'total'                  => (int)($row['total'] ?? 0),
        'last_created_at'        => $lastCreated,
        'last_created_formatted' => profile_format_datetime($lastCreated),
        'last_created_relative'  => profile_relative_time($lastCreated),
    ];
}

function profile_fetch_recent_notifications(int $localUserId, int $limit = 5): array
{
    try {
        $pdo = notif_pdo();
    } catch (Throwable $e) {
        return [];
    }

    try {
        $stmt = $pdo->prepare('SELECT id, title, body, url, is_read, created_at
            FROM notifications
            WHERE user_id = :uid
            ORDER BY created_at DESC
            LIMIT :lim');
        $stmt->bindValue(':uid', $localUserId, PDO::PARAM_INT);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        return [];
    }

    $out = [];
    foreach ($rows as $row) {
        $created = $row['created_at'] ?? null;
        $out[] = [
            'title'     => trim((string)($row['title'] ?? '')) ?: 'Notification',
            'body'      => trim((string)($row['body'] ?? '')),
            'url'       => $row['url'] ?? null,
            'is_read'   => !empty($row['is_read']),
            'created'   => $created,
            'relative'  => profile_relative_time($created),
            'formatted' => profile_format_datetime($created),
        ];
    }

    return $out;
}

function profile_fetch_sectors(PDO $pdo): array
{
    try {
        $stmt = $pdo->query('SELECT id, name FROM sectors ORDER BY name');
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        return [];
    }

    $sectors = [];
    foreach ($rows as $row) {
        if (!isset($row['id'])) {
            continue;
        }
        $sectors[(int)$row['id']] = (string)($row['name'] ?? '');
    }

    return $sectors;
}

function profile_security_highlight(array $securityEvents): ?array
{
    if (!$securityEvents) {
        return null;
    }

    $event = $securityEvents[0];
    $title = (string)($event['title'] ?? '');
    $details = (string)($event['details'] ?? '');
    $meta = (string)($event['meta'] ?? '');
    $tone = 'info';
    $titleLower = strtolower($title);
    if (str_contains($titleLower, 'password') || str_contains($titleLower, 'suspended')) {
        $tone = 'warn';
    }

    return [
        'title'       => $title,
        'description' => $details !== '' ? $details : $meta,
        'time'        => (string)($event['relative'] ?? ''),
        'timestamp'   => (string)($event['formatted'] ?? ''),
        'meta'        => $meta,
        'tone'        => $tone,
    ];
}

function profile_collect_insights(
    array $user,
    array $notificationPrefs,
    array $notificationDevices,
    array $securityEvents,
    array $notificationStats = []
): array
{
    $insights = [];

    $membership = profile_membership_summary($user['created_at'] ?? null);
    $insights[] = [
        'icon'    => '🗓️',
        'title'   => 'Membership length',
        'primary' => $membership['short'],
        'meta'    => $membership['long'],
    ];

    if ($notificationPrefs) {
        $summary = profile_notification_summary($notificationPrefs);
        $active  = $summary['active_channels'];
        $primary = $active === 0
            ? 'Muted'
            : $active . ' channel' . ($active === 1 ? '' : 's') . ' on';

        $metaParts = [];
        foreach ([
            'in-app' => 'In-app',
            'email'  => 'Email',
            'push'   => 'Push',
        ] as $key => $label) {
            if (($summary['channels'][$key] ?? 0) > 0) {
                $metaParts[] = $label;
            }
        }
        if ($summary['snoozed'] > 0) {
            $metaParts[] = $summary['snoozed'] . ' snoozed';
        }

        $insights[] = [
            'icon'    => '🔔',
            'title'   => 'Notification coverage',
            'primary' => $primary,
            'meta'    => $metaParts ? implode(' • ', $metaParts) : 'No channels enabled.',
        ];
    }

    if ($notificationStats) {
        $unread = (int)($notificationStats['unread'] ?? 0);
        $primary = $unread === 0 ? 'Inbox clear' : $unread . ' unread';
        $metaBits = [];
        if (!empty($notificationStats['last_created_relative'])) {
            $metaBits[] = 'Last alert ' . $notificationStats['last_created_relative'];
        }
        $recent = (int)($notificationStats['recent'] ?? 0);
        if ($recent > 0) {
            $metaBits[] = $recent . ' received this week';
        } elseif (!empty($notificationStats['total'])) {
            $metaBits[] = (int)$notificationStats['total'] . ' received overall';
        }
        $insights[] = [
            'icon'    => '📬',
            'title'   => 'Notification inbox',
            'primary' => $primary,
            'meta'    => $metaBits ? implode(' • ', $metaBits) : 'We will surface new alerts here.',
        ];
    }

    $deviceCount = count($notificationDevices);
    $deviceKinds = [];
    foreach ($notificationDevices as $device) {
        $kind = match ((string)($device['kind'] ?? '')) {
            'fcm'  => 'Android',
            'apns' => 'iOS',
            default => 'Web',
        };
        if (!isset($deviceKinds[$kind])) {
            $deviceKinds[$kind] = 0;
        }
        $deviceKinds[$kind]++;
    }

    $deviceMeta = [];
    foreach ($deviceKinds as $label => $count) {
        $deviceMeta[] = $count . ' ' . $label . ($count === 1 ? '' : 's');
    }

    $insights[] = [
        'icon'    => '💡',
        'title'   => 'Trusted devices',
        'primary' => $deviceCount . ' connected',
        'meta'    => $deviceMeta ? implode(' • ', $deviceMeta) : 'Add a browser or mobile device to receive push alerts.',
    ];

    $highlight = profile_security_highlight($securityEvents);
    if ($highlight) {
        $metaBits = array_filter([
            $highlight['time'] ?? '',
            $highlight['timestamp'] ?? '',
        ]);
        $detailParts = [];
        if (!empty($highlight['description'])) {
            $detailParts[] = $highlight['description'];
        }
        foreach ($metaBits as $bit) {
            $detailParts[] = $bit;
        }

        $insights[] = [
            'icon'    => '🛡️',
            'title'   => 'Latest security event',
            'primary' => $highlight['title'],
            'meta'    => implode(' • ', $detailParts),
        ];
    }

    return $insights;
}

function profile_quick_actions(): array
{
    return [
        [
            'icon'        => '🔔',
            'label'       => 'Notifications hub',
            'description' => 'Review unread alerts and digests.',
            'href'        => '/notifications/index.php',
        ],
        [
            'icon'        => '✅',
            'label'       => 'My tasks',
            'description' => 'Jump back to tasks assigned to you.',
            'href'        => '/tasks.php',
        ],
        [
            'icon'        => '📝',
            'label'       => 'Notes workspace',
            'description' => 'Catch up on collaboration threads.',
            'href'        => '/notes/index.php',
        ],
        [
            'icon'        => '⬇️',
            'label'       => 'Data exports',
            'description' => 'Download XLSX or PDF reports for sharing.',
            'href'        => '/export_tasks_excel.php',
        ],
        [
            'icon'        => '🛡️',
            'label'       => 'Security log',
            'description' => 'Open the detailed audit and login history.',
            'href'        => '/notifications/debug.php',
        ],
    ];
}

function profile_mute_field_state(?string $muteUntil): array
{
    $state = [
        'select'      => 'off',
        'description' => '',
        'until'       => $muteUntil,
    ];

    if (!$muteUntil) {
        return $state;
    }

    try {
        $until = new DateTimeImmutable($muteUntil);
        $now   = new DateTimeImmutable('now');
    } catch (Throwable $e) {
        return $state;
    }

    if ($until <= $now) {
        return $state;
    }

    $diff = $until->getTimestamp() - $now->getTimestamp();
    $map  = [
        '1h' => 3600,
        '4h' => 14400,
        '1d' => 86400,
        '3d' => 259200,
        '7d' => 604800,
    ];

    foreach ($map as $key => $seconds) {
        if (abs($diff - $seconds) <= 300) {
            $state['select']      = $key;
            $state['description'] = 'Snoozed until ' . profile_format_datetime($muteUntil);
            return $state;
        }
    }

    if ($diff >= 86400 * 90) {
        $state['select']      = 'forever';
        $state['description'] = 'Muted until you turn it back on';
        return $state;
    }

    $state['select']      = 'keep';
    $state['description'] = 'Snoozed until ' . profile_format_datetime($muteUntil);
    return $state;
}

$errors = [];
$me     = current_user();
$userId = (int)($me['id'] ?? 0);

try {
    $pdo  = pick_users_pdo();
    $user = fetch_user($pdo, $userId);
    if (!$user) {
        http_response_code(404);
        exit('User not found.');
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo '<h1>Profile error</h1><p>Could not access the users table. '
       . 'Make sure it exists on the expected database connection.</p>';
    exit;
}

$storeSchema = profile_store_schema();
$notificationTypes = profile_notification_types();
$notificationPrefs = [];
$notificationUserId = null;
if (function_exists('notif_resolve_local_user_id')) {
    try {
        $notificationUserId = notif_resolve_local_user_id($userId);
        if ($notificationUserId) {
            foreach ($notificationTypes as $type => $meta) {
                try {
                    $pref = notif_get_type_pref($notificationUserId, $type);
                } catch (Throwable $e) {
                    $pref = ['allow_web' => 1, 'allow_email' => 0, 'allow_push' => 0, 'mute_until' => null];
                }
                $notificationPrefs[$type] = [
                    'allow_web'   => !empty($pref['allow_web']),
                    'allow_email' => !empty($pref['allow_email']),
                    'allow_push'  => !empty($pref['allow_push']),
                    'mute_until'  => $pref['mute_until'] ?? null,
                ];
            }
        }
    } catch (Throwable $e) {
        $notificationUserId = null;
    }
}
$notificationsAvailable = $notificationUserId !== null;
$notificationDevices = ($notificationsAvailable) ? profile_fetch_notification_devices($notificationUserId) : [];
$sectorOptions = profile_fetch_sectors($pdo);

/* ---------- POST handlers ---------- */
if (is_post()) {
    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'change_email') {
            $newEmail = trim((string)($_POST['email'] ?? ''));
            if ($newEmail === '') {
                $errors[] = 'Email is required.';
            } elseif (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Please enter a valid email address.';
            } else {
                try {
                    $st = $pdo->prepare('SELECT 1 FROM `users` WHERE `email` = ? AND `id` <> ? LIMIT 1');
                    $st->execute([$newEmail, $userId]);
                    if ($st->fetchColumn()) {
                        $errors[] = 'That email is already in use.';
                    }
                } catch (Throwable $e) {
                    $errors[] = 'Could not validate email uniqueness.';
                }
            }

            if (!$errors) {
                try {
                    $oldEmail = (string)$user['email'];
                    $columnEmail = 'email';
                    $stmt = $pdo->prepare('UPDATE `users` SET `' . $columnEmail . '` = ? WHERE `id` = ?');
                    $stmt->execute([$newEmail, $userId]);

                    profile_sync_shadow_email($userId, $newEmail, $storeSchema);

                    if (function_exists('log_event')) {
                        log_event('user.email_change', 'user', $userId, ['old' => $oldEmail, 'new' => $newEmail]);
                    }
                    if (isset($_SESSION['user']) && is_array($_SESSION['user'])) {
                        $_SESSION['user']['email'] = $newEmail;
                    }
                    redirect_with_message('/account/profile.php', 'Email updated.', 'success');
                } catch (Throwable $e) {
                    $errors[] = 'Failed to update email.';
                }
            }
        }

        if ($action === 'update_sector') {
            $sectorValue = $_POST['sector_id'] ?? '';
            $sectorId = ($sectorValue === '' || $sectorValue === null) ? null : (int)$sectorValue;

            if ($sectorId !== null && !array_key_exists($sectorId, $sectorOptions)) {
                $errors[] = 'Please choose a valid team/sector.';
            }

            if (!$errors) {
                try {
                    if ($sectorId === null) {
                        $stmt = $pdo->prepare('UPDATE `users` SET `sector_id` = NULL WHERE `id` = ?');
                        $stmt->execute([$userId]);
                    } else {
                        $stmt = $pdo->prepare('UPDATE `users` SET `sector_id` = ? WHERE `id` = ?');
                        $stmt->execute([$sectorId, $userId]);
                    }

                    if (isset($_SESSION['user']) && is_array($_SESSION['user'])) {
                        $_SESSION['user']['sector_id'] = $sectorId;
                    }

                    redirect_with_message('/account/profile.php', 'Primary team updated.', 'success');
                } catch (Throwable $e) {
                    $errors[] = 'Could not update your team.';
                }
            }
        }

        if ($action === 'change_password') {
            $current = (string)($_POST['current_password'] ?? '');
            $new     = (string)($_POST['new_password'] ?? '');
            $confirm = (string)($_POST['confirm_password'] ?? '');

            if ($current === '' || $new === '' || $confirm === '') {
                $errors[] = 'All password fields are required.';
            } elseif (!password_verify($current, (string)$user['password_hash'])) {
                $errors[] = 'Your current password is incorrect.';
            } elseif (strlen($new) < 8) {
                $errors[] = 'New password must be at least 8 characters.';
            } elseif ($new !== $confirm) {
                $errors[] = 'New password and confirmation do not match.';
            }

            if (!$errors) {
                try {
                    $hash = password_hash($new, PASSWORD_DEFAULT);
                    $column = profile_password_column();
                    $stmt = $pdo->prepare('UPDATE `users` SET `' . $column . '` = ? WHERE `id` = ?');
                    $stmt->execute([$hash, $userId]);

                    profile_sync_shadow_password($userId, $hash, $storeSchema);

                    if (function_exists('log_event')) {
                        log_event('user.password_change', 'user', $userId);
                    }

                    redirect_with_message('/account/profile.php', 'Password updated.', 'success');
                } catch (Throwable $e) {
                    $errors[] = 'Failed to update password.';
                }
            }
        }

        if ($action === 'update_prefs') {
            if (!$notificationsAvailable) {
                $errors[] = 'Notification preferences are not available right now.';
            } else {
                $prefsInput = $_POST['prefs'] ?? [];
                $now = new DateTimeImmutable('now');
                foreach ($notificationTypes as $type => $meta) {
                    $incoming = $prefsInput[$type] ?? [];
                    $update = [
                        'allow_web'   => !empty($incoming['allow_web']) ? 1 : 0,
                        'allow_email' => !empty($incoming['allow_email']) ? 1 : 0,
                        'allow_push'  => !empty($incoming['allow_push']) ? 1 : 0,
                    ];

                    $choice        = (string)($incoming['mute_for'] ?? 'off');
                    $existingMute  = $notificationPrefs[$type]['mute_until'] ?? null;
                    $muteUntil     = null;

                    switch ($choice) {
                        case 'keep':
                            $muteUntil = $existingMute;
                            break;
                        case 'off':
                            $muteUntil = null;
                            break;
                        case '1h':
                            $muteUntil = $now->modify('+1 hour')->format('Y-m-d H:i:s');
                            break;
                        case '4h':
                            $muteUntil = $now->modify('+4 hours')->format('Y-m-d H:i:s');
                            break;
                        case '1d':
                            $muteUntil = $now->modify('+1 day')->format('Y-m-d H:i:s');
                            break;
                        case '3d':
                            $muteUntil = $now->modify('+3 days')->format('Y-m-d H:i:s');
                            break;
                        case '7d':
                            $muteUntil = $now->modify('+7 days')->format('Y-m-d H:i:s');
                            break;
                        case 'forever':
                            $muteUntil = $now->modify('+5 years')->format('Y-m-d H:i:s');
                            break;
                        default:
                            $muteUntil = null;
                            break;
                    }

                    if ($choice === 'keep' && !$existingMute) {
                        $muteUntil = null;
                    }

                    $update['mute_until'] = $muteUntil;

                    try {
                        notif_set_type_pref($notificationUserId, $type, $update);
                    } catch (Throwable $e) {
                        $errors[] = 'Failed to save notification preferences for ' . $meta['label'] . '.';
                        break;
                    }
                }

                if (!$errors) {
                    redirect_with_message('/account/profile.php', 'Notification preferences updated.', 'success');
                }
            }
        }

        if ($action === 'revoke_device') {
            if (!$notificationsAvailable) {
                $errors[] = 'Notifications are not available right now.';
            } else {
                $deviceId = (int)($_POST['device_id'] ?? 0);
                if ($deviceId <= 0) {
                    $errors[] = 'Device not found.';
                } else {
                    try {
                        $pdoNotif = notif_pdo();
                        $stmt = $pdoNotif->prepare('DELETE FROM notification_devices WHERE id = :id AND user_id = :uid');
                        $stmt->execute([':id' => $deviceId, ':uid' => $notificationUserId]);
                        if ($stmt->rowCount() > 0) {
                            redirect_with_message('/account/profile.php', 'Device disconnected.', 'success');
                        } else {
                            $errors[] = 'Device not found or already removed.';
                        }
                    } catch (Throwable $e) {
                        $errors[] = 'Could not remove the device.';
                    }
                }
            }
        }
    }

    try {
        $user = fetch_user($pdo, $userId) ?? $user;
    } catch (Throwable $e) {
    }

    if ($notificationsAvailable) {
        $notificationPrefs = [];
        foreach ($notificationTypes as $type => $meta) {
            try {
                $pref = notif_get_type_pref($notificationUserId, $type);
            } catch (Throwable $e) {
                $pref = ['allow_web' => 1, 'allow_email' => 0, 'allow_push' => 0, 'mute_until' => null];
            }
            $notificationPrefs[$type] = [
                'allow_web'   => !empty($pref['allow_web']),
                'allow_email' => !empty($pref['allow_email']),
                'allow_push'  => !empty($pref['allow_push']),
                'mute_until'  => $pref['mute_until'] ?? null,
            ];
        }
        $notificationDevices = profile_fetch_notification_devices($notificationUserId);
    }
}

/* ---------- Derived view data ---------- */
$notificationStats = ($notificationsAvailable && $notificationUserId)
    ? profile_notification_counts($notificationUserId)
    : [];
$recentNotifications = ($notificationsAvailable && $notificationUserId)
    ? profile_fetch_recent_notifications($notificationUserId, 6)
    : [];
$statusLabel = 'Active';
$statusBadgeClass = 'badge -success';
if (!empty($user['suspended_at'])) {
    $statusLabel = 'Suspended';
    $statusBadgeClass = 'badge -danger';
}
$roleLabel = (string)($user['role'] ?? $user['role_label'] ?? '');
if ($roleLabel === '' && !empty($user['role_key'])) {
    $roleLabel = ucfirst(str_replace('_', ' ', (string)$user['role_key']));
}
$sectorLabel = (string)($user['sector_name'] ?? '');
$securityEvents = fetch_recent_security_events($userId, 6);
$membershipSummary = profile_membership_summary($user['created_at'] ?? null);
$securityHighlight = profile_security_highlight($securityEvents);
$insightCards = profile_collect_insights($user, $notificationPrefs, $notificationDevices, $securityEvents, $notificationStats);
$quickActions = profile_quick_actions();
$notificationSummary = profile_notification_summary($notificationPrefs);
$latestSecurityEvent = $securityEvents[0] ?? null;
$lastActiveRelative = (string)($latestSecurityEvent['relative'] ?? '');
$lastActiveFull = (string)($latestSecurityEvent['formatted'] ?? '');
$dataExportLinks = [
    [
        'label' => 'Export task workbook',
        'description' => 'Download an Excel file of every task you can view.',
        'href' => '/export_tasks_excel.php',
    ],
    [
        'label' => 'Building PDF rollup',
        'description' => 'Generate a printable PDF summary for your buildings.',
        'href' => '/export_building_pdf.php',
    ],
    [
        'label' => 'Room photo archive',
        'description' => 'Review recent room photos shared with the team.',
        'href' => '/public_room_photos.php',
    ],
];

$title = 'My Profile';
include __DIR__ . '/../includes/header.php';
?>
<div class="profile-page">
  <?php if ($errors): ?>
    <div class="flash flash-error"><?php echo sanitize(implode(' ', $errors)); ?></div>
  <?php endif; ?>

  <div class="profile-layout">
    <aside class="profile-sidebar">
      <section class="profile-card profile-card--identity card">
        <div class="profile-identity">
          <span class="profile-avatar"><?php echo sanitize(profile_avatar_initial($user['email'] ?? '')); ?></span>
          <div class="profile-identity__text">
            <p class="profile-identity__eyebrow">Account</p>
            <h1>Profile</h1>
            <p class="profile-identity__email"><?php echo sanitize($user['email'] ?? ''); ?></p>
          </div>
        </div>
        <div class="profile-chip-row">
          <span class="badge <?php echo sanitize($statusBadgeClass); ?>"><?php echo sanitize($statusLabel); ?></span>
          <?php if ($roleLabel !== ''): ?>
            <span class="profile-chip"><?php echo sanitize($roleLabel); ?></span>
          <?php endif; ?>
          <?php if ($sectorLabel !== ''): ?>
            <span class="profile-chip"><?php echo sanitize($sectorLabel); ?></span>
          <?php endif; ?>
        </div>
        <dl class="profile-meta">
          <div>
            <dt>Joined</dt>
            <dd>
              <?php if ($membershipSummary['short'] !== '—'): ?>
                <span><?php echo sanitize($membershipSummary['short']); ?></span>
                <?php if ($membershipSummary['long']): ?><span class="muted">(<?php echo sanitize($membershipSummary['long']); ?>)</span><?php endif; ?>
              <?php else: ?>
                <span class="muted">—</span>
              <?php endif; ?>
            </dd>
          </div>
          <div>
            <dt>Last activity</dt>
            <dd>
              <?php if ($lastActiveRelative !== ''): ?>
                <span><?php echo sanitize($lastActiveRelative); ?></span>
                <?php if ($lastActiveFull !== ''): ?><span class="muted">(<?php echo sanitize($lastActiveFull); ?>)</span><?php endif; ?>
              <?php else: ?>
                <span class="muted">Waiting for first sign-in</span>
              <?php endif; ?>
            </dd>
          </div>
          <div>
            <dt>Data source</dt>
            <dd><span class="profile-chip"><?php echo sanitize(ucfirst((string)$storeSchema)); ?></span></dd>
          </div>
          <div>
            <dt>User ID</dt>
            <dd><span class="profile-chip">#<?php echo (int)$user['id']; ?></span></dd>
          </div>
        </dl>
      </section>

      <?php if ($securityHighlight): ?>
        <section class="profile-card profile-card--callout profile-card--<?php echo sanitize($securityHighlight['tone']); ?> card">
          <div class="profile-callout">
            <div class="profile-callout__icon" aria-hidden="true">🛡️</div>
            <div class="profile-callout__body">
              <p class="profile-card__eyebrow">Security</p>
              <h2><?php echo sanitize($securityHighlight['title']); ?></h2>
              <?php if (!empty($securityHighlight['description'])): ?>
                <p><?php echo sanitize($securityHighlight['description']); ?></p>
              <?php endif; ?>
              <p class="profile-callout__meta">
                <?php if (!empty($securityHighlight['time'])): ?>
                  <span><?php echo sanitize($securityHighlight['time']); ?></span>
                <?php endif; ?>
                <?php if (!empty($securityHighlight['timestamp'])): ?>
                  <span><?php echo sanitize($securityHighlight['timestamp']); ?></span>
                <?php endif; ?>
              </p>
            </div>
          </div>
        </section>
      <?php endif; ?>

      <?php if ($quickActions): ?>
        <section class="profile-card card">
          <h2 class="profile-card__title">Quick links</h2>
          <ul class="profile-quick-actions">
            <?php foreach ($quickActions as $action): ?>
              <li>
                <a class="profile-quick-action" href="<?php echo sanitize($action['href']); ?>">
                  <span class="profile-quick-action__icon" aria-hidden="true"><?php echo sanitize($action['icon']); ?></span>
                  <span class="profile-quick-action__body">
                    <span class="profile-quick-action__label"><?php echo sanitize($action['label']); ?></span>
                    <span class="profile-quick-action__meta"><?php echo sanitize($action['description']); ?></span>
                  </span>
                </a>
              </li>
            <?php endforeach; ?>
          </ul>
        </section>
      <?php endif; ?>

      <?php if ($insightCards): ?>
        <section class="profile-card card">
          <h2 class="profile-card__title">Snapshot</h2>
          <div class="profile-insight-grid">
            <?php foreach ($insightCards as $insight): ?>
              <div class="profile-insight">
                <span class="profile-insight__icon" aria-hidden="true"><?php echo sanitize($insight['icon']); ?></span>
                <div class="profile-insight__content">
                  <p class="profile-insight__title"><?php echo sanitize($insight['title']); ?></p>
                  <p class="profile-insight__primary"><?php echo sanitize($insight['primary']); ?></p>
                  <?php if (!empty($insight['meta'])): ?>
                    <p class="profile-insight__meta"><?php echo sanitize($insight['meta']); ?></p>
                  <?php endif; ?>
                </div>
                <div class="profile-meter__value"><?php echo $count; ?></div>
              </div>
            <?php endforeach; ?>
          </div>
        </section>
      <?php endif; ?>
    </aside>

    <div class="profile-main">
      <div class="profile-main__forms">
        <form method="post" class="profile-panel card">
          <div class="profile-panel__header">
            <h2>Contact email</h2>
            <p class="profile-panel__subtitle">Keep your sign-in email current so we can reach you quickly.</p>
          </div>
          <div class="profile-panel__body">
            <label class="profile-field">Email
              <input type="email" name="email" required value="<?php echo sanitize((string)$user['email']); ?>">
            </label>
            <label class="profile-field">Role
              <input type="text" value="<?php echo sanitize($roleLabel ?: '—'); ?>" disabled>
            </label>
          </div>
          <div class="profile-panel__footer">
            <input type="hidden" name="action" value="change_email">
            <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
            <button class="btn primary" type="submit">Save email</button>
          </div>
        </form>

        <form method="post" class="profile-panel card">
          <div class="profile-panel__header">
            <h2>Primary team</h2>
            <p class="profile-panel__subtitle">Tag the sector that best represents your work.</p>
          </div>
          <?php if ($sectorOptions): ?>
            <div class="profile-panel__body">
              <label class="profile-field">Team
                <select name="sector_id">
                  <option value="">No primary team</option>
                  <?php $currentSectorId = isset($user['sector_id']) ? (int)$user['sector_id'] : null; ?>
                  <?php foreach ($sectorOptions as $id => $name): ?>
                    <option value="<?php echo (int)$id; ?>"<?php echo ($currentSectorId !== null && $currentSectorId === (int)$id) ? ' selected' : ''; ?>><?php echo sanitize($name ?: 'Unnamed'); ?></option>
                  <?php endforeach; ?>
                </select>
              </label>
              <p class="profile-help muted">We use this to personalize dashboards and exports.</p>
            </div>
            <div class="profile-panel__footer">
              <input type="hidden" name="action" value="update_sector">
              <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
              <button class="btn primary" type="submit">Save team</button>
            </div>
          <?php else: ?>
            <div class="profile-panel__body">
              <p class="muted">We could not load sector options. Ask an administrator to add sectors.</p>
            </div>
          <?php endif; ?>
        </form>

        <form method="post" class="profile-panel profile-panel--wide card">
          <div class="profile-panel__header">
            <h2>Update password</h2>
            <p class="profile-panel__subtitle">Use at least 8 characters and mix letters, numbers, and symbols.</p>
          </div>
          <div class="profile-panel__body profile-panel__body--columns">
            <label class="profile-field">Current password
              <input type="password" name="current_password" required autocomplete="current-password">
            </label>
            <label class="profile-field">New password
              <input type="password" name="new_password" required autocomplete="new-password" minlength="8" placeholder="At least 8 characters">
            </label>
            <label class="profile-field">Confirm new password
              <input type="password" name="confirm_password" required autocomplete="new-password">
            </label>
          </div>
          <div class="profile-panel__footer">
            <input type="hidden" name="action" value="change_password">
            <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
            <button class="btn primary" type="submit">Update password</button>
          </div>
        </form>

        <form method="post" class="profile-panel profile-panel--wide card">
          <div class="profile-panel__header">
            <h2>Notification preferences</h2>
            <p class="profile-panel__subtitle">Choose how we reach you about new work.</p>
          </div>
          <?php if (!$notificationsAvailable): ?>
            <div class="profile-panel__body">
              <p class="muted">Notification preferences are temporarily unavailable.</p>
            </div>
          <?php else: ?>
            <div class="profile-panel__summary">
              <span class="profile-panel__summary-chip"><?php echo (int)$notificationSummary['active_channels']; ?> active channel<?php echo ((int)$notificationSummary['active_channels'] === 1) ? '' : 's'; ?></span>
              <?php if (!empty($notificationSummary['snoozed'])): ?>
                <span class="profile-panel__summary-chip profile-panel__summary-chip--muted"><?php echo (int)$notificationSummary['snoozed']; ?> snoozed</span>
              <?php endif; ?>
            </div>
            <div class="profile-panel__body pref-list">
              <?php foreach ($notificationTypes as $type => $meta):
                $pref      = $notificationPrefs[$type] ?? ['allow_web' => true, 'allow_email' => false, 'allow_push' => false, 'mute_until' => null];
                $muteState = profile_mute_field_state($pref['mute_until']);
                $fieldKey  = preg_replace('/[^a-z0-9]+/i', '_', $type);
                $hasExistingMute = !empty($pref['mute_until']) && $muteState['select'] !== 'off';
                $keepLabel = 'Keep current snooze';
                if (!empty($pref['mute_until'])) {
                    if ($muteState['select'] === 'forever') {
                        $keepLabel = 'Keep mute on';
                    } else {
                        $keepLabel = 'Keep until ' . profile_format_datetime($pref['mute_until']);
                    }
                }
              ?>
                <div class="pref-row">
                  <div class="pref-row__info">
                    <h3><?php echo sanitize($meta['label']); ?></h3>
                    <p class="muted"><?php echo sanitize($meta['description']); ?></p>
                  </div>
                  <div class="pref-row__toggles">
                    <label class="switch">
                      <input type="checkbox" name="prefs[<?php echo sanitize($type); ?>][allow_web]" value="1"<?php echo $pref['allow_web'] ? ' checked' : ''; ?>>
                      <span class="switch__control" aria-hidden="true"></span>
                      <span class="switch__label">In-app</span>
                    </label>
                    <label class="switch">
                      <input type="checkbox" name="prefs[<?php echo sanitize($type); ?>][allow_email]" value="1"<?php echo $pref['allow_email'] ? ' checked' : ''; ?>>
                      <span class="switch__control" aria-hidden="true"></span>
                      <span class="switch__label">Email</span>
                    </label>
                    <label class="switch">
                      <input type="checkbox" name="prefs[<?php echo sanitize($type); ?>][allow_push]" value="1"<?php echo $pref['allow_push'] ? ' checked' : ''; ?>>
                      <span class="switch__control" aria-hidden="true"></span>
                      <span class="switch__label">Push</span>
                    </label>
                  </div>
                  <div class="pref-row__mute">
                    <label for="mute-<?php echo sanitize($fieldKey); ?>">Snooze</label>
                    <select id="mute-<?php echo sanitize($fieldKey); ?>" name="prefs[<?php echo sanitize($type); ?>][mute_for]">
                      <option value="off"<?php echo $muteState['select'] === 'off' ? ' selected' : ''; ?>>Live updates</option>
                      <option value="1h"<?php echo $muteState['select'] === '1h' ? ' selected' : ''; ?>>Pause 1 hour</option>
                      <option value="4h"<?php echo $muteState['select'] === '4h' ? ' selected' : ''; ?>>Pause 4 hours</option>
                      <option value="1d"<?php echo $muteState['select'] === '1d' ? ' selected' : ''; ?>>Pause 1 day</option>
                      <option value="3d"<?php echo $muteState['select'] === '3d' ? ' selected' : ''; ?>>Pause 3 days</option>
                      <option value="7d"<?php echo $muteState['select'] === '7d' ? ' selected' : ''; ?>>Pause 7 days</option>
                      <option value="forever"<?php echo $muteState['select'] === 'forever' ? ' selected' : ''; ?>>Mute until I turn it back on</option>
                      <?php if ($hasExistingMute): ?>
                        <option value="keep"<?php echo $muteState['select'] === 'keep' ? ' selected' : ''; ?>><?php echo sanitize($keepLabel); ?></option>
                      <?php endif; ?>
                    </select>
                    <input type="hidden" name="prefs[<?php echo sanitize($type); ?>][existing_mute_until]" value="<?php echo sanitize((string)($pref['mute_until'] ?? '')); ?>">
                    <?php if ($muteState['description']): ?>
                      <p class="pref-row__hint"><?php echo sanitize($muteState['description']); ?></p>
                    <?php endif; ?>
                  </div>
                </div>
              <?php endforeach; ?>
            </div>
            <div class="profile-panel__footer">
              <input type="hidden" name="action" value="update_prefs">
              <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
              <button class="btn primary" type="submit">Save preferences</button>
            </div>
          <?php endif; ?>
        </form>
      </div>

      <div class="profile-subgrid">
        <section class="profile-panel card">
          <div class="profile-panel__header">
            <h2>Security timeline</h2>
            <p class="profile-panel__subtitle">Latest sign-ins and account changes.</p>
          </div>
          <div class="profile-panel__body">
            <?php if ($securityEvents): ?>
              <ul class="timeline">
                <?php foreach ($securityEvents as $event): ?>
                  <li class="timeline__item">
                    <div class="timeline__title"><?php echo sanitize($event['title']); ?></div>
                    <?php if ($event['details']): ?>
                      <div class="timeline__details"><?php echo sanitize($event['details']); ?></div>
                    <?php endif; ?>
                    <?php if ($event['meta']): ?>
                      <div class="timeline__meta"><?php echo sanitize($event['meta']); ?></div>
                    <?php endif; ?>
                    <div class="timeline__time"><?php echo sanitize($event['relative']); ?> · <?php echo sanitize($event['formatted']); ?></div>
                  </li>
                <?php endforeach; ?>
              </ul>
            <?php else: ?>
              <p class="muted">We have not logged any recent sign-ins yet.</p>
            <?php endif; ?>
          </div>
        </section>

        <section class="profile-panel card">
          <div class="profile-panel__header">
            <h2>Trusted devices</h2>
            <p class="profile-panel__subtitle">Disconnect browsers or mobiles you no longer recognize.</p>
          </div>
          <div class="profile-panel__body">
            <?php if (!$notificationsAvailable): ?>
              <p class="muted">Connect a device to enable web or push notifications.</p>
            <?php elseif ($notificationDevices): ?>
              <ul class="device-list">
                <?php foreach ($notificationDevices as $device):
                  $kind = (string)($device['kind'] ?? 'webpush');
                  $kindLabel = match ($kind) {
                    'fcm'  => 'Android push',
                    'apns' => 'iOS push',
                    default => 'Web push',
                  };
                  $lastUsed = $device['last_used_at'] ?? $device['created_at'] ?? null;
                  $lastRelative = profile_relative_time($lastUsed);
                  $lastFormatted = profile_format_datetime($lastUsed);
                  $uaLabel = profile_summarize_user_agent($device['user_agent'] ?? '');
                ?>
                  <li class="device-row">
                    <div class="device-row__main">
                      <span class="device-row__kind"><?php echo sanitize($kindLabel); ?></span>
                      <div class="device-row__text">
                        <div class="device-row__label"><?php echo sanitize($uaLabel); ?></div>
                        <?php if ($lastFormatted): ?>
                          <div class="device-row__meta"><?php echo sanitize($lastRelative ?: 'Last seen'); ?> · <?php echo sanitize($lastFormatted); ?></div>
                        <?php endif; ?>
                      </div>
                    </div>
                    <form method="post" class="device-row__actions">
                      <input type="hidden" name="action" value="revoke_device">
                      <input type="hidden" name="device_id" value="<?php echo (int)$device['id']; ?>">
                      <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                      <button class="btn secondary small" type="submit">Disconnect</button>
                    </form>
                  </li>
                <?php endforeach; ?>
              </ul>
            <?php else: ?>
              <p class="muted">No connected browsers or mobile devices yet.</p>
            <?php endif; ?>
          </div>
        </section>

        <?php if ($notificationsAvailable): ?>
          <section class="profile-panel card">
            <div class="profile-panel__header">
              <h2>Inbox preview</h2>
              <p class="profile-panel__subtitle">Last few notifications delivered to you.</p>
            </div>
            <div class="profile-panel__body">
              <?php if ($recentNotifications): ?>
                <ul class="inbox-list">
                  <?php foreach ($recentNotifications as $item): ?>
                    <li class="inbox-item<?php echo $item['is_read'] ? ' is-read' : ''; ?>">
                      <span class="inbox-item__status" aria-hidden="true"></span>
                      <div class="inbox-item__content">
                        <div class="inbox-item__title">
                          <?php if (!empty($item['url'])): ?>
                            <a href="<?php echo sanitize($item['url']); ?>"><?php echo sanitize($item['title']); ?></a>
                          <?php else: ?>
                            <?php echo sanitize($item['title']); ?>
                          <?php endif; ?>
                        </div>
                        <?php if (!empty($item['body'])): ?>
                          <p class="inbox-item__body"><?php echo sanitize($item['body']); ?></p>
                        <?php endif; ?>
                        <div class="inbox-item__meta"><?php echo sanitize($item['relative'] ?: $item['formatted']); ?></div>
                      </div>
                    </li>
                  <?php endforeach; ?>
                </ul>
              <?php else: ?>
                <p class="muted">All caught up! We will list new alerts here once they arrive.</p>
              <?php endif; ?>
            </div>
          </section>
        <?php endif; ?>

        <?php if ($notificationsAvailable && $notificationSummary['total_types'] > 0): ?>
          <section class="profile-panel card">
            <div class="profile-panel__header">
              <h2>Notification snapshot</h2>
              <p class="profile-panel__subtitle">Your communication mix at a glance.</p>
            </div>
            <div class="profile-panel__body profile-meter">
              <?php foreach ([
                'in-app' => 'In-app',
                'email'  => 'Email',
                'push'   => 'Push',
              ] as $key => $label):
                $count = (int)($notificationSummary['channels'][$key] ?? 0);
                $ratio = ($notificationSummary['total_types'] > 0)
                  ? min(100, (int)round(($count / $notificationSummary['total_types']) * 100))
                  : 0;
              ?>
                <div class="profile-meter__row">
                  <div class="profile-meter__label"><?php echo sanitize($label); ?></div>
                  <div class="profile-meter__bar" role="presentation">
                    <span style="--value: <?php echo $ratio; ?>%"></span>
                  </div>
                  <div class="profile-meter__value"><?php echo $count; ?></div>
                </div>
              <?php endforeach; ?>
              <?php if (!empty($notificationSummary['snoozed'])): ?>
                <p class="profile-meter__note">Snoozed for <?php echo (int)$notificationSummary['snoozed']; ?> notification type<?php echo ((int)$notificationSummary['snoozed'] === 1) ? '' : 's'; ?>.</p>
              <?php endif; ?>
            </div>
          </section>
        <?php endif; ?>

        <section class="profile-panel card profile-span-2">
          <div class="profile-panel__header">
            <h2>Data tools</h2>
            <p class="profile-panel__subtitle">On-demand exports you can share with stakeholders.</p>
          </div>
          <div class="profile-panel__body">
            <ul class="export-list">
              <?php foreach ($dataExportLinks as $export): ?>
                <li class="export-row">
                  <div class="export-row__text">
                    <a class="export-row__link" href="<?php echo sanitize($export['href']); ?>"><?php echo sanitize($export['label']); ?></a>
                    <p class="export-row__meta muted"><?php echo sanitize($export['description']); ?></p>
                  </div>
                  <span aria-hidden="true" class="export-row__chevron">⟶</span>
                </li>
              <?php endforeach; ?>
            </ul>
          </div>
        </section>
      </div>
    </div>
  </div>
</div>

<?php include __DIR__ . '/../includes/footer.php';