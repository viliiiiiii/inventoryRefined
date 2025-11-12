<?php
declare(strict_types=1);

require_once __DIR__ . '/inventory_helpers.php';
require_login();

$appsPdo = get_pdo();        // APPS (punchlist) DB
$corePdo = get_pdo('core');  // CORE (users/roles/sectors/activity) DB — may be same as APPS if not split

$canManage    = can('inventory_manage');
$isRoot       = current_user_role_key() === 'root';
$userSectorId = current_user_sector_id();

$errors = [];

function inventory_fetch_item(PDO $pdo, int $itemId): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM inventory_items WHERE id = ?');
    $stmt->execute([$itemId]);
    $item = $stmt->fetch();
    return $item ?: null;
}

if (is_post()) {
    try {
        if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
            $errors[] = 'Invalid CSRF token.';
        } elseif (!$canManage) {
            $errors[] = 'Insufficient permissions.';
        } else {
            $action = $_POST['action'] ?? '';
            $currentUser = current_user() ?? [];
            $currentUserId = (int)($currentUser['id'] ?? 0) ?: null;

            if ($action === 'create_item') {
                $name       = trim((string)($_POST['name'] ?? ''));
                $sku        = trim((string)($_POST['sku'] ?? ''));
                $quantity   = max(0, (int)($_POST['quantity'] ?? 0));
                $location   = trim((string)($_POST['location'] ?? ''));
                $sectorIn   = $_POST['sector_id'] ?? '';
                $sectorId   = $isRoot ? (($sectorIn === '' || $sectorIn === 'null') ? null : (int)$sectorIn) : $userSectorId;

                if ($name === '') {
                    $errors[] = 'Name is required.';
                }
                if (!$isRoot && $sectorId === null) {
                    $errors[] = 'Your sector must be assigned before creating items.';
                }

                if (!$errors) {
                    $appsPdo->beginTransaction();
                    try {
                        $stmt = $appsPdo->prepare('INSERT INTO inventory_items (sku, name, sector_id, quantity, location) VALUES (:sku,:name,:sector,:quantity,:location)');
                        $stmt->execute([
                            ':sku'      => $sku !== '' ? $sku : null,
                            ':name'     => $name,
                            ':sector'   => $sectorId,
                            ':quantity' => $quantity,
                            ':location' => $location !== '' ? $location : null,
                        ]);
                        $itemId = (int)$appsPdo->lastInsertId();
                        if ($sectorId !== null) {
                            inventory_adjust_stock($appsPdo, $itemId, $sectorId, $quantity);
                        }
                        if ($quantity > 0) {
                            $appsPdo->prepare('INSERT INTO inventory_movements (item_id, direction, amount, reason, user_id, source_sector_id, target_sector_id, source_location, target_location, requires_signature, transfer_status) VALUES (:item,:dir,:amount,:reason,:user,:src,:tgt,:src_loc,:tgt_loc,:req,:status)')
                                ->execute([
                                    ':item'    => $itemId,
                                    ':dir'     => 'in',
                                    ':amount'  => $quantity,
                                    ':reason'  => 'Initial quantity',
                                    ':user'    => $currentUserId,
                                    ':src'     => null,
                                    ':tgt'     => $sectorId,
                                    ':src_loc' => null,
                                    ':tgt_loc' => $location !== '' ? $location : null,
                                    ':req'     => 0,
                                    ':status'  => 'signed',
                                ]);
                        }
                        $appsPdo->commit();
                        log_event('inventory.add', 'inventory_item', $itemId, ['quantity' => $quantity, 'sector_id' => $sectorId]);
                        redirect_with_message('inventory.php', 'Item added.');
                    } catch (Throwable $e) {
                        $appsPdo->rollBack();
                        throw $e;
                    }
                }
            } elseif ($action === 'bulk_create_items') {
                $bulk = $_POST['bulk'] ?? [];
                $names     = $bulk['name'] ?? [];
                $skus      = $bulk['sku'] ?? [];
                $quantities= $bulk['quantity'] ?? [];
                $locations = $bulk['location'] ?? [];
                $sectors   = $bulk['sector_id'] ?? [];

                $rows = [];
                foreach ((array)$names as $idx => $nameVal) {
                    $nameVal = trim((string)$nameVal);
                    if ($nameVal === '') {
                        continue;
                    }
                    $rows[] = [
                        'name'     => $nameVal,
                        'sku'      => trim((string)($skus[$idx] ?? '')),
                        'quantity' => max(0, (int)($quantities[$idx] ?? 0)),
                        'location' => trim((string)($locations[$idx] ?? '')),
                        'sector'   => $isRoot ? (($sectors[$idx] ?? '') === 'null' || ($sectors[$idx] ?? '') === '' ? null : (int)$sectors[$idx]) : $userSectorId,
                    ];
                }

                if (!$rows) {
                    $errors[] = 'Provide at least one valid item row.';
                } elseif (!$isRoot && $userSectorId === null) {
                    $errors[] = 'Your sector must be assigned before creating items.';
                }

                if (!$errors) {
                    $appsPdo->beginTransaction();
                    try {
                        foreach ($rows as $row) {
                            $stmt = $appsPdo->prepare('INSERT INTO inventory_items (sku, name, sector_id, quantity, location) VALUES (:sku,:name,:sector,:qty,:location)');
                            $stmt->execute([
                                ':sku'      => $row['sku'] !== '' ? $row['sku'] : null,
                                ':name'     => $row['name'],
                                ':sector'   => $row['sector'],
                                ':qty'      => $row['quantity'],
                                ':location' => $row['location'] !== '' ? $row['location'] : null,
                            ]);
                            $itemId = (int)$appsPdo->lastInsertId();
                            if ($row['sector'] !== null) {
                                inventory_adjust_stock($appsPdo, $itemId, $row['sector'], $row['quantity']);
                            }
                            if ($row['quantity'] > 0) {
                                $appsPdo->prepare('INSERT INTO inventory_movements (item_id, direction, amount, reason, user_id, source_sector_id, target_sector_id, source_location, target_location, requires_signature, transfer_status) VALUES (:item,:dir,:amount,:reason,:user,:src,:tgt,:src_loc,:tgt_loc,:req,:status)')
                                    ->execute([
                                        ':item'    => $itemId,
                                        ':dir'     => 'in',
                                        ':amount'  => $row['quantity'],
                                        ':reason'  => 'Initial quantity',
                                        ':user'    => $currentUserId,
                                        ':src'     => null,
                                        ':tgt'     => $row['sector'],
                                        ':src_loc' => null,
                                        ':tgt_loc' => $row['location'] !== '' ? $row['location'] : null,
                                        ':req'     => 0,
                                        ':status'  => 'signed',
                                    ]);
                            }
                        }
                        $appsPdo->commit();
                        redirect_with_message('inventory.php', 'Items added.');
                    } catch (Throwable $e) {
                        $appsPdo->rollBack();
                        throw $e;
                    }
                }
            } elseif ($action === 'update_item') {
                $itemId   = (int)($_POST['item_id'] ?? 0);
                $name     = trim((string)($_POST['name'] ?? ''));
                $sku      = trim((string)($_POST['sku'] ?? ''));
                $location = trim((string)($_POST['location'] ?? ''));
                $sectorIn = $_POST['sector_id'] ?? '';

                $item = inventory_fetch_item($appsPdo, $itemId);
                if (!$item) {
                    $errors[] = 'Item not found.';
                } else {
                    $sectorId = $isRoot ? (($sectorIn === '' || $sectorIn === 'null') ? null : (int)$sectorIn) : $userSectorId;
                    if (!$isRoot && (int)$item['sector_id'] !== (int)$userSectorId) {
                        $errors[] = 'Cannot edit items from other sectors.';
                    }
                    if ($name === '') {
                        $errors[] = 'Name is required.';
                    }
                    if (!$isRoot && $sectorId === null) {
                        $errors[] = 'Your sector must be assigned before editing items.';
                    }
                    if (!$errors) {
                        $appsPdo->prepare('UPDATE inventory_items SET name=:name, sku=:sku, location=:location, sector_id=:sector WHERE id=:id')
                            ->execute([
                                ':name'     => $name,
                                ':sku'      => $sku !== '' ? $sku : null,
                                ':location' => $location !== '' ? $location : null,
                                ':sector'   => $sectorId,
                                ':id'       => $itemId,
                            ]);
                        redirect_with_message('inventory.php', 'Item updated.');
                    }
                }
            } elseif ($action === 'move_stock' || $action === 'bulk_move_stock') {
                $movementsForPdf = [];
                $lineItems = [];
                $itemsToProcess = [];

                if ($action === 'move_stock') {
                    $itemsToProcess[] = [
                        'item_id'           => (int)($_POST['item_id'] ?? 0),
                        'direction'         => ($_POST['direction'] ?? '') === 'out' ? 'out' : 'in',
                        'amount'            => max(1, (int)($_POST['amount'] ?? 0)),
                        'reason'            => trim((string)($_POST['reason'] ?? '')),
                        'target_sector_id'  => isset($_POST['target_sector_id']) && $_POST['target_sector_id'] !== '' && $_POST['target_sector_id'] !== 'null'
                            ? (int)$_POST['target_sector_id'] : null,
                        'requires_signature'=> isset($_POST['requires_signature']) ? (bool)$_POST['requires_signature'] : false,
                        'target_location'   => trim((string)($_POST['target_location'] ?? '')),
                        'notes'             => trim((string)($_POST['notes'] ?? '')),
                    ];
                } else {
                    $bulk = $_POST['move'] ?? [];
                    $itemIds  = $bulk['item_id'] ?? [];
                    $dirs     = $bulk['direction'] ?? [];
                    $amounts  = $bulk['amount'] ?? [];
                    $reasons  = $bulk['reason'] ?? [];
                    $targets  = $bulk['target_sector_id'] ?? [];
                    $reqs     = $bulk['requires_signature'] ?? [];
                    $locations= $bulk['target_location'] ?? [];
                    $notesArr = $bulk['notes'] ?? [];
                    foreach ((array)$itemIds as $idx => $itemIdVal) {
                        $iid = (int)$itemIdVal;
                        if ($iid <= 0) {
                            continue;
                        }
                        $amt = max(1, (int)($amounts[$idx] ?? 0));
                        $dir = ($dirs[$idx] ?? '') === 'out' ? 'out' : 'in';
                        $itemsToProcess[] = [
                            'item_id'           => $iid,
                            'direction'         => $dir,
                            'amount'            => $amt,
                            'reason'            => trim((string)($reasons[$idx] ?? '')),
                            'target_sector_id'  => isset($targets[$idx]) && $targets[$idx] !== '' && $targets[$idx] !== 'null'
                                ? (int)$targets[$idx] : null,
                            'requires_signature'=> isset($reqs[$idx]) && $reqs[$idx] ? true : false,
                            'target_location'   => trim((string)($locations[$idx] ?? '')),
                            'notes'             => trim((string)($notesArr[$idx] ?? '')),
                        ];
                    }
                }

                if (!$itemsToProcess) {
                    $errors[] = 'Provide at least one movement row.';
                }

                if (!$errors) {
                    $appsPdo->beginTransaction();
                    try {
                        foreach ($itemsToProcess as $movementRow) {
                            $item = inventory_fetch_item($appsPdo, (int)$movementRow['item_id']);
                            if (!$item) {
                                throw new RuntimeException('Item not found for movement.');
                            }
                            if (!$isRoot && (int)$item['sector_id'] !== (int)$userSectorId) {
                                throw new RuntimeException('Cannot move stock for other sectors.');
                            }

                            $direction = $movementRow['direction'];
                            $amount    = $movementRow['amount'];
                            $reason    = $movementRow['reason'];
                            $targetSectorId = $movementRow['target_sector_id'];
                            $targetLocation = $movementRow['target_location'];
                            $notes    = $movementRow['notes'];

                            $sourceSectorId = $item['sector_id'] !== null ? (int)$item['sector_id'] : null;
                            $requiresSignature = $movementRow['requires_signature'] || ($targetSectorId !== null && $targetSectorId !== $sourceSectorId);
                            $delta = $direction === 'in' ? $amount : -$amount;
                            $newQuantity = (int)$item['quantity'] + $delta;
                            if ($newQuantity < 0) {
                                throw new RuntimeException('Not enough stock to move "' . ($item['name'] ?? '') . '".');
                            }

                            $appsPdo->prepare('UPDATE inventory_items SET quantity = quantity + :delta WHERE id = :id')
                                ->execute([':delta' => $delta, ':id' => (int)$item['id']]);

                            if ($direction === 'out') {
                                if ($sourceSectorId !== null) {
                                    inventory_adjust_stock($appsPdo, (int)$item['id'], $sourceSectorId, -$amount);
                                }
                                if ($targetSectorId !== null) {
                                    inventory_adjust_stock($appsPdo, (int)$item['id'], $targetSectorId, $amount);
                                }
                            } else {
                                $destSector = $targetSectorId ?? $sourceSectorId;
                                if ($destSector !== null) {
                                    inventory_adjust_stock($appsPdo, (int)$item['id'], $destSector, $amount);
                                }
                            }

                            $appsPdo->prepare('INSERT INTO inventory_movements (item_id, direction, amount, reason, user_id, source_sector_id, target_sector_id, source_location, target_location, requires_signature, transfer_status, notes) VALUES (:item,:dir,:amount,:reason,:user,:src,:tgt,:src_loc,:tgt_loc,:req,:status,:notes)')
                                ->execute([
                                    ':item'    => (int)$item['id'],
                                    ':dir'     => $direction,
                                    ':amount'  => $amount,
                                    ':reason'  => $reason !== '' ? $reason : null,
                                    ':user'    => $currentUserId,
                                    ':src'     => $sourceSectorId,
                                    ':tgt'     => $targetSectorId,
                                    ':src_loc' => $item['location'] ?? null,
                                    ':tgt_loc' => $targetLocation !== '' ? $targetLocation : null,
                                    ':req'     => $requiresSignature ? 1 : 0,
                                    ':status'  => $requiresSignature ? 'pending' : 'signed',
                                    ':notes'   => $notes !== '' ? $notes : null,
                                ]);

                            $movementId = (int)$appsPdo->lastInsertId();
                            $item['quantity'] = $newQuantity;

                            if ($requiresSignature) {
                                $movementsForPdf[] = [
                                    'id'               => $movementId,
                                    'item_id'          => (int)$item['id'],
                                    'direction'        => $direction,
                                    'amount'           => $amount,
                                    'reason'           => $reason,
                                    'source_sector_id' => $sourceSectorId,
                                    'target_sector_id' => $targetSectorId,
                                ];
                                $lineItems[] = [
                                    'name'      => $item['name'],
                                    'sku'       => $item['sku'] ?? '',
                                    'amount'    => $amount,
                                    'direction' => $direction,
                                    'reason'    => $reason !== '' ? $reason : $notes,
                                ];
                            }
                        }
                        $appsPdo->commit();
                    } catch (Throwable $e) {
                        $appsPdo->rollBack();
                        $errors[] = $e->getMessage();
                    }

                    if (!$errors && $movementsForPdf) {
                        try {
                            $sectorRows = (array)$corePdo->query('SELECT id,name FROM sectors')->fetchAll();
                            inventory_generate_transfer_pdf($appsPdo, $movementsForPdf, $lineItems, $sectorRows, $currentUser);
                        } catch (Throwable $e) {
                            $errors[] = 'Movements recorded but PDF could not be generated: ' . $e->getMessage();
                        }
                    }

                    if (!$errors) {
                        redirect_with_message('inventory.php', 'Movement recorded.');
                    }
                }
            } elseif ($action === 'upload_movement_file') {
                $movementId = (int)($_POST['movement_id'] ?? 0);
                $kind       = in_array($_POST['kind'] ?? 'signature', ['signature','photo','other'], true) ? $_POST['kind'] : 'signature';
                $label      = trim((string)($_POST['label'] ?? ''));

                $movement = null;
                if ($movementId > 0) {
                    $stmt = $appsPdo->prepare('SELECT * FROM inventory_movements WHERE id = ?');
                    $stmt->execute([$movementId]);
                    $movement = $stmt->fetch();
                }
                if (!$movement) {
                    $errors[] = 'Movement not found.';
                }

                if (!$errors) {
                    try {
                        $upload = inventory_s3_upload_file($_FILES['movement_file'] ?? []);
                        inventory_store_movement_file($appsPdo, $movementId, $upload, $label !== '' ? $label : null, $kind, $currentUserId);
                        if ($kind === 'signature') {
                            $appsPdo->prepare('UPDATE inventory_movements SET transfer_status = :status WHERE id = :id')
                                ->execute([':status' => 'signed', ':id' => $movementId]);
                        }
                        redirect_with_message('inventory.php', 'File uploaded.');
                    } catch (Throwable $e) {
                        $errors[] = 'Upload failed: ' . $e->getMessage();
                    }
                }
            } elseif ($action === 'mark_movement_signed') {
                $movementId = (int)($_POST['movement_id'] ?? 0);
                $appsPdo->prepare('UPDATE inventory_movements SET transfer_status = :status WHERE id = :id')
                    ->execute([':status' => 'signed', ':id' => $movementId]);
                redirect_with_message('inventory.php', 'Movement marked as signed.');
            }
        }
    } catch (Throwable $e) {
        $errors[] = 'Server error: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    }
}

$sectorOptions = [];
try {
    $sectorOptions = $corePdo->query('SELECT id, name FROM sectors ORDER BY name')->fetchAll();
} catch (Throwable $e) {
    $errors[] = 'Sectors table missing in CORE DB (or query failed).';
}

if ($isRoot) {
    $sectorFilter = $_GET['sector'] ?? '';
} elseif ($userSectorId !== null) {
    $sectorFilter = (string)$userSectorId;
} else {
    $sectorFilter = 'null';
}

$where = [];
$params= [];
if ($sectorFilter !== '' && $sectorFilter !== 'all') {
    if ($sectorFilter === 'null') {
        $where[] = 'sector_id IS NULL';
    } else {
        $where[] = 'sector_id = :sector';
        $params[':sector'] = (int)$sectorFilter;
    }
}
if (!$isRoot && $userSectorId !== null) {
    $where[] = 'sector_id = :my_sector';
    $params[':my_sector'] = (int)$userSectorId;
}
if (!$isRoot && $userSectorId === null) {
    $where[] = 'sector_id IS NULL';
}
$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$items = [];
$movementsByItem = [];
$movementFiles = [];
$movementTokens = [];

try {
    $itemStmt = $appsPdo->prepare("SELECT * FROM inventory_items $whereSql ORDER BY name");
    $itemStmt->execute($params);
    $items = $itemStmt->fetchAll();

    $itemIds = array_map(static fn($row) => (int)$row['id'], $items);
    $movementsByItem = inventory_fetch_movements($appsPdo, $itemIds);

    $movementIds = [];
    foreach ($movementsByItem as $itemMovements) {
        foreach ($itemMovements as $mov) {
            $movementIds[] = (int)$mov['id'];
        }
    }
    $movementFiles  = inventory_fetch_movement_files($appsPdo, $movementIds);
    $movementTokens = inventory_fetch_public_tokens($appsPdo, $movementIds);
} catch (Throwable $e) {
    $errors[] = 'Inventory tables missing in APPS DB (or query failed).';
}

function sector_name_by_id(array $sectors, $id): string {
    foreach ($sectors as $s) {
        if ((string)$s['id'] === (string)$id) {
            return (string)$s['name'];
        }
    }
    return '';
}

function inventory_format_file_label(array $file, array $sectorOptions): string
{
    $displayLabel = (string)($file['label'] ?? '');
    if (($file['kind'] ?? '') === 'signature') {
        $meta = inventory_decode_signature_label($displayLabel);
        if ($meta) {
            $roleLabel = ($meta['role'] ?? '') === 'target' ? 'Receiving signature' : 'Source signature';
            $parts = [$roleLabel];
            if (!empty($meta['sector_name'])) {
                $parts[] = (string)$meta['sector_name'];
            }
            if (!empty($meta['signer'])) {
                $parts[] = (string)$meta['signer'];
            }
            $displayLabel = implode(' · ', array_filter($parts));
        }
    }
    if ($displayLabel === '') {
        $displayLabel = basename((string)($file['file_key'] ?? 'file'));
    }
    return $displayLabel;
}

function inventory_format_datetime(?string $ts): string
{
    if ($ts === null || $ts === '') {
        return '—';
    }
    $time = strtotime($ts);
    if ($time === false) {
        return $ts;
    }
    return date('M j, Y g:i A', $time);
}

function inventory_string_ends_with(string $haystack, string $needle): bool
{
    if ($needle === '') {
        return true;
    }
    $needleLength = strlen($needle);
    if ($needleLength === 0 || $needleLength > strlen($haystack)) {
        return false;
    }
    return substr($haystack, -$needleLength) === $needle;
}

function inventory_file_is_pdf(array $file): bool
{
    $mime = strtolower((string)($file['mime'] ?? ''));
    if ($mime !== '' && strpos($mime, 'pdf') !== false) {
        return true;
    }

    $candidates = [];
    $url = (string)($file['file_url'] ?? '');
    if ($url !== '') {
        $path = (string)parse_url($url, PHP_URL_PATH);
        if ($path !== '') {
            $candidates[] = strtolower($path);
        }
    }

    $key = (string)($file['file_key'] ?? '');
    if ($key !== '') {
        $candidates[] = strtolower($key);
    }

    foreach ($candidates as $candidate) {
        if (inventory_string_ends_with($candidate, '.pdf')) {
            return true;
        }
    }

    return false;
}

$itemsById = [];
$totalQuantity = 0;
$unassignedItems = 0;
foreach ($items as $itemRow) {
    $itemsById[(int)$itemRow['id']] = $itemRow;
    $totalQuantity += (int)$itemRow['quantity'];
    if ($itemRow['sector_id'] === null) {
        $unassignedItems++;
    }
}

$allMovements = [];
foreach ($movementsByItem as $itemId => $movementList) {
    foreach ($movementList as $movementRow) {
        $movementRow['item'] = $itemsById[(int)$itemId] ?? null;
        $allMovements[] = $movementRow;
    }
}

usort($allMovements, static function (array $a, array $b): int {
    return strcmp((string)($b['ts'] ?? ''), (string)($a['ts'] ?? ''));
});

$movementsById = [];
foreach ($allMovements as $movementRow) {
    $movementsById[(int)$movementRow['id']] = $movementRow;
}

$pendingMovements = array_filter($allMovements, static fn($row) => ($row['transfer_status'] ?? '') === 'pending');
$recentMovements  = array_slice($allMovements, 0, 5);

$documentsList = [];
foreach ($movementFiles as $movementId => $files) {
    foreach ($files as $fileRow) {
        if (($fileRow['kind'] ?? '') === 'signature') {
            continue;
        }
        if (!inventory_file_is_pdf((array)$fileRow)) {
            continue;
        }
        $movementRow = $movementsById[(int)$movementId] ?? null;
        $itemRow = $movementRow['item'] ?? null;
        $documentsList[] = [
            'movement_id'   => (int)$movementId,
            'file'          => $fileRow,
            'label'         => inventory_format_file_label($fileRow, (array)$sectorOptions),
            'uploaded_at'   => $fileRow['uploaded_at'] ?? null,
            'url'           => $fileRow['file_url'] ?? '#',
            'kind'          => $fileRow['kind'] ?? '',
            'movement'      => $movementRow,
            'item'          => $itemRow,
        ];
    }
}

$documentsCount = count($documentsList);
$totalItems = count($items);
$pendingCount = count($pendingMovements);
$currentUserDisplay = current_user() ?? [];
$currentUserRoleLabel = current_user_role_key() ?? 'Manager';
$currentUserName = trim((string)($currentUserDisplay['name'] ?? ($currentUserDisplay['email'] ?? 'John Doe')));
$currentUserEmail = trim((string)($currentUserDisplay['email'] ?? ''));
$currentUserInitials = '';
if ($currentUserName !== '') {
    $nameParts = preg_split('/\s+/', $currentUserName) ?: [];
    foreach (array_slice($nameParts, 0, 2) as $part) {
        $part = trim((string)$part);
        if ($part === '') {
            continue;
        }
        $initial = function_exists('mb_substr') ? mb_substr($part, 0, 1, 'UTF-8') : substr($part, 0, 1);
        $currentUserInitials .= strtoupper((string)$initial);
    }
}
if ($currentUserInitials === '') {
    $currentUserInitials = 'JD';
}

$navItems = [
    [
        'id'         => 'dashboard',
        'label'      => 'Dashboard',
        'icon'       => '📊',
        'subtitle'   => 'Overview of your inventory system',
        'add_label'  => $canManage ? 'Quick Action' : '',
        'add_target' => $canManage ? 'modal-add' : '',
    ],
    [
        'id'         => 'inventory',
        'label'      => 'Inventory',
        'icon'       => '📦',
        'subtitle'   => number_format($totalItems) . ' items found',
        'add_label'  => $canManage ? 'Add Item' : '',
        'add_target' => $canManage ? 'modal-add' : '',
    ],
    [
        'id'         => 'transfers',
        'label'      => 'Transfers',
        'icon'       => '🔄',
        'subtitle'   => number_format(count($allMovements)) . ' movement records',
        'add_label'  => $canManage ? 'Bulk Movement' : '',
        'add_target' => $canManage ? 'modal-bulk-move' : '',
    ],
    [
        'id'         => 'documents',
        'label'      => 'Documents',
        'icon'       => '📄',
        'subtitle'   => number_format($documentsCount) . ' uploaded documents',
        'add_label'  => '',
        'add_target' => '',
    ],
];

$dashboardStats = [
    [
        'label' => 'Total Items',
        'value' => number_format($totalItems),
        'icon'  => '📦',
        'class' => 'stat-card--accent',
    ],
    [
        'label' => 'Total Quantity',
        'value' => number_format($totalQuantity),
        'icon'  => '📊',
        'class' => 'stat-card--success',
    ],
    [
        'label' => 'Pending Signatures',
        'value' => number_format($pendingCount),
        'icon'  => '✍️',
        'class' => 'stat-card--warning',
    ],
    [
        'label' => 'Unassigned Items',
        'value' => number_format($unassignedItems),
        'icon'  => '📍',
        'class' => 'stat-card--info',
    ],
];

?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Inventory workspace</title>
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
  --workspace-bg: var(--notes-bg);
  --workspace-sidebar: var(--notes-sidebar);
  --workspace-surface: var(--notes-surface);
  --workspace-border: var(--notes-border);
  --workspace-text: var(--notes-text);
  --workspace-muted: var(--notes-muted);
  --workspace-accent: var(--notes-accent);
  --workspace-accent-soft: var(--notes-accent-soft);
  --workspace-danger: var(--notes-danger);
  --workspace-radius: var(--notes-radius);
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--notes-bg);
  color: var(--notes-text);
  font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
}
a {
  color: inherit;
  text-decoration: none;
}
.inventory-shell,
.notes-shell {
  display: grid;
  grid-template-columns: 280px 1fr;
  min-height: 100vh;
  background: transparent;
  border-radius: var(--workspace-radius);
  overflow: hidden;
  box-shadow: 0 24px 48px -40px rgba(15, 23, 42, 0.35);
}
.inventory-sidebar,
.notes-sidebar {
  background: var(--workspace-sidebar);
  border-right: 1px solid var(--workspace-border);
  padding: 28px 24px;
  display: flex;
  flex-direction: column;
  gap: 28px;
}
.brand {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.brand__title {
  font-size: 1.15rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand__title .icon {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: var(--workspace-accent-soft);
  color: var(--workspace-accent);
}
.brand__subtitle {
  font-size: 0.9rem;
  color: var(--workspace-muted);
}
.stack {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 14px;
  border-radius: 12px;
  border: 1px solid transparent;
  background: var(--workspace-accent);
  color: #fff;
  font-weight: 600;
  font-size: 0.95rem;
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease;
  text-decoration: none;
}
.button:hover {
  transform: translateY(-1px);
  box-shadow: 0 10px 20px rgba(37, 99, 235, 0.18);
}
.button:focus-visible {
  outline: 2px solid var(--workspace-accent);
  outline-offset: 2px;
}
.button--ghost {
  background: transparent;
  color: var(--workspace-accent);
  border-color: rgba(37, 99, 235, 0.35);
  box-shadow: none;
}
.button--ghost:hover {
  background: var(--workspace-accent-soft);
}
.button--subtle {
  background: rgba(15, 23, 42, 0.05);
  color: var(--workspace-text);
  border-color: rgba(15, 23, 42, 0.08);
  box-shadow: none;
}
.button--tiny {
  font-size: 0.8rem;
  padding: 6px 10px;
  border-radius: 10px;
  font-weight: 500;
}
.button--full {
  width: 100%;
}
.inventory-sidebar__card {
  border: 1px solid var(--workspace-border);
  background: var(--workspace-surface);
  border-radius: var(--workspace-radius);
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.inventory-sidebar__card-title {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--workspace-muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.inventory-sidebar__metrics {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.inventory-sidebar__metrics li {
  display: flex;
  justify-content: space-between;
  font-size: 0.95rem;
  color: var(--workspace-text);
}
.inventory-sidebar__metrics .label {
  color: var(--workspace-muted);
  font-size: 0.85rem;
}
.inventory-sidebar__section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.inventory-sidebar__heading {
  font-size: 0.75rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--workspace-muted);
  font-weight: 600;
}
.inventory-sidebar__footer {
  margin-top: auto;
  padding-top: 18px;
  border-top: 1px solid var(--workspace-border);
}
.profile {
  display: flex;
  align-items: center;
  gap: 12px;
}
.profile__avatar {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  background: var(--workspace-accent);
  color: #fff;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
}
.profile__meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 0.9rem;
}
.profile__meta span {
  color: var(--workspace-muted);
  font-size: 0.8rem;
}
.inventory-main,
.notes-main {
  background: var(--workspace-bg);
  display: flex;
  flex-direction: column;
  gap: 24px;
  padding: 32px 40px;
}
.inventory-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 24px;
}
.inventory-header__title {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.inventory-header__title h1 {
  margin: 0;
  font-size: 1.9rem;
}
.inventory-header__title span {
  font-size: 0.95rem;
  color: var(--workspace-muted);
}
.inventory-header__actions {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.inventory-header__search {
  position: relative;
  width: 260px;
}
.inventory-header__search[hidden] {
  display: none !important;
}
.inventory-header__search input {
  width: 100%;
  border: 1px solid var(--workspace-border);
  border-radius: 12px;
  padding: 10px 14px;
  font-size: 0.95rem;
  background: var(--workspace-surface);
  color: var(--workspace-text);
}
.inventory-header__search input::placeholder {
  color: var(--workspace-muted);
}
.inventory-header__buttons {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.inventory-tabs {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 8px;
}
.inventory-tab {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 12px;
  border: 1px solid var(--workspace-border);
  background: var(--workspace-surface);
  cursor: pointer;
  transition: background 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
  min-width: 200px;
}
.inventory-tab__icon {
  font-size: 1.25rem;
}
.inventory-tab__body {
  display: flex;
  flex-direction: column;
  gap: 4px;
  align-items: flex-start;
}
.inventory-tab__label {
  font-weight: 600;
}
.inventory-tab__meta {
  font-size: 0.8rem;
  color: var(--workspace-muted);
}
.inventory-tab:hover {
  border-color: rgba(37, 99, 235, 0.4);
}
.inventory-tab.is-active {
  background: var(--workspace-accent);
  color: #fff;
  border-color: var(--workspace-accent);
  box-shadow: 0 14px 30px -20px rgba(37, 99, 235, 0.5);
}
.inventory-tab.is-active .inventory-tab__meta {
  color: rgba(255, 255, 255, 0.85);
}
.inventory-main__messages {
  min-height: 24px;
}
.inventory-main__body {
  display: flex;
  flex-direction: column;
  gap: 32px;
}
.inventory-view {
  display: none;
}
.inventory-view--active {
  display: block;
}
.inventory-dashboard {
  display: flex;
  flex-direction: column;
  gap: 28px;
}
.inventory-dashboard__stats {
  display: grid;
  gap: 18px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}
.stat-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 18px 20px;
  border-radius: 14px;
  border: 1px solid var(--workspace-border);
  background: var(--workspace-surface);
}
.stat-card__icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.3rem;
  background: var(--workspace-accent-soft);
  color: var(--workspace-accent);
}
.stat-card__meta {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.stat-card__label {
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--workspace-muted);
}
.stat-card__value {
  font-size: 1.6rem;
  font-weight: 600;
  color: var(--workspace-text);
}
.stat-card--success .stat-card__icon {
  background: rgba(34, 197, 94, 0.18);
  color: #15803d;
}
.stat-card--warning .stat-card__icon {
  background: rgba(234, 179, 8, 0.18);
  color: #b45309;
}
.stat-card--info .stat-card__icon {
  background: rgba(14, 165, 233, 0.18);
  color: #0369a1;
}
.inventory-dashboard__activity {
  border: 1px solid var(--workspace-border);
  background: var(--workspace-surface);
  border-radius: 14px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 18px;
}
.inventory-dashboard__section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--workspace-muted);
}
.inventory-dashboard__section-header h2 {
  margin: 0;
  font-size: 1.2rem;
  color: var(--workspace-text);
}
.inventory-activity-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.inventory-activity-list__item {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 16px;
  align-items: center;
  padding: 14px 16px;
  border-radius: 12px;
  border: 1px solid var(--workspace-border);
  background: rgba(15, 23, 42, 0.02);
}
.inventory-activity-list__item--empty {
  justify-content: center;
  text-align: center;
  color: var(--workspace-muted);
  font-style: italic;
}
.inventory-activity-list__badge {
  font-size: 0.75rem;
  font-weight: 700;
  padding: 6px 12px;
  border-radius: 999px;
  min-width: 56px;
  text-align: center;
}
.inventory-activity-list__badge--in {
  background: #dcfce7;
  color: #166534;
}
.inventory-activity-list__badge--out {
  background: #fee2e2;
  color: #b91c1c;
}
.inventory-activity-list__meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.inventory-activity-list__details {
  font-size: 0.85rem;
  color: var(--workspace-muted);
}
.inventory-activity-list__status {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--workspace-muted);
}
.inventory-filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
  justify-content: space-between;
  align-items: flex-end;
}
.inventory-filter-bar__filters {
  display: flex;
  gap: 16px;
  align-items: flex-end;
}
.inventory-filter-bar__filters label {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 0.85rem;
  color: var(--workspace-muted);
}
.inventory-filter-bar__filters select {
  border: 1px solid var(--workspace-border);
  border-radius: 12px;
  padding: 10px 14px;
  background: var(--workspace-surface);
  color: var(--workspace-text);
}
.inventory-filter-bar__actions {
  display: flex;
  gap: 10px;
  align-items: center;
}
.inventory-table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid var(--workspace-border);
  border-radius: 14px;
  overflow: hidden;
  background: var(--workspace-surface);
}
.inventory-table th,
.inventory-table td {
  padding: 16px 20px;
  text-align: left;
  border-bottom: 1px solid var(--workspace-border);
}
.inventory-table thead {
  background: rgba(15, 23, 42, 0.04);
}
.inventory-table tbody tr {
  transition: background 0.12s ease;
}
.inventory-table tbody tr:hover {
  background: rgba(15, 23, 42, 0.02);
}
.inventory-table tbody tr:last-child td {
  border-bottom: none;
}
.inventory-table--compact th,
.inventory-table--compact td {
  padding: 14px 16px;
}
.col-qty {
  width: 90px;
}
.col-actions {
  width: 180px;
}
.item-heading {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.qty-cell {
  font-weight: 600;
}
.action-buttons {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.actions-cell {
  text-align: right;
}
.badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  background: rgba(15, 23, 42, 0.06);
  color: var(--workspace-muted);
}
.badge-muted {
  background: rgba(15, 23, 42, 0.08);
  color: var(--workspace-muted);
}
.muted {
  color: var(--workspace-muted);
  font-size: 0.85rem;
}
.small {
  font-size: 0.75rem;
}
.chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 0.8rem;
  font-weight: 600;
  background: rgba(15, 23, 42, 0.06);
  color: var(--workspace-text);
}
.chip-in {
  background: #dcfce7;
  color: #15803d;
}
.chip-out {
  background: #fee2e2;
  color: #b91c1c;
}
.tag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
  background: rgba(15, 23, 42, 0.08);
  color: var(--workspace-muted);
}
.tag.status-signed,
.tag.status-approved,
.tag.status-completed {
  background: #dcfce7;
  color: #166534;
}
.tag.status-pending,
.tag.status-in_transit,
.tag.status-in-transit {
  background: #fef3c7;
  color: #b45309;
}
.tag.status-cancelled,
.tag.status-rejected,
.tag.status-archived {
  background: #fee2e2;
  color: #b91c1c;
}
.inventory-documents {
  display: grid;
  gap: 18px;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
}
.inventory-document-card {
  border: 1px solid var(--workspace-border);
  background: var(--workspace-surface);
  border-radius: 14px;
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  transition: transform 0.15s ease, border-color 0.15s ease;
}
.inventory-document-card:hover {
  transform: translateY(-2px);
  border-color: var(--workspace-accent);
}
.inventory-document-card__icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: var(--workspace-accent-soft);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.6rem;
}
.inventory-document-card__meta {
  font-size: 0.85rem;
  color: var(--workspace-muted);
}
.inventory-document-card__item {
  font-size: 0.9rem;
  color: var(--workspace-text);
}
.inventory-document-card__footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.inventory-documents__empty {
  border: 1px dashed var(--workspace-border);
  border-radius: 14px;
  padding: 24px;
  text-align: center;
  color: var(--workspace-muted);
  background: rgba(15, 23, 42, 0.02);
}
.movement-files {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.movement-actions {
  display: flex;
  flex-direction: column;
  gap: 8px;
  align-items: flex-start;
}
.file-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px;
  border-radius: 999px;
  background: rgba(37, 99, 235, 0.12);
  color: var(--workspace-accent);
  font-size: 0.8rem;
}
.flash {
  margin-bottom: 0;
}
.flash-error {
  background: #fee2e2;
  border: 1px solid #fca5a5;
  color: #b91c1c;
  padding: 12px 16px;
  border-radius: 12px;
}
.modal {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.45);
  display: grid;
  place-items: center;
  padding: 1.5rem;
  z-index: 60;
}
.modal[hidden] {
  display: none;
}
.modal__dialog {
  background: var(--workspace-surface);
  border-radius: 16px;
  box-shadow: 0 30px 60px -35px rgba(15, 23, 42, 0.5);
  min-width: min(520px, 100%);
  max-width: 880px;
}
.modal__dialog--wide {
  max-width: 960px;
}
.modal__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  padding: 1.25rem 1.5rem 1rem;
  border-bottom: 1px solid var(--workspace-border);
}
.modal__header h3 {
  margin: 0;
}
.modal__close {
  border: none;
  background: transparent;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--workspace-muted);
}
.modal__body {
  padding: 1.25rem 1.5rem;
  display: grid;
  gap: 1rem;
}
.modal__body--history {
  padding: 1rem 1.5rem 1.5rem;
}
.modal__body label {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  font-size: 0.85rem;
  color: var(--workspace-text);
}
.modal__body input,
.modal__body select,
.modal__body textarea {
  border: 1px solid var(--workspace-border);
  border-radius: 12px;
  padding: 0.65rem 0.75rem;
  font-size: 0.95rem;
  background: var(--workspace-surface);
  color: var(--workspace-text);
}
.modal__footer {
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--workspace-border);
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
}
.bulk-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.bulk-row {
  display: grid;
  gap: 1rem;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  padding: 1rem;
  border: 1px solid var(--workspace-border);
  border-radius: 12px;
  background: rgba(15, 23, 42, 0.02);
}
.movement-wrapper {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.movement-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.movement-list li {
  border: 1px solid var(--workspace-border);
  border-radius: 12px;
  padding: 1rem;
  background: rgba(15, 23, 42, 0.02);
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.movement-main {
  display: flex;
  align-items: center;
  gap: 10px;
}
.movement-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 10px 14px;
  border-radius: 12px;
  border: 1px solid transparent;
  cursor: pointer;
  font-weight: 600;
  font-size: 0.95rem;
}
.btn.primary {
  background: var(--workspace-accent);
  color: #fff;
}
.btn.muted {
  background: rgba(15, 23, 42, 0.05);
  color: var(--workspace-text);
  border-color: rgba(15, 23, 42, 0.08);
}
.empty-row {
  text-align: center;
  padding: 32px;
  color: var(--workspace-muted);
}
.empty-row--search[hidden] {
  display: none;
}
@media (max-width: 1100px) {
  .inventory-shell {
    grid-template-columns: minmax(0, 1fr);
  }
  .inventory-sidebar {
    flex-direction: row;
    overflow-x: auto;
    gap: 16px;
    flex-wrap: wrap;
  }
  .inventory-sidebar__footer {
    width: 100%;
    margin-top: 0;
    padding-top: 8px;
    border-top: none;
  }
}
@media (max-width: 900px) {
  .inventory-main {
    padding: 28px 24px;
  }
  .inventory-header {
    flex-direction: column;
    align-items: flex-start;
  }
  .inventory-header__actions {
    width: 100%;
    justify-content: space-between;
  }
  .inventory-header__search {
    width: 100%;
  }
  .inventory-header__buttons {
    width: 100%;
    justify-content: flex-start;
  }
  .actions-cell {
    text-align: left;
  }
  .action-buttons {
    justify-content: flex-start;
  }
}
@media (max-width: 640px) {
  .inventory-tabs {
    flex-direction: column;
  }
  .inventory-tab {
    width: 100%;
  }
  .inventory-table {
    min-width: 100%;
  }
  .modal__dialog {
    min-width: 100%;
  }
}
  </style>
</head>
<body>
<div class="inventory-shell notes-shell">
  <aside class="inventory-sidebar notes-sidebar">
    <div class="brand">
      <div class="brand__title"><span class="icon">📦</span>Inventory workspace</div>
      <div class="brand__subtitle">Signed in as <?php echo sanitize($currentUserEmail !== '' ? $currentUserEmail : $currentUserName); ?></div>
    </div>

    <?php if ($canManage): ?>
      <button type="button" class="button button--full" data-modal-open="modal-add">New item</button>
    <?php endif; ?>

    <div class="inventory-sidebar__card">
      <div class="inventory-sidebar__card-title">Snapshot</div>
      <ul class="inventory-sidebar__metrics">
        <?php foreach ($dashboardStats as $stat): ?>
          <li>
            <span class="label"><?php echo sanitize($stat['label']); ?></span>
            <strong><?php echo sanitize($stat['value']); ?></strong>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>

    <div class="inventory-sidebar__section">
      <div class="inventory-sidebar__heading">Quick actions</div>
      <div class="stack">
        <?php if ($canManage): ?>
          <button type="button" class="button button--ghost" data-modal-open="modal-bulk-add">Bulk add items</button>
          <button type="button" class="button button--ghost" data-modal-open="modal-bulk-move">Bulk movement</button>
        <?php endif; ?>
        <a class="button button--subtle" href="inventory_diag.php">Inventory diagnostics</a>
      </div>
    </div>

    <div class="inventory-sidebar__footer">
      <a class="button button--ghost button--full" href="index.php">← Return to dashboard</a>
    </div>

  </aside>

  <main class="inventory-main notes-main">
    <header class="inventory-header">
      <div class="inventory-header__title">
        <h1 id="inventory-view-title">Dashboard</h1>
        <span id="inventory-view-subtitle">Overview of your inventory system</span>
      </div>
      <div class="inventory-header__actions">
        <div class="inventory-header__search" data-inventory-search>
          <input type="search" id="inventory-search" placeholder="Search items by name, SKU or location…" autocomplete="off">
        </div>
        <div class="inventory-header__buttons">
          <button type="button" class="button button--subtle" id="inventory-export-btn">Export</button>
          <?php if ($canManage): ?>
            <button type="button" class="button" id="inventory-primary-action" data-modal-open="modal-add">Quick action</button>
          <?php endif; ?>
        </div>
      </div>
    </header>

    <nav class="inventory-tabs" role="tablist">
      <?php foreach ($navItems as $index => $item): ?>
        <button
          type="button"
          role="tab"
          class="inventory-tab<?php echo $index === 0 ? ' is-active' : ''; ?>"
          data-view-target="<?php echo sanitize($item['id']); ?>"
          data-subtitle="<?php echo sanitize($item['subtitle']); ?>"
          data-add-label="<?php echo sanitize($item['add_label']); ?>"
          data-add-target="<?php echo sanitize($item['add_target']); ?>"
        >
          <span class="inventory-tab__icon" aria-hidden="true"><?php echo $item['icon']; ?></span>
          <span class="inventory-tab__body">
            <span class="inventory-tab__label"><?php echo sanitize($item['label']); ?></span>
            <span class="inventory-tab__meta"><?php echo sanitize($item['subtitle']); ?></span>
          </span>
        </button>
      <?php endforeach; ?>
    </nav>

    <div class="inventory-main__messages">
      <?php flash_message(); ?>
      <?php if ($errors): ?>
        <div class="flash flash-error"><?php echo sanitize(implode(' ', $errors)); ?></div>
      <?php endif; ?>
    </div>

    <div class="inventory-main__body">
      <section class="inventory-view inventory-view--active" data-view="dashboard">
        <div class="inventory-dashboard">
          <div class="inventory-dashboard__stats">
            <?php foreach ($dashboardStats as $stat): ?>
              <article class="stat-card <?php echo sanitize($stat['class']); ?>">
                <div class="stat-card__icon" aria-hidden="true"><?php echo $stat['icon']; ?></div>
                <div class="stat-card__meta">
                  <span class="stat-card__label"><?php echo sanitize($stat['label']); ?></span>
                  <strong class="stat-card__value"><?php echo sanitize($stat['value']); ?></strong>
                </div>
              </article>
            <?php endforeach; ?>
          </div>

          <div class="inventory-dashboard__activity">
            <header class="inventory-dashboard__section-header">
              <h2>Recent activity</h2>
              <span><?php echo number_format(count($recentMovements)); ?> events</span>
            </header>
            <ul class="inventory-activity-list">
              <?php foreach ($recentMovements as $movement): ?>
                <?php
                  $direction = ($movement['direction'] ?? 'in') === 'out' ? 'out' : 'in';
                  $movementItem = $movement['item'] ?? null;
                  $itemName = $movementItem ? (string)$movementItem['name'] : 'Item #' . (int)$movement['item_id'];
                  $sectorFrom = $movement['source_sector_id'] !== null ? inventory_sector_name((array)$sectorOptions, $movement['source_sector_id']) : '';
                  $sectorTo   = $movement['target_sector_id'] !== null ? inventory_sector_name((array)$sectorOptions, $movement['target_sector_id']) : '';
                ?>
                <li class="inventory-activity-list__item">
                  <div class="inventory-activity-list__badge inventory-activity-list__badge--<?php echo $direction; ?>">
                    <?php echo strtoupper($direction); ?>
                  </div>
                  <div class="inventory-activity-list__meta">
                    <strong><?php echo sanitize($itemName); ?></strong>
                    <span class="inventory-activity-list__details">
                      <?php echo sanitize(inventory_format_datetime($movement['ts'] ?? '')); ?> ·
                      <?php if ($sectorFrom !== '' || $sectorTo !== ''): ?>
                        <?php echo $sectorFrom !== '' ? sanitize($sectorFrom) : 'Unassigned'; ?> → <?php echo $sectorTo !== '' ? sanitize($sectorTo) : 'Unassigned'; ?>
                      <?php else: ?>
                        Internal movement
                      <?php endif; ?>
                    </span>
                  </div>
                  <div class="inventory-activity-list__status">
                    <?php echo ucfirst((string)($movement['transfer_status'] ?? 'signed')); ?> · <?php echo (int)$movement['amount']; ?> units
                  </div>
                </li>
              <?php endforeach; ?>
              <?php if (!$recentMovements): ?>
                <li class="inventory-activity-list__item inventory-activity-list__item--empty">
                  <span>No recent activity captured.</span>
                </li>
              <?php endif; ?>
            </ul>
          </div>
        </div>
      </section>

      <section class="inventory-view" data-view="inventory">
        <div class="inventory-filter-bar">
          <form method="get" class="inventory-filter-bar__filters" autocomplete="off">
            <label>
              <span>Sector</span>
              <select name="sector" <?php echo $isRoot ? '' : 'disabled'; ?>>
                <option value="all" <?php echo ($sectorFilter === '' || $sectorFilter === 'all') ? 'selected' : ''; ?>>All</option>
                <option value="null" <?php echo $sectorFilter === 'null' ? 'selected' : ''; ?>>Unassigned</option>
                <?php foreach ((array)$sectorOptions as $sector): ?>
                  <option value="<?php echo (int)$sector['id']; ?>" <?php echo ((string)$sector['id'] === (string)$sectorFilter) ? 'selected' : ''; ?>>
                    <?php echo sanitize((string)$sector['name']); ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </label>
            <div class="inventory-filter-bar__actions">
              <?php if ($isRoot): ?>
                <button class="button button--subtle" type="submit">Apply</button>
                <a class="button button--ghost" href="inventory.php">Reset</a>
              <?php else: ?>
                <span class="muted small">Filtering limited to your sector.</span>
              <?php endif; ?>
            </div>
          </form>
          <?php if ($canManage): ?>
            <div class="inventory-filter-bar__quick">
              <button class="button button--ghost" type="button" data-modal-open="modal-bulk-add">Bulk add</button>
              <button class="button button--ghost" type="button" data-modal-open="modal-bulk-move">Bulk movement</button>
            </div>
          <?php endif; ?>
        </div>

        <div class="inventory-table-wrapper">
          <table class="inventory-table">
            <thead>
              <tr>
                <th>Item</th>
                <th class="col-qty">Qty</th>
                <th>Sector</th>
                <th>Location</th>
                <th class="col-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($items as $item): ?>
                <?php
                  $itemId = (int)$item['id'];
                  $searchHaystack = strtolower(trim((string)$item['name'] . ' ' . ($item['sku'] ?? '') . ' ' . ($item['location'] ?? '')));
                ?>
                <tr data-item-row data-item-id="<?php echo $itemId; ?>" data-search-haystack="<?php echo sanitize($searchHaystack); ?>">
                  <td>
                    <div class="item-heading">
                      <strong><?php echo sanitize((string)$item['name']); ?></strong>
                      <span class="muted">SKU: <?php echo !empty($item['sku']) ? sanitize((string)$item['sku']) : '—'; ?></span>
                    </div>
                  </td>
                  <td class="qty-cell"><?php echo (int)$item['quantity']; ?></td>
                  <td>
                    <?php
                      $sn = sector_name_by_id((array)$sectorOptions, $item['sector_id']);
                      echo $sn !== '' ? sanitize($sn) : '<span class="badge badge-muted">Unassigned</span>';
                    ?>
                  </td>
                  <td><?php echo !empty($item['location']) ? sanitize((string)$item['location']) : '<em class="muted">—</em>'; ?></td>
                  <td class="actions-cell">
                    <div class="action-buttons">
                      <button class="button button--subtle button--tiny" data-modal-open="modal-history-<?php echo $itemId; ?>">History</button>
                      <?php if ($canManage && ($isRoot || (int)$item['sector_id'] === (int)$userSectorId)): ?>
                        <button class="button button--subtle button--tiny" data-modal-open="modal-edit-<?php echo $itemId; ?>">Edit</button>
                        <button class="button button--tiny" data-modal-open="modal-move-<?php echo $itemId; ?>">Move</button>
                      <?php endif; ?>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
              <?php if ($items): ?>
                <tr class="empty-row empty-row--search" hidden>
                  <td colspan="5">No items match your search.</td>
                </tr>
              <?php endif; ?>
              <?php if (empty($items)): ?>
                <tr class="empty-row">
                  <td colspan="5">No items found for the selected filter.</td>
                </tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </section>

      <section class="inventory-view" data-view="transfers">
        <div class="inventory-transfers">
          <div class="inventory-table-wrapper">
            <table class="inventory-table inventory-table--compact">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Item</th>
                  <th>Direction</th>
                  <th>Amount</th>
                  <th>Route</th>
                  <th>Status</th>
                  <th>Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($allMovements as $movement): ?>
                  <?php
                    $movementId = (int)$movement['id'];
                    $direction  = ($movement['direction'] ?? 'in') === 'out' ? 'Out' : 'In';
                    $movementItem = $movement['item'] ?? null;
                    $itemName = $movementItem ? (string)$movementItem['name'] : 'Item #' . (int)$movement['item_id'];
                    $sectorFrom = $movement['source_sector_id'] !== null ? inventory_sector_name((array)$sectorOptions, $movement['source_sector_id']) : '';
                    $sectorTo   = $movement['target_sector_id'] !== null ? inventory_sector_name((array)$sectorOptions, $movement['target_sector_id']) : '';
                    $attachments = $movementFiles[$movementId] ?? [];
                  ?>
                  <tr>
                    <td><?php echo $movementId; ?></td>
                    <td><?php echo sanitize($itemName); ?></td>
                    <td><span class="chip <?php echo strtolower($direction) === 'out' ? 'chip-out' : 'chip-in'; ?>"><?php echo $direction; ?></span></td>
                    <td><?php echo (int)$movement['amount']; ?></td>
                    <td><?php echo $sectorFrom !== '' ? sanitize($sectorFrom) : '—'; ?> → <?php echo $sectorTo !== '' ? sanitize($sectorTo) : '—'; ?></td>
                    <td><span class="tag status-<?php echo sanitize((string)$movement['transfer_status']); ?>"><?php echo ucfirst((string)$movement['transfer_status']); ?></span></td>
                    <td><?php echo sanitize(inventory_format_datetime($movement['ts'] ?? '')); ?></td>
                    <td>
                      <div class="movement-actions">
                        <?php if ($attachments): ?>
                          <div class="movement-files">
                            <?php foreach ($attachments as $file): ?>
                              <?php $displayLabel = inventory_format_file_label($file, (array)$sectorOptions); ?>
                              <a class="file-pill" href="<?php echo sanitize((string)$file['file_url']); ?>" target="_blank" rel="noopener">📎 <?php echo sanitize($displayLabel); ?></a>
                            <?php endforeach; ?>
                          </div>
                        <?php else: ?>
                          <span class="muted small">No attachments</span>
                        <?php endif; ?>
                        <a class="button button--tiny" href="transfer_pdf.php?movement_id=<?php echo $movementId; ?>" target="_blank" rel="noopener">Transfer paper</a>
                      </div>
                    </td>
                  </tr>
                <?php endforeach; ?>
                <?php if (!$allMovements): ?>
                  <tr class="empty-row">
                    <td colspan="8">No transfer records available.</td>
                  </tr>
                <?php endif; ?>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section class="inventory-view" data-view="documents">
        <div class="inventory-documents">
          <?php foreach ($documentsList as $document): ?>
            <?php
              $movement = $document['movement'];
              $itemRow = $document['item'];
              $itemName = $itemRow ? (string)$itemRow['name'] : 'Item #' . (int)($movement['item_id'] ?? $document['movement_id']);
            ?>
            <article class="inventory-document-card">
              <div class="inventory-document-card__icon" aria-hidden="true">📄</div>
              <h3><?php echo sanitize($document['label']); ?></h3>
              <p class="inventory-document-card__meta">PDF · <?php echo sanitize(inventory_format_datetime($document['uploaded_at'] ?? '')); ?></p>
              <p class="inventory-document-card__item">Movement #<?php echo (int)$document['movement_id']; ?> · <?php echo sanitize($itemName); ?></p>
              <div class="inventory-document-card__footer">
                <span class="tag status-<?php echo sanitize((string)($movement['transfer_status'] ?? 'signed')); ?>"><?php echo ucfirst((string)($movement['transfer_status'] ?? 'signed')); ?></span>
                <a class="button button--tiny" href="<?php echo sanitize((string)$document['url']); ?>" target="_blank" rel="noopener">Open PDF</a>
              </div>
            </article>
          <?php endforeach; ?>
          <?php if (!$documentsList): ?>
            <div class="inventory-documents__empty">No documents uploaded yet.</div>
          <?php endif; ?>
        </div>
      </section>
    </div>
  </main>
</div>

<?php if ($canManage): ?>
  <div class="modal" id="modal-add" hidden>
    <div class="modal__dialog">
      <header class="modal__header">
        <h3>Add Item</h3>
        <button class="modal__close" data-modal-close>&times;</button>
      </header>
      <form method="post" class="modal__body" autocomplete="off">
        <label>Name
          <input type="text" name="name" required>
        </label>
        <label>SKU
          <input type="text" name="sku">
        </label>
        <label>Initial Quantity
          <input type="number" name="quantity" min="0" value="0">
        </label>
        <label>Location
          <input type="text" name="location" placeholder="Shelf, cabinet...">
        </label>
        <?php if ($isRoot): ?>
          <label>Sector
            <select name="sector_id">
              <option value="null">Unassigned</option>
              <?php foreach ((array)$sectorOptions as $sector): ?>
                <option value="<?php echo (int)$sector['id']; ?>"><?php echo sanitize((string)$sector['name']); ?></option>
              <?php endforeach; ?>
            </select>
          </label>
        <?php endif; ?>
        <footer class="modal__footer">
          <input type="hidden" name="action" value="create_item">
          <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
          <button class="btn primary" type="submit">Save</button>
        </footer>
      </form>
    </div>
  </div>

  <div class="modal" id="modal-bulk-add" hidden>
    <div class="modal__dialog modal__dialog--wide">
      <header class="modal__header">
        <h3>Bulk Add Items</h3>
        <button class="modal__close" data-modal-close>&times;</button>
      </header>
      <form method="post" class="modal__body" autocomplete="off">
        <div class="bulk-grid" data-bulk-container>
          <div class="bulk-row" data-template>
            <label>Name
              <input type="text" name="bulk[name][]" required>
            </label>
            <label>SKU
              <input type="text" name="bulk[sku][]">
            </label>
            <label>Quantity
              <input type="number" name="bulk[quantity][]" min="0" value="0">
            </label>
            <label>Location
              <input type="text" name="bulk[location][]">
            </label>
            <?php if ($isRoot): ?>
              <label>Sector
                <select name="bulk[sector_id][]">
                  <option value="null">Unassigned</option>
                  <?php foreach ((array)$sectorOptions as $sector): ?>
                    <option value="<?php echo (int)$sector['id']; ?>"><?php echo sanitize((string)$sector['name']); ?></option>
                  <?php endforeach; ?>
                </select>
              </label>
            <?php else: ?>
              <input type="hidden" name="bulk[sector_id][]" value="<?php echo (int)$userSectorId; ?>">
            <?php endif; ?>
          </div>
        </div>
        <button class="btn secondary" type="button" data-add-row>+ Add another row</button>
        <footer class="modal__footer">
          <input type="hidden" name="action" value="bulk_create_items">
          <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
          <button class="btn primary" type="submit">Import</button>
        </footer>
      </form>
    </div>
  </div>

  <div class="modal" id="modal-bulk-move" hidden>
    <div class="modal__dialog modal__dialog--wide">
      <header class="modal__header">
        <h3>Bulk Movement</h3>
        <button class="modal__close" data-modal-close>&times;</button>
      </header>
      <form method="post" class="modal__body" autocomplete="off">
        <div class="bulk-grid" data-bulk-move-container>
          <div class="bulk-row" data-template>
            <label>Item
              <select name="move[item_id][]">
                <option value="">Select item…</option>
                <?php foreach ($items as $row): ?>
                  <option value="<?php echo (int)$row['id']; ?>"><?php echo sanitize((string)$row['name']); ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label>Direction
              <select name="move[direction][]">
                <option value="in">In</option>
                <option value="out">Out</option>
              </select>
            </label>
            <label>Amount
              <input type="number" name="move[amount][]" min="1" value="1">
            </label>
            <label>Target Sector
              <select name="move[target_sector_id][]">
                <option value="">None</option>
                <option value="null">Unassigned</option>
                <?php foreach ((array)$sectorOptions as $sector): ?>
                  <option value="<?php echo (int)$sector['id']; ?>"><?php echo sanitize((string)$sector['name']); ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label>Reason
              <input type="text" name="move[reason][]">
            </label>
            <label>Notes
              <input type="text" name="move[notes][]" placeholder="Optional details">
            </label>
            <label>Target Location
              <input type="text" name="move[target_location][]" placeholder="Shelf, room…">
            </label>
            <label class="checkbox">
              <input type="checkbox" name="move[requires_signature][]" value="1">
              Require signatures
            </label>
          </div>
        </div>
        <button class="btn secondary" type="button" data-add-move-row>+ Add another row</button>
        <footer class="modal__footer">
          <input type="hidden" name="action" value="bulk_move_stock">
          <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
          <button class="btn primary" type="submit">Record Movements</button>
        </footer>
      </form>
    </div>
  </div>

  <?php foreach ($items as $item): ?>
    <div class="modal" id="modal-history-<?php echo (int)$item['id']; ?>" hidden>
      <div class="modal__dialog modal__dialog--wide">
        <header class="modal__header">
          <h3>History for <?php echo sanitize((string)$item['name']); ?></h3>
          <button class="modal__close" data-modal-close>&times;</button>
        </header>
        <div class="modal__body modal__body--history">
          <div class="movement-wrapper">
            <div class="movement-header">
              <h4>Movement Log</h4>
            </div>
            <ul class="movement-list">
              <?php
                $historyList = $movementsByItem[(int)$item['id']] ?? [];
              ?>
              <?php foreach ($historyList as $movement): ?>
                <?php
                  $movementId = (int)$movement['id'];
                  $direction  = ($movement['direction'] ?? 'in') === 'out' ? 'out' : 'in';
                  $chipClass  = $direction === 'out' ? 'chip-out' : 'chip-in';
                  $sectorFrom = $movement['source_sector_id'] !== null ? inventory_sector_name((array)$sectorOptions, $movement['source_sector_id']) : '';
                  $sectorTo   = $movement['target_sector_id'] !== null ? inventory_sector_name((array)$sectorOptions, $movement['target_sector_id']) : '';
                  $attachments = $movementFiles[$movementId] ?? [];
                  $tokens = $movementTokens[$movementId] ?? [];
                ?>
                <li>
                  <div class="movement-main">
                    <span class="chip <?php echo $chipClass; ?>"><?php echo strtoupper($direction); ?></span>
                    <strong><?php echo (int)$movement['amount']; ?></strong>
                    <span class="muted small"><?php echo sanitize((string)$movement['ts']); ?></span>
                  </div>
                  <div class="movement-meta">
                    <?php if (!empty($movement['reason'])): ?>
                      <span class="tag">Reason: <?php echo sanitize((string)$movement['reason']); ?></span>
                    <?php endif; ?>
                    <?php if (!empty($movement['notes'])): ?>
                      <span class="tag">Notes: <?php echo sanitize((string)$movement['notes']); ?></span>
                    <?php endif; ?>
                    <?php if ($sectorFrom !== '' || $sectorTo !== ''): ?>
                      <span class="tag">Route: <?php echo $sectorFrom !== '' ? sanitize($sectorFrom) : '—'; ?> → <?php echo $sectorTo !== '' ? sanitize($sectorTo) : '—'; ?></span>
                    <?php endif; ?>
                    <?php if (!empty($movement['transfer_form_url'])): ?>
                      <a class="tag tag-link" href="<?php echo sanitize((string)$movement['transfer_form_url']); ?>" target="_blank" rel="noopener">
                        <span aria-hidden="true">📄</span> Transfer PDF
                      </a>
                    <?php endif; ?>
                    <?php if ($tokens): ?>
                      <?php $tokenRow = end($tokens); ?>
                      <span class="tag">QR expires <?php echo sanitize((string)$tokenRow['expires_at']); ?></span>
                    <?php endif; ?>
                    <span class="tag status-<?php echo sanitize((string)$movement['transfer_status']); ?>">Status: <?php echo ucfirst((string)$movement['transfer_status']); ?></span>
                  </div>
                  <?php if ($attachments): ?>
                    <div class="movement-files">
                      <?php foreach ($attachments as $file): ?>
                        <?php $displayLabel = inventory_format_file_label($file, (array)$sectorOptions); ?>
                        <a class="file-pill" href="<?php echo sanitize((string)$file['file_url']); ?>" target="_blank" rel="noopener">
                          📎 <?php echo sanitize($displayLabel); ?>
                        </a>
                      <?php endforeach; ?>
                    </div>
                  <?php endif; ?>
                  <?php if ($canManage): ?>
                    <button class="btn tiny" data-modal-open="modal-upload-<?php echo $movementId; ?>">Upload Paper Trail</button>
                  <?php endif; ?>
                </li>
              <?php endforeach; ?>
              <?php if (empty($historyList)): ?>
                <li class="muted small">No movements yet.</li>
              <?php endif; ?>
            </ul>
          </div>
        </div>
      </div>
    </div>
    <div class="modal" id="modal-edit-<?php echo (int)$item['id']; ?>" hidden>
      <div class="modal__dialog">
        <header class="modal__header">
          <h3>Edit Item</h3>
          <button class="modal__close" data-modal-close>&times;</button>
        </header>
        <form method="post" class="modal__body" autocomplete="off">
          <label>Name
            <input type="text" name="name" value="<?php echo sanitize((string)$item['name']); ?>" required>
          </label>
          <label>SKU
            <input type="text" name="sku" value="<?php echo sanitize((string)($item['sku'] ?? '')); ?>">
          </label>
          <label>Location
            <input type="text" name="location" value="<?php echo sanitize((string)($item['location'] ?? '')); ?>">
          </label>
          <?php if ($isRoot): ?>
            <label>Sector
              <select name="sector_id">
                <option value="null" <?php echo $item['sector_id'] === null ? 'selected':''; ?>>Unassigned</option>
                <?php foreach ((array)$sectorOptions as $sector): ?>
                  <option value="<?php echo (int)$sector['id']; ?>" <?php echo ((string)$item['sector_id'] === (string)$sector['id']) ? 'selected' : ''; ?>>
                    <?php echo sanitize((string)$sector['name']); ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </label>
          <?php endif; ?>
          <footer class="modal__footer">
            <input type="hidden" name="action" value="update_item">
            <input type="hidden" name="item_id" value="<?php echo (int)$item['id']; ?>">
            <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
            <button class="btn primary" type="submit">Save</button>
          </footer>
        </form>
      </div>
    </div>

    <div class="modal" id="modal-move-<?php echo (int)$item['id']; ?>" hidden>
      <div class="modal__dialog">
        <header class="modal__header">
          <h3>Move <?php echo sanitize((string)$item['name']); ?></h3>
          <button class="modal__close" data-modal-close>&times;</button>
        </header>
        <form method="post" class="modal__body" autocomplete="off">
          <label>Direction
            <select name="direction">
              <option value="in">In</option>
              <option value="out">Out</option>
            </select>
          </label>
          <label>Amount
            <input type="number" name="amount" min="1" value="1">
          </label>
          <label>Reason
            <input type="text" name="reason" placeholder="Reason for movement">
          </label>
          <label>Notes
            <input type="text" name="notes" placeholder="Optional notes">
          </label>
          <label>Target Sector
            <select name="target_sector_id">
              <option value="">None</option>
              <option value="null">Unassigned</option>
              <?php foreach ((array)$sectorOptions as $sector): ?>
                <option value="<?php echo (int)$sector['id']; ?>"><?php echo sanitize((string)$sector['name']); ?></option>
              <?php endforeach; ?>
            </select>
          </label>
          <label>Target Location
            <input type="text" name="target_location" placeholder="Shelf, room…">
          </label>
          <label class="checkbox">
            <input type="checkbox" name="requires_signature" value="1" checked>
            Require signatures &amp; PDF trail
          </label>
          <footer class="modal__footer">
            <input type="hidden" name="action" value="move_stock">
            <input type="hidden" name="item_id" value="<?php echo (int)$item['id']; ?>">
            <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
            <button class="btn primary" type="submit">Record Movement</button>
          </footer>
        </form>
      </div>
    </div>
  <?php endforeach; ?>

  <?php foreach ($movementsByItem as $itemId => $movementList): ?>
    <?php foreach ($movementList as $movement): ?>
      <?php $movementId = (int)$movement['id']; ?>
      <div class="modal" id="modal-upload-<?php echo $movementId; ?>" hidden>
        <div class="modal__dialog">
          <header class="modal__header">
            <h3>Upload Paper Trail</h3>
            <button class="modal__close" data-modal-close>&times;</button>
          </header>
          <form method="post" class="modal__body" enctype="multipart/form-data" autocomplete="off">
            <label>File
              <input type="file" name="movement_file" accept="image/*,application/pdf" required>
            </label>
            <label>Label
              <input type="text" name="label" placeholder="e.g. Signed form page 1">
            </label>
            <label>Type
              <select name="kind">
                <option value="signature">Signature</option>
                <option value="photo">Photo</option>
                <option value="other">Other</option>
              </select>
            </label>
            <footer class="modal__footer">
              <input type="hidden" name="action" value="upload_movement_file">
              <input type="hidden" name="movement_id" value="<?php echo $movementId; ?>">
              <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
              <button class="btn primary" type="submit">Upload</button>
            </footer>
          </form>
        </div>
      </div>
    <?php endforeach; ?>
  <?php endforeach; ?>
<?php endif; ?>


<script>
(function(){
  const modalButtons = document.querySelectorAll('[data-modal-open]');
  modalButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-modal-open');
      const modal = document.getElementById(id);
      if (modal) {
        modal.hidden = false;
      }
    });
  });
  document.querySelectorAll('[data-modal-close]').forEach(btn => {
    btn.addEventListener('click', () => {
      const modal = btn.closest('.modal');
      if (modal) modal.hidden = true;
    });
  });
  document.addEventListener('click', evt => {
    if (evt.target.classList && evt.target.classList.contains('modal')) {
      evt.target.hidden = true;
    }
  });

  const cloneRow = (container, template) => {
    const clone = template.cloneNode(true);
    clone.querySelectorAll('input').forEach(input => {
      if (input.type === 'text') input.value = '';
      if (input.type === 'number') input.value = input.getAttribute('min') || 0;
      if (input.type === 'checkbox') input.checked = false;
    });
    clone.querySelectorAll('select').forEach(select => { select.selectedIndex = 0; });
    container.appendChild(clone);
  };

  const bulkContainer = document.querySelector('[data-bulk-container]');
  const bulkTemplate = bulkContainer ? bulkContainer.querySelector('[data-template]') : null;
  document.querySelectorAll('[data-add-row]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (bulkContainer && bulkTemplate) {
        cloneRow(bulkContainer, bulkTemplate);
      }
    });
  });

  const moveContainer = document.querySelector('[data-bulk-move-container]');
  const moveTemplate = moveContainer ? moveContainer.querySelector('[data-template]') : null;
  document.querySelectorAll('[data-add-move-row]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (moveContainer && moveTemplate) {
        cloneRow(moveContainer, moveTemplate);
      }
    });
  });

  const shell = document.querySelector('.inventory-shell');
  if (shell) {
    const viewButtons = shell.querySelectorAll('[data-view-target]');
    const views = shell.querySelectorAll('[data-view]');
    const titleEl = document.getElementById('inventory-view-title');
    const subtitleEl = document.getElementById('inventory-view-subtitle');
    const primaryAction = document.getElementById('inventory-primary-action');
    const searchContainer = shell.querySelector('[data-inventory-search]');
    const searchInput = document.getElementById('inventory-search');
    const searchRows = Array.from(document.querySelectorAll('[data-item-row]'));
    const emptySearchRow = document.querySelector('.empty-row--search');

    const applySearch = () => {
      if (!searchInput) {
        return;
      }
      const query = searchInput.value.trim().toLowerCase();
      let matchCount = 0;
      searchRows.forEach(row => {
        const haystack = (row.getAttribute('data-search-haystack') || '').toLowerCase();
        const matches = query === '' || haystack.indexOf(query) !== -1;
        row.hidden = !matches;
        if (matches) {
          matchCount++;
        }
      });
      if (emptySearchRow) {
        emptySearchRow.hidden = matchCount !== 0;
      }
    };

    if (searchInput) {
      searchInput.addEventListener('input', applySearch);
      applySearch();
    }

    const toggleSearch = (isInventory) => {
      if (searchContainer) {
        searchContainer.hidden = !isInventory;
      }
      if (!isInventory && searchInput) {
        searchInput.blur();
      }
    };

    const activateView = (targetId) => {
      viewButtons.forEach(btn => {
        const isMatch = btn.getAttribute('data-view-target') === targetId;
        btn.classList.toggle('is-active', isMatch);
        if (isMatch && titleEl && subtitleEl) {
          const labelSpan = btn.querySelector('.inventory-tab__label') || btn.querySelector('span:last-child');
          titleEl.textContent = labelSpan ? labelSpan.textContent.trim() : btn.textContent.trim();
          subtitleEl.textContent = btn.getAttribute('data-subtitle') || '';
        }
        if (isMatch && primaryAction) {
          const addLabel = btn.getAttribute('data-add-label') || '';
          const addTarget = btn.getAttribute('data-add-target') || '';
          if (addLabel.trim() === '' || addTarget.trim() === '') {
            primaryAction.hidden = true;
            primaryAction.removeAttribute('data-modal-open');
          } else {
            primaryAction.hidden = false;
            primaryAction.textContent = addLabel;
            primaryAction.setAttribute('data-modal-open', addTarget);
          }
        }
      });

      views.forEach(view => {
        const isMatch = view.getAttribute('data-view') === targetId;
        view.classList.toggle('inventory-view--active', isMatch);
      });

      if (primaryAction && primaryAction.hidden) {
        primaryAction.blur();
      }

      toggleSearch(targetId === 'inventory');
      if (targetId === 'inventory' && searchInput) {
        applySearch();
      }
    };

    viewButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-view-target');
        if (targetId) {
          activateView(targetId);
        }
      });
    });

    const initialButton = shell.querySelector('[data-view-target].is-active');
    if (initialButton) {
      activateView(initialButton.getAttribute('data-view-target'));
    } else {
      activateView('dashboard');
    }
  }
})();
</script>
</body>
</html>
