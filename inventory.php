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

$title = 'Inventory';
include __DIR__ . '/includes/header.php';
?>
<div class="inventory-app">
  <aside class="inventory-app__sidebar">
    <div class="inventory-app__brand">
      <div class="inventory-app__brand-icon">INV</div>
      <div class="inventory-app__brand-meta">
        <strong>Inventory Suite</strong>
        <span>Operations Control</span>
      </div>
    </div>
    <nav class="inventory-app__nav">
      <?php foreach ($navItems as $index => $item): ?>
        <button
          type="button"
          class="inventory-app__nav-item<?php echo $index === 0 ? ' is-active' : ''; ?>"
          data-view-target="<?php echo sanitize($item['id']); ?>"
          data-subtitle="<?php echo sanitize($item['subtitle']); ?>"
          data-add-label="<?php echo sanitize($item['add_label']); ?>"
          data-add-target="<?php echo sanitize($item['add_target']); ?>"
        >
          <span class="inventory-app__nav-icon" aria-hidden="true"><?php echo $item['icon']; ?></span>
          <span><?php echo sanitize($item['label']); ?></span>
        </button>
      <?php endforeach; ?>
    </nav>
    <div class="inventory-app__sidebar-footer">
      <div class="inventory-app__user-avatar" aria-hidden="true"><?php echo sanitize($currentUserInitials); ?></div>
      <div class="inventory-app__user-meta">
        <strong><?php echo sanitize($currentUserName !== '' ? $currentUserName : 'John Doe'); ?></strong>
        <span><?php echo sanitize($currentUserRoleLabel !== '' ? $currentUserRoleLabel : 'Manager'); ?></span>
      </div>
    </div>
  </aside>

  <div class="inventory-app__main">
    <header class="inventory-app__header">
      <div>
        <h1 id="inventory-view-title">Dashboard</h1>
        <p id="inventory-view-subtitle">Overview of your inventory system</p>
      </div>
      <div class="inventory-app__header-actions">
        <button type="button" class="btn btn-ghost" id="inventory-export-btn">Export</button>
        <?php if ($canManage): ?>
          <button type="button" class="btn primary" id="inventory-primary-action" data-modal-open="modal-add">Quick Action</button>
        <?php endif; ?>
      </div>
    </header>

    <div class="inventory-app__alerts">
      <?php flash_message(); ?>
      <?php if ($errors): ?>
        <div class="flash flash-error"><?php echo sanitize(implode(' ', $errors)); ?></div>
      <?php endif; ?>
    </div>

    <div class="inventory-app__content">
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
              <h2>Recent Activity</h2>
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
                      <?php echo (int)$movement['amount']; ?> units · <?php echo sanitize(inventory_format_datetime($movement['ts'] ?? '')); ?>
                    </span>
                    <span class="inventory-activity-list__details">
                      Route: <?php echo $sectorFrom !== '' ? sanitize($sectorFrom) : '—'; ?> → <?php echo $sectorTo !== '' ? sanitize($sectorTo) : '—'; ?>
                    </span>
                  </div>
                  <span class="inventory-activity-list__status status-<?php echo sanitize((string)$movement['transfer_status']); ?>">
                    <?php echo ucfirst((string)$movement['transfer_status']); ?>
                  </span>
                </li>
              <?php endforeach; ?>
              <?php if (!$recentMovements): ?>
                <li class="inventory-activity-list__item inventory-activity-list__item--empty">No recent movements.</li>
              <?php endif; ?>
            </ul>
          </div>
        </div>
      </section>

      <section class="inventory-view" data-view="inventory">
        <div class="inventory-filter-bar">
          <div class="inventory-filter-bar__search">
            <input type="search" id="inventory-search" placeholder="Search items by name, SKU or location…" autocomplete="off">
            <span class="inventory-filter-bar__search-icon" aria-hidden="true">🔍</span>
          </div>
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
                <button class="btn primary" type="submit">Apply</button>
                <a class="btn secondary" href="inventory.php">Reset</a>
              <?php else: ?>
                <span class="muted small">Filtering limited to your sector.</span>
              <?php endif; ?>
            </div>
          </form>
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
                      <button class="btn tiny secondary" data-modal-open="modal-history-<?php echo $itemId; ?>">History</button>
                      <?php if ($canManage && ($isRoot || (int)$item['sector_id'] === (int)$userSectorId || $isRoot)): ?>
                        <button class="btn tiny secondary" data-modal-open="modal-edit-<?php echo $itemId; ?>">Edit</button>
                        <button class="btn tiny" data-modal-open="modal-move-<?php echo $itemId; ?>">Move</button>
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
                    <td>
                      <span class="chip <?php echo strtolower($direction) === 'out' ? 'chip-out' : 'chip-in'; ?>">
                        <?php echo $direction; ?>
                      </span>
                    </td>
                    <td><?php echo (int)$movement['amount']; ?></td>
                    <td>
                      <?php echo $sectorFrom !== '' ? sanitize($sectorFrom) : '—'; ?> → <?php echo $sectorTo !== '' ? sanitize($sectorTo) : '—'; ?>
                    </td>
                    <td>
                      <span class="tag status-<?php echo sanitize((string)$movement['transfer_status']); ?>"><?php echo ucfirst((string)$movement['transfer_status']); ?></span>
                    </td>
                    <td><?php echo sanitize(inventory_format_datetime($movement['ts'] ?? '')); ?></td>
                    <td>
                      <?php if ($attachments): ?>
                        <div class="movement-files">
                          <?php foreach ($attachments as $file): ?>
                            <?php $displayLabel = inventory_format_file_label($file, (array)$sectorOptions); ?>
                            <a class="file-pill" href="<?php echo sanitize((string)$file['file_url']); ?>" target="_blank" rel="noopener">
                              📎 <?php echo sanitize($displayLabel); ?>
                            </a>
                          <?php endforeach; ?>
                        </div>
                      <?php else: ?>
                        <span class="muted small">—</span>
                      <?php endif; ?>
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
              <p class="inventory-document-card__meta">
                PDF · <?php echo sanitize(inventory_format_datetime($document['uploaded_at'] ?? '')); ?>
              </p>
              <p class="inventory-document-card__item">Movement #<?php echo (int)$document['movement_id']; ?> · <?php echo sanitize($itemName); ?></p>
              <div class="inventory-document-card__footer">
                <span class="tag status-<?php echo sanitize((string)($movement['transfer_status'] ?? 'signed')); ?>">
                  <?php echo ucfirst((string)($movement['transfer_status'] ?? 'signed')); ?>
                </span>
                <a class="btn tiny" href="<?php echo sanitize((string)$document['url']); ?>" target="_blank" rel="noopener">Open PDF</a>
              </div>
            </article>
          <?php endforeach; ?>
          <?php if (!$documentsList): ?>
            <div class="inventory-documents__empty">No documents uploaded yet.</div>
          <?php endif; ?>
        </div>
      </section>
    </div>
  </div>
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
<style>
:root {
  color-scheme: only light;
  --inventory-bg: #f9fafb;
  --inventory-sidebar: #ffffff;
  --inventory-surface: #ffffff;
  --inventory-border: #e5e7eb;
  --inventory-text: #111827;
  --inventory-muted: #6b7280;
  --inventory-accent: #2563eb;
  --inventory-accent-soft: rgba(37, 99, 235, 0.12);
  --inventory-radius: 14px;
  --inventory-danger: #dc2626;
}
body {
  background: var(--inventory-bg);
  color: var(--inventory-text);
}
a {
  color: inherit;
  text-decoration: none;
}
.inventory-app {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 0;
  min-height: calc(100vh - 140px);
  background: transparent;
  border-radius: var(--inventory-radius);
  overflow: hidden;
  box-shadow: 0 24px 48px -38px rgba(15, 23, 42, 0.18);
}
.inventory-app__sidebar {
  background: var(--inventory-sidebar);
  border-right: 1px solid var(--inventory-border);
  display: flex;
  flex-direction: column;
  gap: 24px;
  padding: 28px 22px;
}
.inventory-app__brand {
  display: flex;
  align-items: center;
  gap: 12px;
}
.inventory-app__brand-icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: var(--inventory-accent-soft);
  color: var(--inventory-accent);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  letter-spacing: 0.08em;
}
.inventory-app__brand-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 0.9rem;
  color: var(--inventory-muted);
}
.inventory-app__brand-meta strong {
  color: var(--inventory-text);
  font-weight: 600;
  font-size: 1rem;
}
.inventory-app__nav {
  display: flex;
  flex-direction: column;
  gap: 8px;
  flex: 1;
  overflow-y: auto;
  padding-right: 6px;
}
.inventory-app__nav-item {
  border: 1px solid transparent;
  background: transparent;
  border-radius: var(--inventory-radius);
  padding: 12px 16px;
  text-align: left;
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 0.95rem;
  color: var(--inventory-text);
  cursor: pointer;
  transition: background 0.15s ease, border-color 0.15s ease, transform 0.15s ease;
}
.inventory-app__nav-item:hover {
  background: var(--inventory-accent-soft);
  border-color: rgba(37, 99, 235, 0.18);
  transform: translateX(2px);
}
.inventory-app__nav-item.is-active {
  background: var(--inventory-accent);
  color: #fff;
  border-color: var(--inventory-accent);
  box-shadow: 0 12px 26px -18px rgba(37, 99, 235, 0.45);
}
.inventory-app__nav-icon {
  font-size: 1.25rem;
}
.inventory-app__sidebar-footer {
  margin-top: auto;
  border-top: 1px solid var(--inventory-border);
  padding-top: 18px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.inventory-app__user-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: var(--inventory-accent);
  color: #fff;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
}
.inventory-app__user-meta {
  display: flex;
  flex-direction: column;
  font-size: 0.85rem;
  color: var(--inventory-muted);
}
.inventory-app__user-meta strong {
  color: var(--inventory-text);
  font-weight: 600;
}
.inventory-app__main {
  background: var(--inventory-bg);
  display: flex;
  flex-direction: column;
}
.inventory-app__header {
  padding: 28px 32px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  background: var(--inventory-surface);
  border-bottom: 1px solid var(--inventory-border);
}
.inventory-app__header h1 {
  margin: 0;
  font-size: 1.8rem;
}
.inventory-app__header p {
  margin: 6px 0 0;
  color: var(--inventory-muted);
  font-size: 0.95rem;
}
.inventory-app__header-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}
.btn-ghost {
  background: transparent;
  border: 1px solid var(--inventory-border);
  color: var(--inventory-text);
  padding: 10px 18px;
  border-radius: var(--inventory-radius);
  cursor: pointer;
  transition: background 0.15s ease;
}
.btn-ghost:hover {
  background: rgba(15, 23, 42, 0.04);
}
.inventory-app__alerts {
  padding: 0 32px;
}
.inventory-app__content {
  flex: 1;
  padding: 32px 32px 40px;
  overflow-y: auto;
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
  display: grid;
  gap: 24px;
}
.inventory-dashboard__stats {
  display: grid;
  gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}
.stat-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 18px 20px;
  border-radius: var(--inventory-radius);
  background: var(--inventory-surface);
  border: 1px solid var(--inventory-border);
  box-shadow: none;
}
.stat-card__icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.3rem;
  color: var(--inventory-accent);
  background: var(--inventory-accent-soft);
}
.stat-card__meta {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.stat-card__label {
  font-size: 0.75rem;
  color: var(--inventory-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.stat-card__value {
  font-size: 1.55rem;
  color: var(--inventory-text);
  font-weight: 600;
}
.stat-card--success .stat-card__icon {
  background: rgba(34, 197, 94, 0.15);
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
  background: var(--inventory-surface);
  border-radius: var(--inventory-radius);
  padding: 24px;
  border: 1px solid var(--inventory-border);
}
.inventory-dashboard__section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 18px;
  color: var(--inventory-muted);
}
.inventory-dashboard__section-header h2 {
  margin: 0;
  color: var(--inventory-text);
  font-size: 1.15rem;
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
  padding: 14px 16px;
  border-radius: var(--inventory-radius);
  border: 1px solid var(--inventory-border);
  background: rgba(15, 23, 42, 0.02);
  align-items: center;
}
.inventory-activity-list__item--empty {
  text-align: center;
  color: var(--inventory-muted);
  font-style: italic;
}
.inventory-activity-list__badge {
  font-size: 0.75rem;
  font-weight: 700;
  padding: 6px 12px;
  border-radius: 999px;
  text-align: center;
  min-width: 56px;
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
  color: var(--inventory-muted);
}
.inventory-activity-list__status {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--inventory-muted);
}
.inventory-filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: flex-end;
  margin-bottom: 20px;
}
.inventory-filter-bar__search {
  position: relative;
  flex: 1;
  min-width: 220px;
}
.inventory-filter-bar__search input {
  width: 100%;
  padding: 12px 16px 12px 46px;
  border-radius: var(--inventory-radius);
  border: 1px solid var(--inventory-border);
  background: var(--inventory-surface);
  color: var(--inventory-text);
}
.inventory-filter-bar__search input:focus {
  outline: 2px solid rgba(37, 99, 235, 0.28);
  outline-offset: 1px;
}
.inventory-filter-bar__search-icon {
  position: absolute;
  left: 16px;
  top: 50%;
  transform: translateY(-50%);
  pointer-events: none;
  font-size: 0.95rem;
  color: var(--inventory-muted);
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
  color: var(--inventory-muted);
}
.inventory-filter-bar__filters select {
  padding: 10px 14px;
  border-radius: var(--inventory-radius);
  border: 1px solid var(--inventory-border);
  background: var(--inventory-surface);
  color: var(--inventory-text);
}
.inventory-filter-bar__actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.inventory-table-wrapper {
  background: var(--inventory-surface);
  border-radius: var(--inventory-radius);
  border: 1px solid var(--inventory-border);
  overflow: hidden;
}
.inventory-table {
  width: 100%;
  border-collapse: collapse;
}
.inventory-table th,
.inventory-table td {
  padding: 16px 20px;
  text-align: left;
  border-bottom: 1px solid var(--inventory-border);
}
.inventory-table thead th {
  font-size: 0.78rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--inventory-muted);
  background: rgba(15, 23, 42, 0.03);
}
.inventory-table tbody tr:hover {
  background: rgba(37, 99, 235, 0.06);
}
.inventory-table--compact td,
.inventory-table--compact th {
  padding: 14px 16px;
}
.col-qty {
  width: 90px;
}
.col-actions {
  width: 220px;
}
.item-heading {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.muted {
  color: var(--inventory-muted);
  font-size: 0.85rem;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 0.75rem;
  background: rgba(15, 23, 42, 0.06);
}
.badge-muted {
  background: rgba(148, 163, 184, 0.18);
  color: var(--inventory-muted);
}
.qty-cell {
  font-weight: 600;
}
.actions-cell {
  text-align: right;
}
.action-buttons {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
}
.empty-row,
.empty-row--search {
  text-align: center;
  color: var(--inventory-muted);
  font-style: italic;
}
.chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.chip-in {
  background: #dcfce7;
  color: #166534;
}
.chip-out {
  background: #fee2e2;
  color: #b91c1c;
}
.tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.05);
  font-size: 0.75rem;
  color: var(--inventory-muted);
}
.tag-link {
  background: rgba(37, 99, 235, 0.12);
  color: var(--inventory-accent);
}
.status-pending {
  background: rgba(250, 204, 21, 0.2);
  color: #92400e;
}
.status-signed,
.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #166534;
}
.status-cancelled {
  background: rgba(248, 113, 113, 0.2);
  color: #b91c1c;
}
.movement-files {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}
.file-pill {
  padding: 6px 10px;
  border-radius: var(--inventory-radius);
  background: rgba(37, 99, 235, 0.08);
  font-size: 0.78rem;
  color: var(--inventory-accent);
}
.inventory-transfers {
  display: flex;
  flex-direction: column;
  gap: 24px;
}
.inventory-documents {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 20px;
}
.inventory-document-card {
  background: var(--inventory-surface);
  border: 1px solid var(--inventory-border);
  border-radius: var(--inventory-radius);
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  transition: transform 0.15s ease, border-color 0.15s ease;
}
.inventory-document-card:hover {
  transform: translateY(-2px);
  border-color: var(--inventory-accent);
}
.inventory-document-card__icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: var(--inventory-accent-soft);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 1.4rem;
}
.inventory-document-card__meta,
.inventory-document-card__item {
  font-size: 0.85rem;
  color: var(--inventory-muted);
}
.inventory-document-card__footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.inventory-documents__empty {
  padding: 40px;
  text-align: center;
  color: var(--inventory-muted);
  border: 1px dashed var(--inventory-border);
  border-radius: var(--inventory-radius);
  background: rgba(15, 23, 42, 0.02);
}
.modal {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.45);
  display: grid;
  place-items: center;
  padding: 1.5rem;
  z-index: 50;
}
.modal[hidden] {
  display: none;
}
.modal__dialog {
  background: var(--inventory-surface);
  border-radius: var(--inventory-radius);
  box-shadow: 0 24px 48px -32px rgba(15, 23, 42, 0.4);
  min-width: min(520px, 100%);
  max-width: 820px;
}
.modal__dialog--wide {
  max-width: 960px;
}
.modal__header {
  padding: 1.25rem 1.5rem 1rem;
  border-bottom: 1px solid var(--inventory-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}
.modal__header h3 {
  margin: 0;
}
.modal__close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--inventory-muted);
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
  gap: 0.35rem;
  font-size: 0.85rem;
  color: var(--inventory-text);
}
.modal__body input,
.modal__body select,
.modal__body textarea {
  border: 1px solid var(--inventory-border);
  border-radius: var(--inventory-radius);
  padding: 0.6rem 0.75rem;
  font-size: 0.9rem;
  background: var(--inventory-surface);
  color: var(--inventory-text);
}
.modal__footer {
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--inventory-border);
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
}
.movement-wrapper {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.movement-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
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
  border: 1px solid var(--inventory-border);
  border-radius: var(--inventory-radius);
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
.movement-main strong {
  font-size: 1.05rem;
  color: var(--inventory-text);
}
.movement-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.movement-wrapper .btn.tiny {
  align-self: flex-start;
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
  border: 1px dashed var(--inventory-border);
  border-radius: var(--inventory-radius);
  background: rgba(15, 23, 42, 0.02);
}
.checkbox {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
@media (max-width: 1080px) {
  .inventory-app {
    grid-template-columns: 1fr;
    min-height: auto;
  }
  .inventory-app__sidebar {
    border-right: none;
    border-bottom: 1px solid var(--inventory-border);
    flex-direction: row;
    align-items: flex-start;
    gap: 18px;
  }
  .inventory-app__nav {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 8px;
  }
  .inventory-app__nav-item {
    flex: 1 1 calc(50% - 8px);
  }
  .inventory-app__sidebar-footer {
    display: none;
  }
}
@media (max-width: 768px) {
  .inventory-app__header {
    flex-direction: column;
    align-items: flex-start;
    gap: 16px;
  }
  .inventory-app__header-actions {
    width: 100%;
    justify-content: flex-start;
  }
  .inventory-app__content {
    padding: 24px;
  }
  .inventory-filter-bar__filters {
    flex-wrap: wrap;
  }
  .inventory-filter-bar__actions {
    width: 100%;
  }
}
@media (max-width: 640px) {
  .inventory-app__nav-item {
    flex: 1 1 100%;
  }
  .inventory-table {
    min-width: 100%;
  }
  .actions-cell {
    text-align: left;
  }
  .action-buttons {
    justify-content: flex-start;
  }
  .modal__dialog {
    min-width: 100%;
  }
}
</style>

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

  const app = document.querySelector('.inventory-app');
  if (app) {
    const viewButtons = app.querySelectorAll('[data-view-target]');
    const views = app.querySelectorAll('[data-view]');
    const titleEl = document.getElementById('inventory-view-title');
    const subtitleEl = document.getElementById('inventory-view-subtitle');
    const primaryAction = document.getElementById('inventory-primary-action');
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

    const activateView = (targetId) => {
      viewButtons.forEach(btn => {
        const isMatch = btn.getAttribute('data-view-target') === targetId;
        btn.classList.toggle('is-active', isMatch);
        if (isMatch && titleEl && subtitleEl) {
          const labelSpan = btn.querySelector('span:last-child');
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

    const initialButton = app.querySelector('[data-view-target].is-active');
    if (initialButton) {
      activateView(initialButton.getAttribute('data-view-target'));
    } else {
      activateView('dashboard');
    }
  }
})();
</script>
<?php include __DIR__ . '/includes/footer.php'; ?>
