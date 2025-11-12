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
                    <?php if ($canManage && ($isRoot || (int)$item['sector_id'] === (int)$userSectorId || $isRoot)): ?>
                      <div class="action-buttons">
                        <button class="btn tiny secondary" data-modal-open="modal-edit-<?php echo $itemId; ?>">Edit</button>
                        <button class="btn tiny" data-modal-open="modal-move-<?php echo $itemId; ?>">Move</button>
                      </div>
                    <?php else: ?>
                      <span class="muted small">—</span>
                    <?php endif; ?>
                  </td>
                </tr>
                <tr class="movement-row" data-movement-row-for="<?php echo $itemId; ?>">
                  <td colspan="5">
                    <div class="movement-wrapper">
                      <div class="movement-header">
                        <h4>Movements</h4>
                      </div>
                      <ul class="movement-list">
                        <?php foreach ($movementsByItem[$itemId] ?? [] as $movement): ?>
                          <?php
                            $movementId = (int)$movement['id'];
                            $direction  = $movement['direction'] === 'out' ? 'out' : 'in';
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
                        <?php if (empty($movementsByItem[$itemId])): ?>
                          <li class="muted small">No movements yet.</li>
                        <?php endif; ?>
                      </ul>
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
                <?php echo sanitize(ucfirst((string)$document['kind'])); ?> · <?php echo sanitize(inventory_format_datetime($document['uploaded_at'] ?? '')); ?>
              </p>
              <p class="inventory-document-card__item">Movement #<?php echo (int)$document['movement_id']; ?> · <?php echo sanitize($itemName); ?></p>
              <div class="inventory-document-card__footer">
                <span class="tag status-<?php echo sanitize((string)($movement['transfer_status'] ?? 'signed')); ?>">
                  <?php echo ucfirst((string)($movement['transfer_status'] ?? 'signed')); ?>
                </span>
                <a class="btn tiny" href="<?php echo sanitize((string)$document['url']); ?>" target="_blank" rel="noopener">Open</a>
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
.inventory-app {
  display: flex;
  gap: 0;
  background: #f5f7fb;
  border-radius: 18px;
  overflow: hidden;
  min-height: 720px;
  box-shadow: 0 30px 60px -45px rgba(15, 23, 42, 0.35);
}

.inventory-app__sidebar {
  width: 260px;
  background: #ffffff;
  display: flex;
  flex-direction: column;
  border-right: 1px solid #e2e8f0;
}

.inventory-app__brand {
  padding: 24px 20px;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  align-items: center;
  gap: 12px;
}

.inventory-app__brand-icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: linear-gradient(135deg, #2563eb, #7c3aed);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.inventory-app__brand-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 0.85rem;
  color: #475569;
}

.inventory-app__brand-meta strong {
  color: #0f172a;
  font-size: 1rem;
}

.inventory-app__nav {
  padding: 18px 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex: 1;
  overflow-y: auto;
}

.inventory-app__nav-item {
  border: none;
  background: transparent;
  border-radius: 10px;
  padding: 12px 16px;
  text-align: left;
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 0.95rem;
  color: #334155;
  cursor: pointer;
  transition: background 0.2s ease, transform 0.2s ease;
}

.inventory-app__nav-item:hover {
  background: #edf2ff;
  transform: translateX(2px);
}

.inventory-app__nav-item.is-active {
  background: #2563eb;
  color: #fff;
  box-shadow: 0 14px 28px -20px rgba(37, 99, 235, 0.9);
}

.inventory-app__nav-icon {
  font-size: 1.3rem;
}

.inventory-app__sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid #e2e8f0;
  display: flex;
  align-items: center;
  gap: 12px;
}

.inventory-app__user-avatar {
  width: 40px;
  height: 40px;
  border-radius: 999px;
  background: #2563eb;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
}

.inventory-app__user-meta {
  display: flex;
  flex-direction: column;
  font-size: 0.85rem;
  color: #475569;
}

.inventory-app__user-meta strong {
  color: #0f172a;
}

.inventory-app__main {
  flex: 1;
  display: flex;
  flex-direction: column;
  background: linear-gradient(145deg, #f8fafc, #eef2ff);
}

.inventory-app__header {
  padding: 28px 32px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid rgba(148, 163, 184, 0.2);
}

.inventory-app__header h1 {
  margin: 0;
  font-size: 1.9rem;
  color: #0f172a;
}

.inventory-app__header p {
  margin: 6px 0 0;
  color: #64748b;
  font-size: 0.95rem;
}

.inventory-app__header-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}

.btn-ghost {
  background: transparent;
  border: 1px solid #cbd5e1;
  color: #0f172a;
  padding: 10px 18px;
  border-radius: 10px;
  cursor: pointer;
  transition: background 0.2s ease;
}

.btn-ghost:hover {
  background: rgba(148, 163, 184, 0.12);
}

.inventory-app__alerts {
  padding: 0 32px;
}

.inventory-app__content {
  flex: 1;
  padding: 32px;
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
  gap: 32px;
}

.inventory-dashboard__stats {
  display: grid;
  gap: 20px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px;
  border-radius: 18px;
  background: #ffffff;
  border: 1px solid rgba(37, 99, 235, 0.08);
  box-shadow: 0 24px 45px -36px rgba(15, 23, 42, 0.45);
}

.stat-card__icon {
  width: 48px;
  height: 48px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.4rem;
  color: #fff;
}

.stat-card__meta {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.stat-card__label {
  font-size: 0.85rem;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.stat-card__value {
  font-size: 1.6rem;
  color: #0f172a;
}

.stat-card--accent .stat-card__icon {
  background: linear-gradient(135deg, #2563eb, #1e3a8a);
}

.stat-card--success .stat-card__icon {
  background: linear-gradient(135deg, #22c55e, #16a34a);
}

.stat-card--warning .stat-card__icon {
  background: linear-gradient(135deg, #f59e0b, #d97706);
}

.stat-card--info .stat-card__icon {
  background: linear-gradient(135deg, #0ea5e9, #0284c7);
}

.inventory-dashboard__activity {
  background: #ffffff;
  border-radius: 18px;
  padding: 24px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  box-shadow: 0 24px 45px -38px rgba(15, 23, 42, 0.4);
}

.inventory-dashboard__section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
  color: #64748b;
}

.inventory-dashboard__section-header h2 {
  margin: 0;
  color: #0f172a;
}

.inventory-activity-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.inventory-activity-list__item {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 16px;
  padding: 16px;
  border-radius: 14px;
  border: 1px solid rgba(148, 163, 184, 0.22);
  background: #f8fafc;
  align-items: center;
}

.inventory-activity-list__item--empty {
  text-align: center;
  display: block;
  color: #64748b;
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
  color: #64748b;
}

.inventory-activity-list__status {
  font-size: 0.8rem;
  font-weight: 600;
}

.inventory-filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: flex-end;
  margin-bottom: 24px;
}

.inventory-filter-bar__search {
  position: relative;
  flex: 1;
  min-width: 220px;
}

.inventory-filter-bar__search input {
  width: 100%;
  padding: 12px 16px 12px 46px;
  border-radius: 12px;
  border: 1px solid #cbd5e1;
  background: #ffffff;
  color: #0f172a;
}

.inventory-filter-bar__search-icon {
  position: absolute;
  left: 16px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1rem;
  color: #94a3b8;
}

.inventory-filter-bar__filters {
  display: flex;
  gap: 16px;
  align-items: center;
}

.inventory-filter-bar__filters label {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 0.85rem;
  color: #475569;
}

.inventory-filter-bar__filters select {
  padding: 10px 14px;
  border-radius: 10px;
  border: 1px solid #cbd5e1;
  background: #ffffff;
  min-width: 180px;
}

.inventory-filter-bar__actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.inventory-table-wrapper {
  overflow-x: auto;
  background: #ffffff;
  border-radius: 18px;
  box-shadow: 0 24px 45px -38px rgba(15, 23, 42, 0.35);
  border: 1px solid rgba(148, 163, 184, 0.18);
}

.inventory-table {
  width: 100%;
  border-collapse: collapse;
  min-width: 760px;
}

.inventory-table th,
.inventory-table td {
  padding: 0.9rem 1.1rem;
  border-bottom: 1px solid #e2e8f0;
  text-align: left;
  vertical-align: top;
}

.inventory-table th {
  background: #f1f5f9;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: #64748b;
}

.inventory-table tbody tr:last-child td {
  border-bottom: none;
}

.col-qty {
  width: 80px;
  text-align: center;
}

.qty-cell {
  font-size: 1.15rem;
  font-weight: 700;
  text-align: center;
  color: #111827;
}

.col-actions,
.actions-cell {
  width: 160px;
  text-align: right;
}

.action-buttons {
  display: flex;
  gap: 0.4rem;
  justify-content: flex-end;
}

.item-heading {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.item-heading strong {
  font-size: 1.05rem;
  color: #0f172a;
}

.movement-row td {
  background: #f8fafc;
  padding: 0 1rem 1.2rem;
}

.movement-wrapper {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding-top: 1rem;
}

.movement-header h4 {
  margin: 0;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #0f172a;
}

.movement-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.movement-list li {
  background: #ffffff;
  border-radius: 12px;
  padding: 0.75rem;
  border: 1px solid #dce4f4;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.movement-main {
  display: flex;
  gap: 0.6rem;
  align-items: center;
}

.movement-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  font-size: 0.75rem;
  color: #475569;
}

.movement-files {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.tag {
  background: #e2e8f0;
  border-radius: 999px;
  padding: 0.2rem 0.6rem;
}

.tag-link {
  text-decoration: none;
  color: #1d4ed8;
  background: #e0e7ff;
}

.file-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.3rem 0.6rem;
  background: #ffffff;
  border-radius: 999px;
  border: 1px solid #cbd5f5;
  text-decoration: none;
  font-size: 0.75rem;
  color: #1d4ed8;
}

.file-pill:hover {
  background: #e0e7ff;
}

.chip {
  display: inline-block;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 700;
}

.chip-in {
  background: #dcfce7;
  color: #166534;
}

.chip-out {
  background: #fee2e2;
  color: #b91c1c;
}

.badge-muted {
  background: #e2e8f0;
  color: #475569;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
}

.status-pending {
  background: #fef08a;
  color: #854d0e;
}

.status-signed {
  background: #bbf7d0;
  color: #166534;
}

.status-cancelled {
  background: #fecaca;
  color: #b91c1c;
}

.status-in_transit {
  background: #fde68a;
  color: #92400e;
}

.status-completed {
  background: #d1fae5;
  color: #15803d;
}

.movement-wrapper .btn.tiny {
  align-self: flex-start;
}

.empty-row td {
  text-align: center;
  padding: 1.5rem;
  color: #64748b;
  font-style: italic;
}

.inventory-table--compact th,
.inventory-table--compact td {
  padding: 0.75rem 0.9rem;
}

.inventory-documents {
  display: grid;
  gap: 20px;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
}

.inventory-document-card {
  background: #ffffff;
  border-radius: 16px;
  padding: 20px;
  border: 1px solid rgba(148, 163, 184, 0.2);
  box-shadow: 0 24px 45px -40px rgba(15, 23, 42, 0.4);
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.inventory-document-card__icon {
  width: 52px;
  height: 52px;
  border-radius: 14px;
  background: #edf2ff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
}

.inventory-document-card__meta {
  margin: 0;
  color: #64748b;
  font-size: 0.85rem;
}

.inventory-document-card__item {
  margin: 0;
  color: #0f172a;
  font-size: 0.9rem;
}

.inventory-document-card__footer {
  margin-top: auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.inventory-documents__empty {
  grid-column: 1 / -1;
  text-align: center;
  padding: 32px;
  border-radius: 16px;
  background: #f8fafc;
  color: #64748b;
  font-style: italic;
}

.modal {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(15, 23, 42, 0.48);
  z-index: 1000;
  padding: 1.5rem;
}

.modal[hidden] {
  display: none;
}

.modal__dialog {
  background: #fff;
  border-radius: 16px;
  max-width: 520px;
  width: 100%;
  box-shadow: 0 30px 70px -40px rgba(15, 23, 42, 0.7);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal__dialog--wide {
  max-width: 880px;
}

.modal__header {
  padding: 1rem 1.25rem;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal__header h3 {
  margin: 0;
  font-size: 1.1rem;
}

.modal__close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: #334155;
}

.modal__body {
  padding: 1.25rem;
  display: grid;
  gap: 1rem;
}

.modal__body label {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  font-size: 0.85rem;
  color: #1f2937;
}

.modal__body input,
.modal__body select,
.modal__body textarea {
  border: 1px solid #cbd5e1;
  border-radius: 10px;
  padding: 0.6rem 0.75rem;
  font-size: 0.9rem;
}

.modal__footer {
  padding: 1rem 1.25rem;
  border-top: 1px solid #e2e8f0;
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
  border: 1px dashed #cbd5f5;
  border-radius: 12px;
  background: #f8fafc;
}

.checkbox {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

@media (max-width: 1080px) {
  .inventory-app {
    flex-direction: column;
  }

  .inventory-app__sidebar {
    width: 100%;
    flex-direction: row;
    align-items: center;
  }

  .inventory-app__nav {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 8px;
    padding: 12px;
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

  .inventory-activity-list__item {
    grid-template-columns: 1fr;
  }

  .modal {
    padding: 0.5rem;
  }

  .modal__dialog {
    max-height: 95vh;
    overflow: auto;
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
    const movementRowMap = new Map();

    searchRows.forEach(row => {
      const itemId = row.getAttribute('data-item-id');
      if (!itemId) {
        return;
      }
      const movementRow = document.querySelector(`[data-movement-row-for="${itemId}"]`);
      if (movementRow) {
        movementRowMap.set(itemId, movementRow);
      }
    });

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
        const itemId = row.getAttribute('data-item-id');
        if (itemId && movementRowMap.has(itemId)) {
          movementRowMap.get(itemId).hidden = !matches;
        }
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
