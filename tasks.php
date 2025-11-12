<?php
require_once __DIR__ . '/helpers.php';
require_login();
if (!can('view')) {
    http_response_code(403);
    exit('Forbidden');
}

$filters   = get_filter_values();
$page      = max(1, (int)($_GET['page'] ?? 1));
$perPage   = 30;
$sort      = $_GET['sort'] ?? 'id';       // changed default from created_at → id
$direction = $_GET['direction'] ?? 'DESC';
$total     = 0;

$tasks     = fetch_tasks($filters, $sort, $direction, $perPage, ($page - 1) * $perPage, $total);
$taskIds   = array_column($tasks, 'id');
$photos    = fetch_photos_for_tasks($taskIds);
$buildings = fetch_buildings();
$rooms     = $filters['building_id'] ? fetch_rooms_by_building($filters['building_id']) : [];
$exportRoomMeta = export_room_group_summary($filters);

$query = $_GET;
unset($query['page']);
$baseQuery = http_build_query(array_filter($query, fn($value) => $value !== '' && $value !== []));
$pages = (int)ceil($total / $perPage);

// For quick edit modal selects
$allStatuses   = get_statuses();   // array of status keys
$allPriorities = get_priorities(); // array of priority keys

// CSRF for the quick edit POST
$csrfName  = defined('CSRF_TOKEN_NAME') ? CSRF_TOKEN_NAME : '_csrf';
$csrfToken = csrf_token();

$title = 'Tasks';
include __DIR__ . '/includes/header.php';
?>

<section class="card">
  <div class="card-header">
    <h1>Tasks</h1>
    <div class="actions">
      <?php if (can('edit')): ?>
        <a class="btn primary" href="task_new.php">New Task</a>
      <?php endif; ?>
      <button class="btn" type="button" id="openExportModal">Export</button>
    </div>
  </div>

  <!-- Filters: mobile = stacked; desktop = compact multi-column via CSS -->
  <form method="get" class="filters">
    <label>Search
      <input type="text" name="search" value="<?php echo sanitize($filters['search']); ?>" placeholder="Title or description">
    </label>

    <label>Building
      <select name="building_id" data-room-source data-room-target="filter-room filter-room-from filter-room-to">
        <option value="">All</option>
        <?php foreach ($buildings as $building): ?>
          <option value="<?php echo $building['id']; ?>" <?php echo $filters['building_id'] == $building['id'] ? 'selected' : ''; ?>>
            <?php echo sanitize($building['name']); ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>

    <label>Room
      <select name="room_id" id="filter-room" data-room-placeholder="All">
        <option value="">All</option>
        <?php foreach ($rooms as $room): ?>
          <option value="<?php echo $room['id']; ?>" <?php echo $filters['room_id'] == $room['id'] ? 'selected' : ''; ?>>
            <?php echo sanitize($room['room_number'] . ($room['label'] ? ' - ' . $room['label'] : '')); ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>

    <label>Priority
      <select name="priority">
        <option value="">Any priority</option>
        <?php foreach ($allPriorities as $priority): ?>
          <option value="<?php echo $priority; ?>" <?php echo (($filters['priority'] ?? '') === $priority) ? 'selected' : ''; ?>>
            <?php echo sanitize(priority_label($priority)); ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>

    <label>Status
      <select name="status">
        <option value="">All</option>
        <?php foreach ($allStatuses as $status): ?>
          <option value="<?php echo $status; ?>" <?php echo $filters['status'] === $status ? 'selected' : ''; ?>>
            <?php echo sanitize(status_label($status)); ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>

    <label>Assigned To
      <input type="text" name="assigned_to" value="<?php echo sanitize($filters['assigned_to']); ?>">
    </label>

    <label>Room From
      <select name="room_from" id="filter-room-from" data-room-placeholder="Any" <?php echo $filters['building_id'] ? '' : 'disabled'; ?>>
        <option value="">Any</option>
        <?php foreach ($rooms as $room): ?>
          <option value="<?php echo $room['id']; ?>" <?php echo $filters['room_from'] == $room['id'] ? 'selected' : ''; ?>>
            <?php echo sanitize($room['room_number'] . ($room['label'] ? ' - ' . $room['label'] : '')); ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>

    <label>Room To
      <select name="room_to" id="filter-room-to" data-room-placeholder="Any" <?php echo $filters['building_id'] ? '' : 'disabled'; ?>>
        <option value="">Any</option>
        <?php foreach ($rooms as $room): ?>
          <option value="<?php echo $room['id']; ?>" <?php echo $filters['room_to'] == $room['id'] ? 'selected' : ''; ?>>
            <?php echo sanitize($room['room_number'] . ($room['label'] ? ' - ' . $room['label'] : '')); ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>

    <label>Due From
      <input type="date" name="due_from" value="<?php echo sanitize($filters['due_from']); ?>">
    </label>

    <label>Due To
      <input type="date" name="due_to" value="<?php echo sanitize($filters['due_to']); ?>">
    </label>

    <label>Has Photos
      <select name="has_photos">
        <option value="">Any</option>
        <option value="1" <?php echo $filters['has_photos'] === '1' ? 'selected' : ''; ?>>Yes</option>
        <option value="0" <?php echo $filters['has_photos'] === '0' ? 'selected' : ''; ?>>No</option>
      </select>
    </label>

    <div class="filter-actions">
      <button class="btn primary" type="submit">Apply</button>
      <a class="btn secondary" href="tasks.php">Reset</a>
    </div>
  </form>
</section>

<section class="card">
  <form id="taskListForm" method="get" action="export_pdf.php" target="_blank">
    <input type="hidden" name="selected" id="selectedTasks" value="">

    <!-- Add table--cards so mobile renders as cards (CSS switches under ~920px) -->
    <table class="table table-excel compact-rows table--cards">
      <thead>
        <tr>
          <th class="col-check">
            <input type="checkbox" id="toggle-all">
          </th>
          <th class="col-id">
            <a href="?<?php echo http_build_query(array_merge($query, ['sort' => 'id', 'direction' => $direction === 'ASC' ? 'DESC' : 'ASC'])); ?>">
              ID
            </a>
          </th>
          <th class="col-building">Building</th>
          <th class="col-room">
            <a href="?<?php echo http_build_query(array_merge($query, ['sort' => 'room', 'direction' => $direction === 'ASC' ? 'DESC' : 'ASC'])); ?>">
              Room
            </a>
          </th>
          <th class="col-title">Title</th>
          <th class="col-priority">
            <a href="?<?php echo http_build_query(array_merge($query, ['sort' => 'priority', 'direction' => $direction === 'ASC' ? 'DESC' : 'ASC'])); ?>">
              Priority
            </a>
          </th>
          <th class="col-assigned">Assigned To</th>
          <th class="col-status">Status</th>
          <th class="col-photos">Photos</th>
          <th class="col-actions"></th>
        </tr>
      </thead>

      <tbody>
        <?php if (!$tasks): ?>
          <tr>
            <td colspan="10" class="text-center muted">No tasks found.</td>
          </tr>
        <?php else: ?>
          <?php foreach ($tasks as $task): ?>
            <?php $taskPhotos = $photos[$task['id']] ?? []; ?>
            <tr data-task-id="<?php echo (int)$task['id']; ?>">
              <td class="col-check" data-label="Select">
                <input type="checkbox" class="task-checkbox" value="<?php echo $task['id']; ?>" data-room-id="<?php echo (int)$task['room_id']; ?>">
              </td>

              <td class="col-id" data-label="ID">#<?php echo (int)$task['id']; ?></td>

              <td class="col-building" data-label="Building">
                <?php echo sanitize($task['building_name']); ?>
              </td>

              <td class="col-room" data-label="Room">
                <?php echo sanitize($task['room_number'] . ($task['room_label'] ? ' - ' . $task['room_label'] : '')); ?>
              </td>

              <td class="col-title" data-label="Title">
                <a href="task_view.php?id=<?php echo (int)$task['id']; ?>">
                  <?php echo sanitize($task['title']); ?>
                </a>
              </td>

              <td class="col-priority" data-label="Priority">
                <span class="badge <?php echo priority_class($task['priority']); ?>">
                  <?php echo sanitize(priority_label($task['priority'])); ?>
                </span>
              </td>

              <td class="col-assigned" data-label="Assigned To">
                <?php echo sanitize($task['assigned_to'] ?? ''); ?>
              </td>

              <td class="col-status" data-label="Status">
                <span class="badge <?php echo status_class($task['status']); ?>">
                  <?php echo sanitize(status_label($task['status'])); ?>
                </span>
              </td>

              <td class="col-photos" data-label="Photos">
                <button
                  class="btn small js-view-photos"
                  type="button"
                  data-task-id="<?php echo (int)$task['id']; ?>"
                >
                  View photos<?php if (!empty($task['photo_count'])) echo ' ('.(int)$task['photo_count'].')'; ?>
                </button>
              </td>

              <td class="col-actions" data-label="Actions">
                <a class="btn small" href="task_edit.php?id=<?php echo (int)$task['id']; ?>">Edit</a>
                <?php if (can('edit')): ?>
                  <button
                    type="button"
                    class="btn small js-quick-edit"
                    data-task-id="<?php echo (int)$task['id']; ?>"
                    data-task-assigned="<?php echo sanitize($task['assigned_to'] ?? ''); ?>"
                    data-task-status="<?php echo sanitize($task['status']); ?>"
                    data-task-priority="<?php echo sanitize($task['priority']); ?>"
                  >Quick Edit</button>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
        <?php endif; ?>
      </tbody>
    </table>

  </form>

  <?php if ($pages > 1): ?>
    <div class="pagination">
      <?php for ($i = 1; $i <= $pages; $i++): ?>
        <a class="btn <?php echo $i === $page ? 'primary' : ''; ?>" href="?<?php echo http_build_query(array_merge($query, ['page' => $i])); ?>">
          <?php echo $i; ?>
        </a>
      <?php endfor; ?>
    </div>
  <?php endif; ?>
</section>

<!-- Export Modal -->
<div id="exportModal" class="photo-modal hidden" aria-hidden="true" data-export-meta='<?= json_encode([
    'filtered' => array_merge($exportRoomMeta, ['taskTotal' => (int)$total])
], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>'>
  <div class="photo-modal-backdrop" data-close-export></div>
  <div class="photo-modal-box" role="dialog" aria-modal="true" aria-labelledby="exportModalTitle">
    <div class="photo-modal-header">
      <h3 id="exportModalTitle">Export tasks</h3>
      <button class="close-btn" type="button" title="Close" data-close-export>&times;</button>
    </div>

    <form id="exportForm" class="photo-modal-body">
      <fieldset>
        <legend>Format</legend>
        <label class="radio-option">
          <input type="radio" name="format" value="pdf" checked>
          <span>PDF (with photos &amp; QR codes)</span>
        </label>
        <label class="radio-option">
          <input type="radio" name="format" value="excel">
          <span>Excel (XLSX with QR codes)</span>
        </label>
      </fieldset>

      <fieldset>
        <legend>Task range</legend>
        <label class="radio-option">
          <input type="radio" name="scope" value="filtered" id="exportScopeFiltered" checked>
          <span>All tasks matching current filters (<span id="exportFilteredCount"><?php echo number_format($total); ?></span>)</span>
        </label>
        <label class="radio-option">
          <input type="radio" name="scope" value="selected" id="exportScopeSelected" disabled>
          <span>Only selected tasks (<span id="exportSelectedCount">0</span>)</span>
        </label>
        <p class="muted hidden" id="exportSelectedHint">Select tasks in the table first.</p>
        <p class="muted hidden" id="exportRoomSummary"></p>
      </fieldset>

      <div class="form-actions">
        <button class="btn primary" type="submit">Download</button>
        <button class="btn secondary" type="button" data-close-export>Cancel</button>
      </div>
    </form>
  </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const form             = document.getElementById('taskListForm');
  const toggleAll        = document.getElementById('toggle-all');
  const exportBtn        = document.getElementById('openExportModal');
  const exportModal      = document.getElementById('exportModal');
  const exportForm       = document.getElementById('exportForm');
  const scopeFiltered    = document.getElementById('exportScopeFiltered');
  const scopeSelected    = document.getElementById('exportScopeSelected');
  const selectedField    = document.getElementById('selectedTasks');
  const selectedCountEl  = document.getElementById('exportSelectedCount');
  const filteredCountEl  = document.getElementById('exportFilteredCount');
  const selectedHint     = document.getElementById('exportSelectedHint');
  const closeControls    = exportModal ? Array.from(exportModal.querySelectorAll('[data-close-export]')) : [];
  const roomSummaryEl    = document.getElementById('exportRoomSummary');

  let exportMeta = {};
  if (exportModal) {
    try {
      exportMeta = JSON.parse(exportModal.getAttribute('data-export-meta') || '{}');
    } catch (err) {
      exportMeta = {};
    }
  }

  const baseQuery = <?php echo json_encode($baseQuery, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
  const endpoints = {
    pdf: 'export_table_pdf_wkhtml.php',
    excel: 'export_tasks_excel.php'
  };

  const taskCheckboxes = () => Array.from(document.querySelectorAll('.task-checkbox'));
  const selectedIds = () => taskCheckboxes().filter(cb => cb.checked).map(cb => cb.value);

  const currentScopeValue = () => {
    if (!exportForm) return 'filtered';
    const selectedScope = exportForm.querySelector('input[name="scope"]:checked');
    return selectedScope ? selectedScope.value : 'filtered';
  };

  function getFilteredRoomMeta() {
    const meta = (exportMeta && exportMeta.filtered) ? exportMeta.filtered : {};
    return {
      roomTotal: Number(meta.roomTotal || 0),
      multiRooms: Number(meta.multiRooms || 0),
      maxTasksPerRoom: Number(meta.maxTasksPerRoom || 0),
      taskTotal: Number(meta.taskTotal || 0),
    };
  }

  function computeSelectedRoomMeta() {
    const counts = {};
    taskCheckboxes().forEach((cb) => {
      if (!cb.checked) return;
      const roomId = cb.getAttribute('data-room-id') || '';
      if (roomId === '') return;
      counts[roomId] = (counts[roomId] || 0) + 1;
    });

    const roomIds = Object.keys(counts);
    let multiRooms = 0;
    let maxTasks = 0;
    let taskTotal = 0;

    roomIds.forEach((roomId) => {
      const count = counts[roomId];
      if (count > 1) multiRooms += 1;
      if (count > maxTasks) maxTasks = count;
      taskTotal += count;
    });

    return {
      roomTotal: roomIds.length,
      multiRooms,
      maxTasksPerRoom: maxTasks,
      taskTotal,
    };
  }

  function updateRoomSummary(scopeValue) {
    if (!roomSummaryEl) return;
    const scope = scopeValue || currentScopeValue();
    const meta = scope === 'selected' ? computeSelectedRoomMeta() : getFilteredRoomMeta();
    const multi = meta.multiRooms || 0;

    if (multi > 0) {
      const max = meta.maxTasksPerRoom || 0;
      const scopeLabel = scope === 'selected' ? 'selected tasks' : 'filtered tasks';
      const maxText = max > 1 ? ` (up to ${max} in one room)` : '';
      roomSummaryEl.textContent = `${multi} room${multi === 1 ? '' : 's'} within the ${scopeLabel} contain multiple tasks${maxText}. Those rooms will share a single QR code.`;
      roomSummaryEl.classList.remove('hidden');
    } else {
      roomSummaryEl.classList.add('hidden');
      roomSummaryEl.textContent = '';
    }
  }

  function updateSelectedState() {
    const allBoxes     = taskCheckboxes();
    const selected     = selectedIds();
    const selectedCount = selected.length;

    if (selectedCountEl) {
      selectedCountEl.textContent = selectedCount.toString();
    }

    if (filteredCountEl) {
      filteredCountEl.textContent = '<?php echo number_format($total); ?>';
    }

    if (toggleAll) {
      if (allBoxes.length === 0) {
        toggleAll.indeterminate = false;
        toggleAll.checked = false;
      } else {
        const allChecked = selectedCount === allBoxes.length;
        toggleAll.checked = allChecked;
        toggleAll.indeterminate = !allChecked && selectedCount > 0;
      }
    }

    if (scopeSelected) {
      const hasSelection = selectedCount > 0;
      scopeSelected.disabled = !hasSelection;
      if (!hasSelection && scopeSelected.checked && scopeFiltered) {
        scopeFiltered.checked = true;
      }
    }

    if (selectedHint) {
      selectedHint.classList.toggle('hidden', selectedCount > 0);
    }

    updateRoomSummary();

    return selected;
  }

  function openExportModal() {
    if (!exportModal) return;
    updateSelectedState();
    exportModal.classList.remove('hidden');
    exportModal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }

  function closeExportModal() {
    if (!exportModal) return;
    exportModal.classList.add('hidden');
    exportModal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  function buildAction(base, query) {
    if (!query) return base;
    return base.includes('?') ? base + '&' + query : base + '?' + query;
  }

  if (toggleAll) {
    toggleAll.addEventListener('change', () => {
      const boxes = taskCheckboxes();
      boxes.forEach(cb => { cb.checked = toggleAll.checked; });
      updateSelectedState();
    });
  }

  document.addEventListener('change', (event) => {
    const target = event.target;
    if (target && target.classList && target.classList.contains('task-checkbox')) {
      updateSelectedState();
    }
  });

  if (exportBtn) {
    exportBtn.addEventListener('click', openExportModal);
  }

  closeControls.forEach((btn) => {
    btn.addEventListener('click', closeExportModal);
  });

  if (exportModal) {
    exportModal.addEventListener('click', (event) => {
      if (event.target.classList.contains('photo-modal-backdrop')) {
        closeExportModal();
      }
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && exportModal && !exportModal.classList.contains('hidden')) {
      closeExportModal();
    }
  });

  if (exportForm) {
    exportForm.addEventListener('change', (event) => {
      if (event.target && event.target.name === 'scope') {
        updateRoomSummary(event.target.value);
      }
    });

    exportForm.addEventListener('submit', (event) => {
      event.preventDefault();

      const formatInput = exportForm.querySelector('input[name="format"]:checked');
      const scopeInput  = exportForm.querySelector('input[name="scope"]:checked');
      const format      = formatInput ? formatInput.value : '';
      const scope       = scopeInput ? scopeInput.value : 'filtered';

      if (!format || !endpoints[format]) {
        alert('Select an export format.');
        return;
      }

      const ids = selectedIds();
      if (scope === 'selected') {
        if (ids.length === 0) {
          alert('Select at least one task to export.');
          return;
        }
        if (selectedField) {
          selectedField.value = ids.join(',');
        }
      } else if (selectedField) {
        selectedField.value = '';
      }

      const action = buildAction(endpoints[format], baseQuery);
      if (form) {
        form.action = action;
        form.submit();
      }

      closeExportModal();
    });
  }

  // Initialize counts on load
  updateSelectedState();
  updateRoomSummary();
});
</script>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const modal     = document.getElementById('photoModal');
  const modalBody = document.getElementById('photoModalBody');

  function openModal() {
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    modalBody.innerHTML = '';
  }

  // Close handlers (backdrop, close button, Esc)
  modal.addEventListener('click', (e) => {
    if (e.target.matches('[data-close-photo-modal], .photo-modal-backdrop')) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) closeModal();
  });

  // Delegate click from any "View photos" button
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.js-view-photos');
    if (!btn) return;

    const taskId = parseInt(btn.getAttribute('data-task-id'), 10) || 0;
    if (!taskId) {
      console.error('Missing data-task-id on .js-view-photos button.');
      alert('Could not determine Task ID for photos.');
      return;
    }

    try {
      const res = await fetch('get_task_photos.php?task_id=' + encodeURIComponent(taskId), {
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
      });
      const data = await res.json();

      if (!res.ok || !data.ok) {
        throw new Error((data && data.error) ? data.error : 'Failed to load photos');
      }

      if (!Array.isArray(data.photos) || data.photos.length === 0) {
        modalBody.innerHTML = '<p class="text-muted">No photos for this task.</p>';
        openModal();
        return;
      }

      // Build images
      const frag = document.createDocumentFragment();
      data.photos.forEach((p) => {
        if (!p || !p.url) return;
        const img = document.createElement('img');
        img.loading = 'lazy';
        img.decoding = 'async';
        img.src = p.url;
        img.alt = 'Task photo';
        frag.appendChild(img);
      });
      modalBody.innerHTML = '';
      modalBody.appendChild(frag);
      openModal();
    } catch (err) {
      console.error(err);
      alert('Could not load photos: ' + err.message);
    }
  });
});
</script>

<!-- Photo Modal -->
<div id="photoModal" class="photo-modal hidden" aria-hidden="true">
  <div class="photo-modal-backdrop" data-close-photo-modal></div>
  <div class="photo-modal-box" role="dialog" aria-modal="true" aria-labelledby="photoModalTitle">
    <div class="photo-modal-header">
      <h3 id="photoModalTitle">Task photos</h3>
      <button class="close-btn" type="button" title="Close" data-close-photo-modal>&times;</button>
    </div>
    <div id="photoModalBody" class="photo-modal-body">
      <!-- images are injected here -->
    </div>
  </div>
</div>

<?php if (can('edit')): ?>
<!-- Quick Edit Modal (reuses modal styling) -->
<div id="quickModal" class="photo-modal hidden" aria-hidden="true">
  <div class="photo-modal-backdrop" data-close-quick></div>
  <div class="photo-modal-box" role="dialog" aria-modal="true" aria-labelledby="quickModalTitle">
    <div class="photo-modal-header">
      <h3 id="quickModalTitle">Quick Edit</h3>
      <button class="close-btn" type="button" title="Close" data-close-quick>&times;</button>
    </div>

    <form id="quickForm" class="photo-modal-body">
      <input type="hidden" name="<?php echo sanitize($csrfName); ?>" value="<?php echo sanitize($csrfToken); ?>">
      <input type="hidden" name="id" id="quickTaskId" value="">
      <div class="grid two">
        <label>Assigned To
          <input type="text" name="assigned_to" id="quickAssigned" placeholder="Name or team">
        </label>

        <label>Status
          <select name="status" id="quickStatus">
            <?php foreach ($allStatuses as $st): ?>
              <option value="<?php echo sanitize($st); ?>"><?php echo sanitize(status_label($st)); ?></option>
            <?php endforeach; ?>
          </select>
        </label>

        <label>Priority
          <select name="priority" id="quickPriority">
            <?php foreach ($allPriorities as $pr): ?>
              <option value="<?php echo sanitize($pr); ?>"><?php echo sanitize(priority_label($pr)); ?></option>
            <?php endforeach; ?>
          </select>
        </label>
      </div>

      <div class="form-actions" style="margin-top:.5rem">
        <button class="btn primary" type="submit">Save</button>
        <button class="btn secondary" type="button" data-close-quick>Cancel</button>
      </div>
    </form>
  </div>
</div>

<script>
(function(){
  const quickModal  = document.getElementById('quickModal');
  const quickForm   = document.getElementById('quickForm');
  const idInput     = document.getElementById('quickTaskId');
  const assignedInp = document.getElementById('quickAssigned');
  const statusSel   = document.getElementById('quickStatus');
  const prioritySel = document.getElementById('quickPriority');

  function openQuick() {
    quickModal.classList.remove('hidden');
    quickModal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }
  function closeQuick() {
    quickModal.classList.add('hidden');
    quickModal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    quickForm.reset();
    idInput.value = '';
  }

  // Open with prefill
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.js-quick-edit');
    if (!btn) return;

    const id        = btn.getAttribute('data-task-id');
    const assigned  = btn.getAttribute('data-task-assigned') || '';
    const statusKey = btn.getAttribute('data-task-status') || '';
    const prioKey   = btn.getAttribute('data-task-priority') || '';

    idInput.value       = id || '';
    assignedInp.value   = assigned;
    if (statusKey)   statusSel.value   = statusKey;
    if (prioKey)     prioritySel.value = prioKey;

    // Update title
    const titleEl = document.getElementById('quickModalTitle');
    if (titleEl) titleEl.textContent = 'Quick Edit — Task #' + id;

    openQuick();
  });

  // Close handlers
  quickModal?.addEventListener('click', (e) => {
    if (e.target.matches('[data-close-quick], .photo-modal-backdrop')) closeQuick();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !quickModal.classList.contains('hidden')) closeQuick();
  });

  // Submit
  quickForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = new FormData(quickForm);
    try {
      const res = await fetch('task_quick_update.php', {
        method: 'POST',
        credentials: 'same-origin',
        body: form
      });
      const data = await res.json();

      if (!res.ok || !data || !data.ok) {
        throw new Error((data && data.error) ? data.error : 'Failed to save changes');
      }

      // Update the row inline
      const t = data.task || {};
      const row = document.querySelector('tr[data-task-id="'+ (t.id || form.get("id")) +'"]');
      if (row) {
        // Assigned To
        const assignedCell = row.querySelector('.col-assigned');
        if (assignedCell) assignedCell.textContent = t.assigned_to || form.get('assigned_to') || '';

        // Status badge
        const statusBadge = row.querySelector('.col-status .badge');
        if (statusBadge && t.status_label) {
          statusBadge.textContent = t.status_label;
          if (t.status_class) statusBadge.className = t.status_class;
        }

        // Priority badge
        const prioBadge = row.querySelector('.col-priority .badge');
        if (prioBadge && t.priority_label) {
          prioBadge.textContent = t.priority_label;
          if (t.priority_class) prioBadge.className = t.priority_class;
        }

        // Also update the button dataset for future edits
        const btn = row.querySelector('.js-quick-edit');
        if (btn) {
          if (t.assigned_to !== undefined) btn.setAttribute('data-task-assigned', t.assigned_to || '');
          if (t.status_key)   btn.setAttribute('data-task-status', t.status_key);
          if (t.priority_key) btn.setAttribute('data-task-priority', t.priority_key);
        }
      }

      closeQuick();
    } catch (err) {
      alert(err.message || 'Save failed');
    }
  });
})();
</script>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>