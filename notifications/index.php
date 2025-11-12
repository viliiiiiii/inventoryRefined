<?php
// notifications/index.php
require_once __DIR__ . '/../helpers.php';
require_once __DIR__ . '/../includes/notifications.php';
require_login();

$me = current_user();
$userId = (int)($me['id'] ?? 0);
$page   = max(1, (int)($_GET['page'] ?? 1));
$per    = 50;
$list   = notif_list($userId, $per, ($page - 1) * $per);
$unreadTotal = notif_unread_count($userId);

$typeLabels = [
    'task.assigned'   => 'Task assignment',
    'task.unassigned' => 'Task reassigned',
    'task.updated'    => 'Task updated',
    'note.shared'     => 'Note shared',
    'note.comment'    => 'New note comment',
];

$typeIcons = [
    'task.assigned'   => '🧭',
    'task.unassigned' => '🔁',
    'task.updated'    => '🛠️',
    'note.shared'     => '🗂️',
    'note.comment'    => '💬',
];

if (!function_exists('notif_relative_time')) {
    function notif_relative_time(?string $timestamp): string {
        if (!$timestamp) {
            return '';
        }
        try {
            $dt = new DateTimeImmutable($timestamp);
        } catch (Throwable $e) {
            return (string)$timestamp;
        }
        $now  = new DateTimeImmutable('now');
        $diff = $now->getTimestamp() - $dt->getTimestamp();
        if ($diff < 0) {
            $diff = 0;
        }
        if ($diff < 60) {
            return $diff . 's ago';
        }
        $mins = (int)floor($diff / 60);
        if ($mins < 60) {
            return $mins . 'm ago';
        }
        $hours = (int)floor($mins / 60);
        if ($hours < 24) {
            return $hours . 'h ago';
        }
        $days = (int)floor($hours / 24);
        if ($days < 7) {
            return $days . 'd ago';
        }
        return $dt->format('M j, Y');
    }
}

if (!function_exists('notif_normalize_search')) {
    function notif_normalize_search(string $value): string {
        $value = trim(preg_replace('/\s+/', ' ', $value) ?? '');
        if (function_exists('mb_strtolower')) {
            return mb_strtolower($value, 'UTF-8');
        }
        return strtolower($value);
    }
}

$groups = [];
$totalCount = 0;

try {
    $now = new DateTimeImmutable('now');
    $todayStart = $now->setTime(0, 0, 0);
} catch (Throwable $e) {
    $todayStart = null;
}
$yesterdayStart = $todayStart ? $todayStart->modify('-1 day') : null;
$weekStart      = $todayStart ? $todayStart->modify('-6 days') : null;

foreach ($list as $row) {
    $totalCount++;

    $typeKey = (string)($row['type'] ?? 'general');
    $label   = $typeLabels[$typeKey] ?? ucwords(str_replace(['.', '_'], ' ', $typeKey));
    $icon    = $typeIcons[$typeKey] ?? '🔔';
    $title   = trim((string)($row['title'] ?? ''));
    if ($title === '') {
        $title = $label;
    }
    $body = trim((string)($row['body'] ?? ''));

    $category = 'other';
    if (strpos($typeKey, 'task') === 0) {
        $category = 'task';
    } elseif (strpos($typeKey, 'note') === 0) {
        $category = 'note';
    }

    $createdAtRaw = $row['created_at'] ?? null;
    $createdAt    = null;
    $dayKey       = 'unknown';
    $dayLabel     = 'Earlier';
    $dayTag       = 'older';
    $dayDateLabel = '';
    $timeAttr     = '';
    $timeDisplay  = '';
    $timeRel      = notif_relative_time($createdAtRaw);
    $weekFlag     = 0;

    if ($createdAtRaw) {
        try {
            $createdAt = new DateTimeImmutable($createdAtRaw);
        } catch (Throwable $e) {
            $createdAt = null;
        }
    }

    if ($createdAt) {
        $dayKey = $createdAt->format('Y-m-d');
        $timeAttr = $createdAt->format(DateTimeInterface::ATOM);
        $timeDisplay = trim($createdAt->format('g:i A') . ($timeRel ? ' · ' . $timeRel : ''));
        if ($todayStart && $createdAt >= $todayStart) {
            $dayLabel = 'Today';
            $dayTag   = 'today';
        } elseif ($yesterdayStart && $createdAt >= $yesterdayStart) {
            $dayLabel = 'Yesterday';
            $dayTag   = 'yesterday';
        } elseif ($weekStart && $createdAt >= $weekStart) {
            $dayLabel = $createdAt->format('l');
            $dayTag   = 'week';
        } else {
            $dayLabel = $createdAt->format('M j, Y');
            $dayTag   = 'older';
        }
        $dayDateLabel = $createdAt->format('M j, Y');
        if ($weekStart && $createdAt >= $weekStart) {
            $weekFlag = 1;
        }
        if ($timeDisplay === '') {
            $timeDisplay = $createdAt->format('g:i A');
        }
    }

    if (!isset($groups[$dayKey])) {
        $groups[$dayKey] = [
            'label' => $dayLabel,
            'tag'   => $dayTag,
            'date'  => $dayDateLabel,
            'items' => [],
        ];
    }

    $searchBlob = notif_normalize_search($title . ' ' . $body . ' ' . $label);

    $groups[$dayKey]['items'][] = [
        'id'            => (int)($row['id'] ?? 0),
        'title'         => $title,
        'body'          => $body,
        'label'         => $label,
        'icon'          => $icon,
        'url'           => $row['url'] ?? null,
        'is_unread'     => empty($row['is_read']),
        'type_key'      => $typeKey,
        'category'      => $category,
        'day_tag'       => $dayTag,
        'week_flag'     => $weekFlag,
        'search_blob'   => $searchBlob,
        'time_attr'     => $timeAttr,
        'time_display'  =>
            $timeDisplay ?: ($timeRel ?: ''),
        'time_relative' => $timeRel,
    ];
}

$hasNotifications = $totalCount > 0;
$emptyTitle   = $hasNotifications ? 'No notifications match your filters' : 'You’re all caught up';
$emptyMessage = $hasNotifications
    ? 'Clear filters or adjust your search to see more updates.'
    : 'When new activity arrives, it will appear here automatically.';

$title = 'Notifications';
include __DIR__ . '/../includes/header.php';

$searchId = 'notif-search';
?>
<section class="notif-hub">
  <header class="notif-hub__header">
    <div class="notif-hub__intro">
      <h1>Notifications</h1>
      <div class="notif-hub__summary" data-match-text>
        <span><strong data-unread-count><?php echo (int)$unreadTotal; ?></strong> unread</span>
        <span class="notif-hub__dot" aria-hidden="true">•</span>
        <span>Showing <strong data-match-count><?php echo (int)$totalCount; ?></strong> <span data-match-label><?php echo $totalCount === 1 ? 'notification' : 'notifications'; ?></span></span>
      </div>
    </div>
    <div class="notif-hub__actions">
      <button type="button" class="btn ghost small" data-refresh>Refresh</button>
      <form method="post" action="/notifications/api.php" data-action="mark-all" class="inline">
        <input type="hidden" name="action" value="mark_all_read">
        <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
        <button class="btn primary small" type="submit" <?php echo $unreadTotal ? '' : 'disabled'; ?>>Mark all read</button>
      </form>
    </div>
  </header>

  <div class="notif-hub__controls">
    <label class="notif-control">
      <span class="notif-control__label">Filter</span>
      <select class="notif-control__input" data-filter>
        <option value="all">All</option>
        <option value="unread">Unread</option>
        <option value="recent">Recent</option>
        <option value="task">Tasks</option>
        <option value="note">Notes</option>
        <option value="other">Other</option>
      </select>
    </label>
    <div class="notif-control notif-control--search">
      <label class="notif-control__label" for="<?php echo $searchId; ?>">Search</label>
      <div class="notif-control__search">
        <input id="<?php echo $searchId; ?>" type="search" placeholder="Search notifications" autocomplete="off" class="notif-control__input" data-search>
        <button type="button" class="notif-control__clear" data-clear-search>Clear</button>
      </div>
    </div>
  </div>

  <?php if ($hasNotifications): ?>
    <div class="notif-feed" data-feed>
      <?php foreach ($groups as $group): ?>
        <?php $count = count($group['items']); ?>
        <section class="notif-feed__group" data-day-section data-day-tag="<?php echo sanitize($group['tag']); ?>">
          <header class="notif-feed__header">
            <div class="notif-feed__heading">
              <span class="notif-feed__title"><?php echo sanitize($group['label']); ?></span>
              <?php if (!empty($group['date'])): ?>
                <span class="notif-feed__date"><?php echo sanitize($group['date']); ?></span>
              <?php endif; ?>
            </div>
            <span class="notif-feed__count" data-day-count><?php echo $count === 1 ? '1 update' : $count . ' updates'; ?></span>
          </header>
          <div class="notif-feed__list">
            <?php foreach ($group['items'] as $item):
              $isUnread = !empty($item['is_unread']);
              $searchBlob = sanitize($item['search_blob']);
              $timeAttr   = $item['time_attr'] ?? '';
              $timeDisplay = $item['time_display'] ?: ($item['time_relative'] ?? '');
            ?>
              <article class="notif-card<?php echo $isUnread ? ' is-unread' : ''; ?>" data-entry data-id="<?php echo (int)$item['id']; ?>" data-type="<?php echo sanitize($item['type_key']); ?>" data-category="<?php echo sanitize($item['category']); ?>" data-read="<?php echo $isUnread ? '0' : '1'; ?>" data-search="<?php echo $searchBlob; ?>" data-day-tag="<?php echo sanitize($item['day_tag']); ?>" data-week="<?php echo !empty($item['week_flag']) ? '1' : '0'; ?>">
                <div class="notif-card__icon" aria-hidden="true"><?php echo $item['icon']; ?></div>
                <div class="notif-card__content">
                  <div class="notif-card__top">
                    <div class="notif-card__info">
                      <span class="notif-card__title"><?php echo sanitize($item['title']); ?></span>
                      <span class="notif-card__tag"><?php echo sanitize($item['label']); ?></span>
                    </div>
                    <?php if ($timeAttr): ?>
                      <time class="notif-card__time" datetime="<?php echo sanitize($timeAttr); ?>"><?php echo sanitize($timeDisplay); ?></time>
                    <?php elseif ($timeDisplay): ?>
                      <span class="notif-card__time"><?php echo sanitize($timeDisplay); ?></span>
                    <?php endif; ?>
                  </div>
                  <?php if ($item['body'] !== ''): ?>
                    <p class="notif-card__body"><?php echo nl2br(sanitize($item['body'])); ?></p>
                  <?php endif; ?>
                  <div class="notif-card__footer">
                    <span class="notif-card__status<?php echo $isUnread ? ' is-active' : ''; ?>" data-status><?php echo $isUnread ? 'Unread' : 'Read'; ?></span>
                    <div class="notif-card__actions">
                      <?php if (!empty($item['url'])): ?>
                        <a class="btn ghost xsmall" href="<?php echo sanitize($item['url']); ?>">Open</a>
                      <?php endif; ?>
                      <form method="post" action="/notifications/api.php" class="notif-card__toggle" data-action="toggle-read">
                        <input type="hidden" name="id" value="<?php echo (int)$item['id']; ?>">
                        <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                        <button type="submit" class="btn ghost xsmall" name="action" value="mark_read" data-toggle-read <?php echo $isUnread ? '' : 'hidden'; ?>>Mark read</button>
                        <button type="submit" class="btn ghost xsmall" name="action" value="mark_unread" data-toggle-unread <?php echo $isUnread ? 'hidden' : ''; ?>>Mark unread</button>
                      </form>
                      <form method="post" action="/notifications/api.php" class="notif-card__delete" data-action="delete">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="id" value="<?php echo (int)$item['id']; ?>">
                        <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                        <button type="submit" class="btn ghost xsmall danger" aria-label="Delete notification">Delete</button>
                      </form>
                    </div>
                  </div>
                </div>
              </article>
            <?php endforeach; ?>
          </div>
        </section>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <div class="notif-empty" data-empty
       data-base-title="You’re all caught up"
       data-base-message="When new activity arrives, it will appear here automatically."
       data-filter-title="No notifications match"
       data-filter-message="Clear filters or adjust your search to see more updates."
       <?php echo $hasNotifications ? 'hidden' : ''; ?>>
    <div class="notif-empty__icon">🔕</div>
    <h2 data-empty-title><?php echo sanitize($emptyTitle); ?></h2>
    <p class="muted" data-empty-message><?php echo sanitize($emptyMessage); ?></p>
    <?php if ($hasNotifications): ?>
      <button type="button" class="btn ghost small" data-empty-reset>Reset filters</button>
    <?php endif; ?>
  </div>
</section>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const feed = document.querySelector('[data-feed]');
  const dot = document.getElementById('notifDot');
  const unreadNode = document.querySelector('[data-unread-count]');
  const matchCountNode = document.querySelector('[data-match-count]');
  const matchLabelNode = document.querySelector('[data-match-label]');
  const markAllForm = document.querySelector('form[data-action="mark-all"]');
  const markAllButton = markAllForm ? markAllForm.querySelector('button[type="submit"]') : null;
  const filterSelect = document.querySelector('[data-filter]');
  const searchInput = document.querySelector('[data-search]');
  const clearSearch = document.querySelector('[data-clear-search]');
  const emptyState = document.querySelector('[data-empty]');
  const emptyTitle = emptyState ? emptyState.querySelector('[data-empty-title]') : null;
  const emptyMessage = emptyState ? emptyState.querySelector('[data-empty-message]') : null;
  const emptyReset = emptyState ? emptyState.querySelector('[data-empty-reset]') : null;
  const refreshBtn = document.querySelector('[data-refresh]');
  let entries = feed ? Array.from(feed.querySelectorAll('[data-entry]')) : [];

  const updateEntries = () => {
    entries = feed ? Array.from(feed.querySelectorAll('[data-entry]')) : [];
  };

  const getUnreadCount = () => entries.filter(entry => entry.dataset.read === '0').length;

  const renderCount = (value) => {
    const count = Number.isFinite(value) ? Math.max(0, value) : getUnreadCount();
    if (unreadNode) {
      unreadNode.textContent = count;
    }
    if (markAllButton) {
      markAllButton.disabled = count === 0;
    }
    if (dot) {
      if (count > 0) {
        dot.textContent = count > 99 ? '99+' : String(count);
        dot.classList.add('is-visible');
      } else {
        dot.textContent = '';
        dot.classList.remove('is-visible');
      }
    }
  };

  const updateMatchDisplay = (value) => {
    if (matchCountNode) {
      matchCountNode.textContent = value;
    }
    if (matchLabelNode) {
      matchLabelNode.textContent = value === 1 ? 'notification' : 'notifications';
    }
  };

  const updateDaySections = (visibleMap) => {
    document.querySelectorAll('[data-day-section]').forEach(section => {
      const visibleCount = visibleMap.get(section) || 0;
      const countNode = section.querySelector('[data-day-count]');
      section.hidden = visibleCount === 0;
      if (countNode) {
        if (visibleCount === 0) {
          countNode.textContent = '';
        } else {
          countNode.textContent = visibleCount === 1 ? '1 update' : `${visibleCount} updates`;
        }
      }
    });
  };

  const applyFilters = () => {
    updateEntries();
    const total = entries.length;
    if (!total) {
      if (emptyState) {
        emptyState.hidden = false;
        if (emptyTitle) {
          emptyTitle.textContent = emptyState.dataset.baseTitle || 'You’re all caught up';
        }
        if (emptyMessage) {
          emptyMessage.textContent = emptyState.dataset.baseMessage || 'When new activity arrives, it will appear here automatically.';
        }
        if (emptyReset) {
          emptyReset.hidden = true;
        }
      }
      updateMatchDisplay(0);
      updateDaySections(new Map());
      renderCount(0);
      return;
    }

    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const filter = filterSelect ? (filterSelect.value || 'all') : 'all';
    const visibleMap = new Map();
    let visible = 0;

    entries.forEach(entry => {
      const category = entry.dataset.category || 'other';
      const dayTag = entry.dataset.dayTag || '';
      const isUnread = entry.dataset.read === '0';
      const haystack = entry.dataset.search || '';
      const matchesFilter = filter === 'all'
        || (filter === 'unread' && isUnread)
        || (filter === 'recent' && (dayTag === 'today' || dayTag === 'yesterday'))
        || (filter === category);
      const matchesSearch = !query || haystack.indexOf(query) !== -1;
      const show = matchesFilter && matchesSearch;

      entry.hidden = !show;
      entry.classList.toggle('is-hidden', !show);

      if (show) {
        visible += 1;
        const section = entry.closest('[data-day-section]');
        if (section) {
          visibleMap.set(section, (visibleMap.get(section) || 0) + 1);
        }
      }
    });

    updateDaySections(visibleMap);
    updateMatchDisplay(visible);

    if (emptyState) {
      const isFiltered = filter !== 'all' || query.length > 0;
      if (visible === 0) {
        emptyState.hidden = false;
        if (emptyTitle) {
          emptyTitle.textContent = isFiltered
            ? (emptyState.dataset.filterTitle || 'No notifications match')
            : (emptyState.dataset.baseTitle || 'You’re all caught up');
        }
        if (emptyMessage) {
          emptyMessage.textContent = isFiltered
            ? (emptyState.dataset.filterMessage || 'Clear filters or adjust your search to see more updates.')
            : (emptyState.dataset.baseMessage || 'When new activity arrives, it will appear here automatically.');
        }
        if (emptyReset) {
          emptyReset.hidden = !isFiltered;
        }
      } else {
        emptyState.hidden = true;
        if (emptyReset) {
          emptyReset.hidden = true;
        }
      }
    }

    renderCount();
    if (clearSearch) {
      clearSearch.hidden = query.length === 0;
    }
  };

  renderCount();
  applyFilters();

  if (filterSelect) {
    filterSelect.addEventListener('change', applyFilters);
  }

  if (searchInput) {
    searchInput.addEventListener('input', applyFilters);
  }

  if (clearSearch) {
    clearSearch.addEventListener('click', () => {
      if (searchInput) {
        searchInput.value = '';
      }
      clearSearch.hidden = true;
      applyFilters();
      if (searchInput) {
        searchInput.focus();
      }
    });
    clearSearch.hidden = true;
  }

  if (emptyReset) {
    emptyReset.addEventListener('click', () => {
      if (filterSelect) {
        filterSelect.value = 'all';
      }
      if (searchInput) {
        searchInput.value = '';
      }
      if (clearSearch) {
        clearSearch.hidden = true;
      }
      applyFilters();
    });
  }

  const postForm = async (form, submitter) => {
    const data = new FormData(form);
    if (submitter && submitter.name) {
      data.append(submitter.name, submitter.value);
    }
    const response = await fetch(form.action, {
      method: 'POST',
      body: data,
      credentials: 'same-origin',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json'
      }
    });
    if (!response.ok) {
      throw new Error('Request failed');
    }
    return await response.json();
  };

  const removeEntry = (entry, unreadCount) => {
    if (!entry) {
      return;
    }
    entry.remove();
    updateEntries();
    renderCount(typeof unreadCount === 'number' ? unreadCount : undefined);
    applyFilters();
  };

  const handleToggle = (form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const submitter = event.submitter;
      if (!submitter) {
        form.submit();
        return;
      }
      const action = submitter.value;
      try {
        const json = await postForm(form, submitter);
        if (!json || json.ok !== true) {
          return;
        }
        const parent = form.closest('[data-entry]');
        if (!parent) {
          return;
        }
        const makeUnread = action === 'mark_unread';
        parent.dataset.read = makeUnread ? '0' : '1';
        parent.classList.toggle('is-unread', makeUnread);
        const statusNode = parent.querySelector('[data-status]');
        if (statusNode) {
          statusNode.textContent = makeUnread ? 'Unread' : 'Read';
          statusNode.classList.toggle('is-active', makeUnread);
        }
        const readBtn = form.querySelector('[data-toggle-read]');
        const unreadBtn = form.querySelector('[data-toggle-unread]');
        if (readBtn) {
          readBtn.hidden = !makeUnread;
        }
        if (unreadBtn) {
          unreadBtn.hidden = makeUnread;
        }
        renderCount(typeof json.count === 'number' ? json.count : undefined);
        applyFilters();
      } catch (err) {
        console.error(err);
        form.submit();
      }
    });
  };

  document.querySelectorAll('form[data-action="toggle-read"]').forEach(handleToggle);

  const handleDelete = (form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!confirm('Delete this notification?')) {
        return;
      }
      try {
        const json = await postForm(form);
        if (!json || json.ok !== true) {
          return;
        }
        const entry = form.closest('[data-entry]');
        removeEntry(entry, typeof json.count === 'number' ? json.count : undefined);
      } catch (err) {
        console.error(err);
        form.submit();
      }
    });
  };

  document.querySelectorAll('form[data-action="delete"]').forEach(handleDelete);

  if (markAllForm) {
    markAllForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!confirm('Mark all notifications as read?')) {
        return;
      }
      try {
        const json = await postForm(markAllForm);
        if (!json || json.ok !== true) {
          return;
        }
        entries.forEach(entry => {
          entry.dataset.read = '1';
          entry.classList.remove('is-unread');
          const statusNode = entry.querySelector('[data-status]');
          if (statusNode) {
            statusNode.textContent = 'Read';
            statusNode.classList.remove('is-active');
          }
          const toggle = entry.querySelector('form[data-action="toggle-read"]');
          if (toggle) {
            const readBtn = toggle.querySelector('[data-toggle-read]');
            const unreadBtn = toggle.querySelector('[data-toggle-unread]');
            if (readBtn) {
              readBtn.hidden = true;
            }
            if (unreadBtn) {
              unreadBtn.hidden = false;
            }
          }
        });
        renderCount(typeof json.count === 'number' ? json.count : undefined);
        applyFilters();
      } catch (err) {
        console.error(err);
        markAllForm.submit();
      }
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      window.location.reload();
    });
  }
});
</script>
<?php include __DIR__ . '/../includes/footer.php'; ?>