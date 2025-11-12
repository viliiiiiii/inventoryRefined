(function () {
    'use strict';

    const appState = {
        activeModal: null,
        modalPayload: null,
    };

    const qs = (sel, ctx = document) => ctx.querySelector(sel);
    const qsa = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

    function openModal(modalId, payload) {
        const modal = qs(`[data-modal="${modalId}"]`);
        if (!modal) {
            return;
        }
        closeModal();
        modal.classList.add('modal--visible');
        document.body.style.overflow = 'hidden';
        appState.activeModal = modal;
        appState.modalPayload = payload || null;

        if (modalId === 'note-share' || modalId === 'template-share') {
            prepareShareModal(modal, payload || {});
        } else if (modalId === 'quick-note') {
            const first = qs('input[name="title"]', modal);
            if (first) {
                setTimeout(() => first.focus(), 40);
            }
        }
    }

    function closeModal() {
        if (appState.activeModal) {
            appState.activeModal.classList.remove('modal--visible');
            appState.activeModal = null;
            appState.modalPayload = null;
            document.body.style.overflow = '';
        }
    }

    function prepareShareModal(modal, payload) {
        const form = qs('form', modal);
        if (!form) {
            return;
        }
        const ownerId = payload && typeof payload.owner === 'number' ? payload.owner : null;
        const selected = Array.isArray(payload.selected) ? payload.selected.map(Number) : [];
        const hiddenField = qs('input[name="note_id"], input[name="template_id"]', form);
        if (hiddenField) {
            hiddenField.value = payload.noteId || payload.templateId || '';
        }
        qsa('input[type="checkbox"]', form).forEach((checkbox) => {
            const value = Number(checkbox.value);
            checkbox.checked = selected.includes(value);
            checkbox.disabled = ownerId !== null && value === ownerId;
        });
        const filterInput = qs('[data-share-filter]', form);
        if (filterInput) {
            filterInput.value = '';
            filterShareList(filterInput, form);
            setTimeout(() => filterInput.focus(), 40);
        }
    }

    function filterShareList(input, container) {
        const term = input.value.trim().toLowerCase();
        qsa('[data-share-user]', container).forEach((row) => {
            const text = row.textContent.trim().toLowerCase();
            row.style.display = text.includes(term) ? '' : 'none';
        });
    }

    function handleShareSubmit(event) {
        const form = event.target;
        if (!form.matches('[data-share-form]')) {
            return;
        }
        event.preventDefault();
        const formData = new FormData(form);
        const type = form.getAttribute('data-share-form');
        fetch(window.location.href, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
            },
            body: formData,
        })
            .then(async (response) => {
                const data = await response.json().catch(() => null);
                if (!response.ok || !data || !data.ok) {
                    const message = data && data.message ? data.message : (window.notesApp && window.notesApp.messages.saveError) || 'Unable to save changes.';
                    throw new Error(message);
                }
                if (type === 'note') {
                    updateNoteShares(data.note_id, data.shares || []);
                } else if (type === 'template') {
                    updateTemplateShares(data.template_id, data.selected || []);
                }
                closeModal();
            })
            .catch((error) => {
                alert(error.message);
            });
    }

    function updateNoteShares(noteId, shareRows) {
        if (!noteId) {
            return;
        }
        const container = qs(`[data-share-target="${noteId}"]`);
        if (!container) {
            return;
        }
        const placeholder = container.querySelector('[data-share-placeholder]');
        if (placeholder) {
            placeholder.remove();
        }
        qsa('.avatar-chip', container).forEach((chip) => chip.remove());
        if (!shareRows || shareRows.length === 0) {
            if (container.hasAttribute('data-share-allow-placeholder')) {
                const empty = document.createElement('span');
                empty.className = 'note-shares__placeholder';
                empty.setAttribute('data-share-placeholder', '');
                empty.textContent = 'Only you';
                container.appendChild(empty);
            }
            return;
        }
        shareRows.forEach((row) => {
            if (!row || typeof row.id === 'undefined') {
                return;
            }
            const label = row.label || `User #${row.id}`;
            if (window.notesApp && window.notesApp.shareMap) {
                window.notesApp.shareMap[row.id] = label;
            }
            const chip = document.createElement('span');
            chip.className = 'avatar-chip';
            chip.title = label;
            const initials = (label || '').trim().slice(0, 2).toUpperCase();
            chip.textContent = initials;
            container.appendChild(chip);
        });
    }

    function updateTemplateShares(templateId, selected) {
        if (!templateId) {
            return;
        }
        const card = qs(`.template-card[data-template-id="${templateId}"]`);
        if (!card) {
            return;
        }
        const meta = qs('.template-card__meta span:last-child', card);
        if (meta) {
            meta.textContent = `${Array.isArray(selected) ? selected.length : 0} shared`;
        }
    }

    function handleQuickNote(event) {
        const form = event.target;
        if (!form.classList.contains('quick-note-form')) {
            return;
        }
        event.preventDefault();
        const formData = new FormData(form);
        fetch(window.location.href, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
            },
            body: formData,
        })
            .then(async (response) => {
                const data = await response.json().catch(() => null);
                if (!response.ok || !data || !data.ok) {
                    const message = data && data.message ? data.message : 'Unable to capture note.';
                    throw new Error(message);
                }
                if (data.redirect) {
                    window.location.href = data.redirect;
                } else {
                    window.location.reload();
                }
            })
            .catch((error) => {
                alert(error.message);
            });
    }

    function bindModals() {
        qsa('[data-modal-open]').forEach((button) => {
            button.addEventListener('click', (event) => {
                event.preventDefault();
                const modalId = button.getAttribute('data-modal-open');
                let payload = null;
                if (button.dataset.shareConfig) {
                    try {
                        payload = JSON.parse(button.dataset.shareConfig);
                    } catch (e) {
                        payload = null;
                    }
                }
                openModal(modalId, payload);
            });
        });

        qsa('[data-modal-close]').forEach((button) => {
            button.addEventListener('click', (event) => {
                event.preventDefault();
                closeModal();
            });
        });

        qsa('[data-modal]').forEach((modal) => {
            modal.addEventListener('click', (event) => {
                if (event.target === modal) {
                    closeModal();
                }
            });
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
    }

    function bindShareFilters() {
        qsa('[data-share-filter]').forEach((input) => {
            input.addEventListener('input', () => {
                const form = input.closest('form');
                if (form) {
                    filterShareList(input, form);
                }
            });
        });
    }

    function bindSearch() {
        const input = qs('#notes-search');
        if (!input) {
            return;
        }
        const cards = qsa('.note-card');
        input.addEventListener('input', () => {
            const term = input.value.trim().toLowerCase();
            cards.forEach((card) => {
                const title = (card.dataset.noteTitle || '').toLowerCase();
                const body = card.textContent ? card.textContent.toLowerCase() : '';
                const match = !term || title.includes(term) || body.includes(term);
                card.style.display = match ? '' : 'none';
            });
        });
    }

    function bindCommentReplies() {
        document.body.addEventListener('click', (event) => {
            const toggle = event.target.closest('[data-reply-toggle]');
            if (toggle) {
                event.preventDefault();
                const id = toggle.getAttribute('data-reply-toggle');
                const form = document.querySelector(`[data-reply-form="${id}"]`);
                if (form) {
                    const isHidden = form.hasAttribute('hidden');
                    if (isHidden) {
                        form.removeAttribute('hidden');
                        const textarea = form.querySelector('textarea');
                        if (textarea) {
                            setTimeout(() => textarea.focus(), 30);
                        }
                    } else {
                        form.setAttribute('hidden', '');
                    }
                }
            }

            const cancel = event.target.closest('[data-reply-cancel]');
            if (cancel) {
                event.preventDefault();
                const id = cancel.getAttribute('data-reply-cancel');
                const form = document.querySelector(`[data-reply-form="${id}"]`);
                if (form) {
                    form.setAttribute('hidden', '');
                }
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        bindModals();
        bindShareFilters();
        bindSearch();
        bindCommentReplies();
        document.body.addEventListener('submit', (event) => {
            if (event.target.matches('[data-share-form]')) {
                handleShareSubmit(event);
            } else if (event.target.classList.contains('quick-note-form')) {
                handleQuickNote(event);
            }
        }, true);
    });
})();