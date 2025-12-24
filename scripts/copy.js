function addSelectionCopyBehavior(wrapper) {
    codeBlockWrappers.push(wrapper);
}

function addModalCopyBehavior(wrapper) {
    modalCopyWrappers.push(wrapper);
}

function addCopyButton(wrapper, getText) {
    // Copy buttons are intentionally suppressed; selection copying is used instead.
    if (!wrapper) {
        return;
    }
    const existing = wrapper.querySelector('.copy-btn');
    if (existing) {
        existing.remove();
    }
}

function attachSelectionCopyHandler() {
    if (selectionCopyHandlerAttached) {
        return;
    }

    const handleSelectionCopy = () => {
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed) {
            return;
        }

        const wrapper = findIntersectingWrapper(selection);
        if (!wrapper) {
            return;
        }

        const selectedText = selection.toString();
        if (!selectedText.trim()) {
            return;
        }

        const now = Date.now();
        if (selectedText === lastCopiedSelection && wrapper === lastCopiedWrapper && (now - lastCopiedAt) < 200) {
            return;
        }

        lastCopiedSelection = selectedText;
        lastCopiedWrapper = wrapper;
        lastCopiedAt = now;
        lastSelectionRect = selection.getRangeAt(0)?.getBoundingClientRect?.() || null;

        navigator.clipboard.writeText(selectedText)
            .then(() => showCopyFeedback(wrapper, 'Copied', lastSelectionRect))
            .catch((error) => {
                console.warn('Copy failed', error);
                showCopyFeedback(wrapper, 'Copy failed', lastSelectionRect);
            });
    };

    ['mouseup', 'keyup', 'touchend'].forEach(eventName => {
        document.addEventListener(eventName, handleSelectionCopy);
    });

    selectionCopyHandlerAttached = true;
}

function findIntersectingWrapper(selection) {
    if (!selection.rangeCount) {
        return null;
    }

    const wrappers = [...codeBlockWrappers, ...modalCopyWrappers];

    for (const wrapper of wrappers) {
        if (selectionIntersectsWrapper(selection, wrapper) && selectionWithinWrapper(selection, wrapper)) {
            return wrapper;
        }
    }

    return null;
}

function selectionIntersectsWrapper(selection, wrapper) {
    for (let i = 0; i < selection.rangeCount; i++) {
        const range = selection.getRangeAt(i);
        if (typeof range.intersectsNode === 'function') {
            if (range.intersectsNode(wrapper)) {
                return true;
            }
        } else {
            const wrapperRange = document.createRange();
            wrapperRange.selectNodeContents(wrapper);
            const startsBeforeEnd = range.compareBoundaryPoints(Range.END_TO_START, wrapperRange) < 0;
            const endsAfterStart = range.compareBoundaryPoints(Range.START_TO_END, wrapperRange) > 0;
            if (startsBeforeEnd && endsAfterStart) {
                return true;
            }
        }
    }
    return false;
}

function selectionWithinWrapper(selection, wrapper) {
    const range = selection.rangeCount ? selection.getRangeAt(0) : null;
    if (!range) {
        return false;
    }
    const { startContainer, endContainer } = range;
    return wrapper.contains(startContainer) && wrapper.contains(endContainer);
}

function showCopyFeedback(_wrapper, message) {
    let badge = document.querySelector('.copy-feedback-global');
    if (!badge) {
        badge = document.createElement('div');
        badge.className = 'copy-feedback copy-feedback-global';
        document.body.appendChild(badge);
    }

    badge.textContent = message;
    badge.classList.add('visible');

    if (badge._timeoutId) {
        clearTimeout(badge._timeoutId);
    }

    badge._timeoutId = setTimeout(() => {
        badge.classList.remove('visible');
    }, 1600);
}
