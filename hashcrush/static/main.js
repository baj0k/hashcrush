(function () {
    function toggleElement(element, visible) {
        if (!element) {
            return;
        }
        element.classList.toggle('hc-hidden', !visible);
    }

    function applySelectToggles(select) {
        if (!select) {
            return;
        }

        var hideTargets = (select.dataset.hideTargets || '')
            .split(',')
            .map(function (value) { return value.trim(); })
            .filter(Boolean);
        hideTargets.forEach(function (targetId) {
            toggleElement(document.getElementById(targetId), false);
        });

        var targetId = select.dataset.toggleTarget;
        if (targetId) {
            var visible = false;
            if (select.dataset.toggleNonempty === 'true') {
                visible = select.value.trim() !== '';
            } else {
                visible = select.value === (select.dataset.toggleValue || '');
            }
            toggleElement(document.getElementById(targetId), visible);
        }

        var toggleGroup = select.dataset.toggleGroup;
        if (!toggleGroup) {
            return;
        }

        document.querySelectorAll('[data-toggle-group-section="' + toggleGroup + '"]').forEach(function (section) {
            var allowedValues = (section.dataset.toggleValues || '')
                .split(',')
                .map(function (value) { return value.trim(); })
                .filter(Boolean);
            toggleElement(section, allowedValues.indexOf(select.value) !== -1);
        });
    }

    function bindSelectToggles() {
        document.querySelectorAll('select[data-toggle-target], select[data-toggle-group]').forEach(function (select) {
            select.addEventListener('change', function () {
                applySelectToggles(select);
            });
            applySelectToggles(select);
        });
    }

    function bindFileTriggers() {
        document.querySelectorAll('[data-file-trigger]').forEach(function (button) {
            button.addEventListener('click', function () {
                var target = document.getElementById(button.dataset.fileTrigger);
                if (target) {
                    target.click();
                }
            });
        });

        document.querySelectorAll('input[type="file"][data-auto-submit="true"]').forEach(function (input) {
            input.addEventListener('change', function () {
                if (input.files && input.files.length > 0 && input.form) {
                    input.form.submit();
                }
            });
        });
    }

    function bindConfirmForms() {
        document.querySelectorAll('form[data-confirm]').forEach(function (form) {
            form.addEventListener('submit', function (event) {
                if (!window.confirm(form.dataset.confirm)) {
                    event.preventDefault();
                }
            });
        });
    }

    function formatUploadBytes(bytes) {
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var value = Math.max(0, Number(bytes) || 0);
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex += 1;
        }
        if (value >= 100 || unitIndex === 0) {
            return value.toFixed(0) + ' ' + units[unitIndex];
        }
        if (value >= 10) {
            return value.toFixed(1).replace(/\.0$/, '') + ' ' + units[unitIndex];
        }
        return value.toFixed(2).replace(/\.00$/, '').replace(/(\.\d)0$/, '$1') + ' ' + units[unitIndex];
    }

    var UPLOAD_TRACK_STORAGE_KEY = 'hashcrush.uploadOperations.v1';
    var UPLOAD_COMPLETED_RETENTION_MS = 6 * 60 * 60 * 1000;
    var uploadMonitorTimer = 0;

    function parseJsonString(rawValue) {
        if (!rawValue) {
            return null;
        }
        try {
            return JSON.parse(rawValue);
        } catch (error) {
            return null;
        }
    }

    function extractUploadOperationId(statusUrl) {
        if (!statusUrl) {
            return '';
        }
        var trimmed = String(statusUrl).replace(/\/+$/, '');
        return trimmed.split('/').pop() || trimmed;
    }

    function normalizeTrackedUploadEntry(entry) {
        if (!entry || typeof entry !== 'object') {
            return null;
        }

        var statusUrl = typeof entry.statusUrl === 'string' ? entry.statusUrl : '';
        if (!statusUrl) {
            return null;
        }

        return {
            operationId: typeof entry.operationId === 'string' && entry.operationId
                ? entry.operationId
                : extractUploadOperationId(statusUrl),
            statusUrl: statusUrl,
            title: typeof entry.title === 'string' && entry.title
                ? entry.title
                : 'Processing file...',
            detail: typeof entry.detail === 'string'
                ? entry.detail
                : 'The server is processing the uploaded file.',
            percent: typeof entry.percent === 'number' ? entry.percent : 0,
            complete: entry.complete === true,
            success: entry.success === true,
            failed: entry.failed === true,
            redirectUrl: typeof entry.redirectUrl === 'string' && entry.redirectUrl
                ? entry.redirectUrl
                : null,
            createdAt: typeof entry.createdAt === 'number' ? entry.createdAt : Date.now(),
            updatedAt: typeof entry.updatedAt === 'number' ? entry.updatedAt : Date.now(),
        };
    }

    function loadTrackedUploadEntries() {
        var rawValue = null;
        try {
            rawValue = window.localStorage.getItem(UPLOAD_TRACK_STORAGE_KEY);
        } catch (error) {
            return [];
        }
        var payload = parseJsonString(rawValue);
        if (!Array.isArray(payload)) {
            return [];
        }

        return payload
            .map(normalizeTrackedUploadEntry)
            .filter(Boolean);
    }

    function saveTrackedUploadEntries(entries) {
        var normalizedEntries = pruneTrackedUploadEntries(entries || []);
        try {
            if (!normalizedEntries.length) {
                window.localStorage.removeItem(UPLOAD_TRACK_STORAGE_KEY);
                return normalizedEntries;
            }
            window.localStorage.setItem(
                UPLOAD_TRACK_STORAGE_KEY,
                JSON.stringify(normalizedEntries)
            );
        } catch (error) {
            return normalizedEntries;
        }
        return normalizedEntries;
    }

    function pruneTrackedUploadEntries(entries) {
        var cutoff = Date.now() - UPLOAD_COMPLETED_RETENTION_MS;
        var deduped = {};
        (entries || []).forEach(function (entry) {
            var normalizedEntry = normalizeTrackedUploadEntry(entry);
            if (!normalizedEntry) {
                return;
            }
            if (
                normalizedEntry.complete
                && typeof normalizedEntry.updatedAt === 'number'
                && normalizedEntry.updatedAt < cutoff
            ) {
                return;
            }
            deduped[normalizedEntry.operationId] = normalizedEntry;
        });
        return Object.keys(deduped).map(function (key) {
            return deduped[key];
        });
    }

    function upsertTrackedUploadEntry(statusUrl, payload) {
        var entries = loadTrackedUploadEntries();
        var operationId = extractUploadOperationId(statusUrl);
        var matchedEntry = null;

        entries = entries.map(function (entry) {
            if (entry.operationId !== operationId) {
                return entry;
            }
            matchedEntry = entry;
            return entry;
        });

        if (!matchedEntry) {
            matchedEntry = normalizeTrackedUploadEntry({
                operationId: operationId,
                statusUrl: statusUrl,
                createdAt: Date.now(),
                updatedAt: Date.now(),
            });
            entries.push(matchedEntry);
        }

        if (payload && typeof payload === 'object') {
            matchedEntry.title = payload.title || matchedEntry.title || 'Processing file...';
            matchedEntry.detail = payload.detail || matchedEntry.detail || 'The server is processing the uploaded file.';
            if (typeof payload.percent === 'number') {
                matchedEntry.percent = payload.percent;
            }
            matchedEntry.complete = payload.complete === true;
            matchedEntry.success = payload.success === true;
            matchedEntry.failed = payload.failed === true;
            matchedEntry.redirectUrl = payload.redirect_url || matchedEntry.redirectUrl;
            matchedEntry.updatedAt = Date.now();
        }

        saveTrackedUploadEntries(entries);
        renderGlobalUploadMonitor(entries);
        if (entries.some(function (entry) { return !entry.complete; })) {
            scheduleUploadMonitorPoll(1200);
        }
        return matchedEntry;
    }

    function dismissTrackedUploadEntry(operationId) {
        var remainingEntries = loadTrackedUploadEntries().filter(function (entry) {
            return entry.operationId !== operationId;
        });
        saveTrackedUploadEntries(remainingEntries);
        renderGlobalUploadMonitor(remainingEntries);
    }

    function setTrackedUploadEntryFailure(statusUrl, title, detail) {
        upsertTrackedUploadEntry(statusUrl, {
            title: title,
            detail: detail,
            percent: 100,
            complete: true,
            success: false,
            failed: true,
        });
    }

    function createGlobalUploadElement(entry) {
        var wrapper = document.createElement('div');
        wrapper.className = 'hc-global-upload-item';
        if (entry.failed) {
            wrapper.classList.add('is-failed');
        } else if (entry.success) {
            wrapper.classList.add('is-succeeded');
        }

        var header = document.createElement('div');
        header.className = 'hc-global-upload-item-header';

        var headerText = document.createElement('div');
        var title = document.createElement('div');
        title.className = 'hc-global-upload-item-title';
        title.textContent = entry.title || 'Processing file...';
        headerText.appendChild(title);

        var detail = document.createElement('div');
        detail.className = 'hc-global-upload-item-detail';
        detail.textContent = entry.detail || 'The server is processing the uploaded file.';
        headerText.appendChild(detail);
        header.appendChild(headerText);

        var statusBadge = document.createElement('span');
        statusBadge.className = 'badge';
        if (entry.failed) {
            statusBadge.classList.add('badge-danger');
            statusBadge.textContent = 'Failed';
        } else if (entry.success) {
            statusBadge.classList.add('badge-success');
            statusBadge.textContent = 'Done';
        } else {
            statusBadge.classList.add('badge-info');
            statusBadge.textContent = Math.round(Math.max(0, Math.min(100, entry.percent || 0))) + '%';
        }
        header.appendChild(statusBadge);
        wrapper.appendChild(header);

        var progress = document.createElement('div');
        progress.className = 'progress mt-3';
        progress.setAttribute('role', 'progressbar');
        progress.setAttribute('aria-valuemin', '0');
        progress.setAttribute('aria-valuemax', '100');

        var progressBar = document.createElement('div');
        progressBar.className = 'progress-bar';
        if (!entry.complete) {
            progressBar.classList.add('progress-bar-striped', 'progress-bar-animated');
        }
        if (entry.failed) {
            progressBar.classList.add('bg-danger');
        }
        progressBar.style.width = Math.max(0, Math.min(100, entry.percent || 0)) + '%';
        progressBar.setAttribute('aria-valuenow', String(Math.round(entry.percent || 0)));
        progressBar.textContent = entry.success ? 'Done' : entry.failed ? 'Failed' : Math.round(entry.percent || 0) + '%';
        progress.appendChild(progressBar);
        wrapper.appendChild(progress);

        if (entry.complete) {
            var actions = document.createElement('div');
            actions.className = 'hc-global-upload-item-actions';

            if (entry.success && entry.redirectUrl) {
                var openLink = document.createElement('a');
                openLink.className = 'btn btn-sm btn-outline-primary';
                openLink.href = entry.redirectUrl;
                openLink.textContent = 'Open Result';
                actions.appendChild(openLink);
            }

            var dismissButton = document.createElement('button');
            dismissButton.type = 'button';
            dismissButton.className = 'btn btn-sm btn-outline-secondary';
            dismissButton.textContent = 'Dismiss';
            dismissButton.addEventListener('click', function () {
                dismissTrackedUploadEntry(entry.operationId);
            });
            actions.appendChild(dismissButton);
            wrapper.appendChild(actions);
        }

        return wrapper;
    }

    function renderGlobalUploadMonitor(entries) {
        var monitor = document.querySelector('[data-global-upload-monitor]');
        var list = document.querySelector('[data-global-upload-list]');
        if (!monitor || !list) {
            return;
        }

        var normalizedEntries = saveTrackedUploadEntries(entries || loadTrackedUploadEntries());
        normalizedEntries.sort(function (left, right) {
            if (left.complete !== right.complete) {
                return left.complete ? 1 : -1;
            }
            return (right.updatedAt || 0) - (left.updatedAt || 0);
        });

        list.innerHTML = '';
        normalizedEntries.forEach(function (entry) {
            list.appendChild(createGlobalUploadElement(entry));
        });
        toggleElement(monitor, normalizedEntries.length > 0);
    }

    function scheduleUploadMonitorPoll(delayMs) {
        if (uploadMonitorTimer) {
            window.clearTimeout(uploadMonitorTimer);
        }
        uploadMonitorTimer = window.setTimeout(function () {
            uploadMonitorTimer = 0;
            pollTrackedUploadEntries();
        }, typeof delayMs === 'number' ? delayMs : 1000);
    }

    function pollTrackedUploadEntries() {
        var entries = loadTrackedUploadEntries();
        var pendingEntries = entries.filter(function (entry) {
            return !entry.complete;
        });

        renderGlobalUploadMonitor(entries);
        if (!pendingEntries.length) {
            return;
        }

        var remainingRequests = pendingEntries.length;

        function finishPollCycle() {
            remainingRequests -= 1;
            if (remainingRequests > 0) {
                return;
            }
            var refreshedEntries = loadTrackedUploadEntries();
            renderGlobalUploadMonitor(refreshedEntries);
            if (refreshedEntries.some(function (entry) { return !entry.complete; })) {
                scheduleUploadMonitorPoll(1200);
            }
        }

        pendingEntries.forEach(function (entry) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', entry.statusUrl, true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

            xhr.addEventListener('load', function () {
                if (xhr.status >= 200 && xhr.status < 300) {
                    var payload = parseJsonString(xhr.responseText);
                    if (payload) {
                        upsertTrackedUploadEntry(entry.statusUrl, payload);
                    } else {
                        setTrackedUploadEntryFailure(
                            entry.statusUrl,
                            'Processing status unavailable.',
                            'The server returned an unexpected status payload.'
                        );
                    }
                } else if (xhr.status === 401 || xhr.status === 403 || xhr.status === 404) {
                    dismissTrackedUploadEntry(entry.operationId);
                } else {
                    setTrackedUploadEntryFailure(
                        entry.statusUrl,
                        'Processing status unavailable.',
                        'The browser could not confirm the latest upload status.'
                    );
                }
                finishPollCycle();
            });

            xhr.addEventListener('error', function () {
                setTrackedUploadEntryFailure(
                    entry.statusUrl,
                    'Processing status unavailable.',
                    'The browser lost connection while checking upload progress.'
                );
                finishPollCycle();
            });

            xhr.send();
        });
    }

    function setUploadStatus(form, options) {
        var statusPanel = form.querySelector('[data-upload-status]');
        var statusTitle = form.querySelector('[data-upload-status-title]');
        var statusDetail = form.querySelector('[data-upload-status-detail]');
        var progressBar = form.querySelector('[data-upload-progress-bar]');
        if (!statusPanel || !statusTitle || !statusDetail || !progressBar) {
            return;
        }

        statusPanel.classList.remove('hc-hidden');
        statusTitle.textContent = options.title || '';
        statusDetail.textContent = options.detail || '';

        progressBar.classList.remove('bg-danger');
        progressBar.classList.remove('progress-bar-striped');
        progressBar.classList.remove('progress-bar-animated');

        if (options.error) {
            progressBar.classList.add('bg-danger');
        }

        if (options.processing) {
            progressBar.classList.add('progress-bar-striped');
            progressBar.classList.add('progress-bar-animated');
        }

        var width = typeof options.percent === 'number'
            ? Math.max(0, Math.min(100, options.percent))
            : 0;
        progressBar.style.width = width + '%';
        progressBar.setAttribute('aria-valuenow', String(Math.round(width)));
        progressBar.textContent = options.label || (Math.round(width) + '%');
    }

    function bindUploadProgressForms() {
        document.querySelectorAll('form[data-upload-progress-form="true"]').forEach(function (form) {
            if (form.dataset.uploadProgressBound === 'true') {
                return;
            }
            form.dataset.uploadProgressBound = 'true';

            form.addEventListener('submit', function (event) {
                if (!window.FormData || !window.XMLHttpRequest) {
                    return;
                }
                if (form.dataset.uploadSubmitting === 'true') {
                    event.preventDefault();
                    return;
                }

                var fileInputs = Array.prototype.slice.call(
                    form.querySelectorAll('input[type="file"]')
                ).filter(function (input) {
                    return input.files && input.files.length > 0;
                });
                if (!fileInputs.length) {
                    return;
                }

                event.preventDefault();
                form.dataset.uploadSubmitting = 'true';

                var submitButtons = Array.prototype.slice.call(
                    form.querySelectorAll('button[type="submit"], input[type="submit"]')
                );
                submitButtons.forEach(function (button) {
                    button.disabled = true;
                });

                var totalBytes = fileInputs.reduce(function (total, input) {
                    return total + Array.prototype.slice.call(input.files).reduce(function (sum, file) {
                        return sum + (file.size || 0);
                    }, 0);
                }, 0);

                setUploadStatus(form, {
                    title: 'Uploading file...',
                    detail: totalBytes > 0
                        ? '0 B of ' + formatUploadBytes(totalBytes)
                        : 'Starting upload.',
                    percent: 0,
                    label: '0%',
                });

                var xhr = new XMLHttpRequest();
                xhr.open((form.method || 'POST').toUpperCase(), form.action || window.location.href, true);
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

                xhr.upload.addEventListener('progress', function (progressEvent) {
                    if (progressEvent.lengthComputable && progressEvent.total > 0) {
                        var percent = (progressEvent.loaded / progressEvent.total) * 100;
                        setUploadStatus(form, {
                            title: 'Uploading file...',
                            detail: formatUploadBytes(progressEvent.loaded) + ' of ' + formatUploadBytes(progressEvent.total),
                            percent: percent,
                            label: Math.round(percent) + '%',
                        });
                        return;
                    }

                    setUploadStatus(form, {
                        title: 'Uploading file...',
                        detail: 'Uploading to the server.',
                        percent: 100,
                        label: 'Uploading...',
                        processing: true,
                    });
                });

                xhr.upload.addEventListener('load', function () {
                    setUploadStatus(form, {
                        title: 'Upload complete. Processing file...',
                        detail: 'The server is validating and loading the file. Large uploads can take a while.',
                        percent: 100,
                        label: 'Processing...',
                        processing: true,
                    });
                });

                function restoreSubmitButtons() {
                    delete form.dataset.uploadSubmitting;
                    submitButtons.forEach(function (button) {
                        button.disabled = false;
                    });
                }

                function parseJsonResponse(targetXhr) {
                    var contentType = targetXhr.getResponseHeader('Content-Type') || '';
                    if (contentType.indexOf('application/json') === -1) {
                        return null;
                    }
                    return parseJsonString(targetXhr.responseText || '{}');
                }

                function pollUploadOperation(statusUrl) {
                    var statusXhr = new XMLHttpRequest();
                    statusXhr.open('GET', statusUrl, true);
                    statusXhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

                    statusXhr.addEventListener('load', function () {
                        if (!(statusXhr.status >= 200 && statusXhr.status < 300)) {
                            restoreSubmitButtons();
                            setUploadStatus(form, {
                                title: 'Processing status unavailable.',
                                detail: 'The file may still be processing, but the browser could not read the latest status. Please refresh to confirm.',
                                percent: 100,
                                label: 'Unknown',
                                error: true,
                            });
                            return;
                        }

                        var payload = parseJsonResponse(statusXhr);
                        if (!payload) {
                            restoreSubmitButtons();
                            setTrackedUploadEntryFailure(
                                statusUrl,
                                'Processing status unavailable.',
                                'The server returned an unexpected status payload. Please refresh and confirm the upload result.'
                            );
                            setUploadStatus(form, {
                                title: 'Processing status unavailable.',
                                detail: 'The server returned an unexpected status payload. Please refresh and confirm the upload result.',
                                percent: 100,
                                label: 'Unknown',
                                error: true,
                            });
                            return;
                        }

                        upsertTrackedUploadEntry(statusUrl, payload);
                        var percent = typeof payload.percent === 'number' ? payload.percent : 0;
                        var label = payload.complete
                            ? (payload.success ? 'Done' : 'Failed')
                            : (Math.round(percent) + '%');
                        setUploadStatus(form, {
                            title: payload.title || 'Processing file...',
                            detail: payload.detail || 'The server is processing the uploaded file.',
                            percent: percent,
                            label: label,
                            processing: !payload.complete,
                            error: payload.failed,
                        });

                        if (payload.success && payload.redirect_url) {
                            dismissTrackedUploadEntry(extractUploadOperationId(statusUrl));
                            window.location = payload.redirect_url;
                            return;
                        }

                        if (payload.failed) {
                            restoreSubmitButtons();
                            return;
                        }

                        window.setTimeout(function () {
                            pollUploadOperation(statusUrl);
                        }, 700);
                    });

                    statusXhr.addEventListener('error', function () {
                        restoreSubmitButtons();
                        setTrackedUploadEntryFailure(
                            statusUrl,
                            'Processing status unavailable.',
                            'The browser lost connection while checking server-side progress.'
                        );
                        setUploadStatus(form, {
                            title: 'Processing status unavailable.',
                            detail: 'The browser lost connection while checking server-side progress.',
                            percent: 100,
                            label: 'Unknown',
                            error: true,
                        });
                    });

                    statusXhr.send();
                }

                xhr.addEventListener('load', function () {
                    if (xhr.status >= 200 && xhr.status < 400) {
                        var payload = parseJsonResponse(xhr);
                        if (payload && payload.status_url) {
                            upsertTrackedUploadEntry(payload.status_url, payload);
                            setUploadStatus(form, {
                                title: payload.title || 'Processing file...',
                                detail: payload.detail || 'The server is validating and loading the file.',
                                percent: typeof payload.percent === 'number' ? payload.percent : 0,
                                label: 'Processing...',
                                processing: true,
                            });
                            pollUploadOperation(payload.status_url);
                            return;
                        }
                        if (xhr.responseURL && xhr.responseURL !== window.location.href) {
                            window.location = xhr.responseURL;
                            return;
                        }
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                        return;
                    }

                    var errorPayload = parseJsonResponse(xhr);
                    restoreSubmitButtons();
                    setUploadStatus(form, {
                        title: (errorPayload && errorPayload.title) || 'Upload failed.',
                        detail: (errorPayload && (errorPayload.detail || errorPayload.error))
                            || 'The server returned an unexpected response. Please retry.',
                        percent: 100,
                        label: 'Failed',
                        error: true,
                    });
                });

                xhr.addEventListener('error', function () {
                    restoreSubmitButtons();
                    setUploadStatus(form, {
                        title: 'Upload failed.',
                        detail: 'The network connection was interrupted during upload.',
                        percent: 100,
                        label: 'Failed',
                        error: true,
                    });
                });

                xhr.addEventListener('abort', function () {
                    restoreSubmitButtons();
                    setUploadStatus(form, {
                        title: 'Upload canceled.',
                        detail: 'The upload was canceled before completion.',
                        percent: 0,
                        label: 'Canceled',
                        error: true,
                    });
                });

                xhr.send(new FormData(form));
            });
        });
    }

    function bindFilterInputs() {
        document.querySelectorAll('[data-filter-input]').forEach(function (input) {
            if (input.dataset.filterBound === 'true') {
                return;
            }
            input.dataset.filterBound = 'true';

            var itemSelector = input.dataset.filterInput;
            var emptyTargetId = input.dataset.filterEmptyTarget;
            if (!itemSelector) {
                return;
            }

            function applyFilter() {
                var query = (input.value || '').trim().toLowerCase();
                var visibleCount = 0;

                document.querySelectorAll(itemSelector).forEach(function (item) {
                    var haystack = (
                        item.dataset.filterText
                        || item.textContent
                        || ''
                    ).toLowerCase();
                    var visible = !query || haystack.indexOf(query) !== -1;
                    item.classList.toggle('hc-hidden', !visible);
                    if (visible) {
                        visibleCount += 1;
                    }
                });

                if (emptyTargetId) {
                    toggleElement(
                        document.getElementById(emptyTargetId),
                        visibleCount === 0
                    );
                }
            }

            input.addEventListener('input', applyFilter);
            applyFilter();
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        renderGlobalUploadMonitor();
        if (loadTrackedUploadEntries().some(function (entry) { return !entry.complete; })) {
            scheduleUploadMonitorPoll(250);
        }
        bindSelectToggles();
        bindFileTriggers();
        bindConfirmForms();
        bindUploadProgressForms();
        bindFilterInputs();
    });
})();
