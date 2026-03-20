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
                    try {
                        return JSON.parse(targetXhr.responseText || '{}');
                    } catch (error) {
                        return null;
                    }
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
                            setUploadStatus(form, {
                                title: 'Processing status unavailable.',
                                detail: 'The server returned an unexpected status payload. Please refresh and confirm the upload result.',
                                percent: 100,
                                label: 'Unknown',
                                error: true,
                            });
                            return;
                        }

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

    document.addEventListener('DOMContentLoaded', function () {
        bindSelectToggles();
        bindFileTriggers();
        bindConfirmForms();
        bindUploadProgressForms();
    });
})();
