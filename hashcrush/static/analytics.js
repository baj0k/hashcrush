(function () {
    var currentChartMarkup = {};
    var palette = {
        danger: '#b46d63',
        warning: '#b89b57',
        warningSoft: '#c0b37f',
        success: '#889a5b',
        neutral: '#7f7f72',
        neutralSoft: '#595950',
        background: '#151515',
        backgroundStrong: '#0f0f0f',
        border: '#2f2f2f',
        grid: '#3a3a3a',
        text: '#cccccc',
        textMuted: '#aaaaaa'
    };

    function byId(id) {
        return document.getElementById(id);
    }

    function isCompactViewport() {
        return Boolean(window.matchMedia && window.matchMedia('(max-width: 767.98px)').matches);
    }

    function escapeXml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function polarToCartesian(cx, cy, radius, angleInRadians) {
        return {
            x: cx + (radius * Math.cos(angleInRadians)),
            y: cy + (radius * Math.sin(angleInRadians))
        };
    }

    function donutSegmentPath(cx, cy, outerRadius, innerRadius, startAngle, endAngle) {
        var outerStart = polarToCartesian(cx, cy, outerRadius, startAngle);
        var outerEnd = polarToCartesian(cx, cy, outerRadius, endAngle);
        var innerEnd = polarToCartesian(cx, cy, innerRadius, endAngle);
        var innerStart = polarToCartesian(cx, cy, innerRadius, startAngle);
        var largeArcFlag = endAngle - startAngle > Math.PI ? 1 : 0;

        return [
            'M', outerStart.x, outerStart.y,
            'A', outerRadius, outerRadius, 0, largeArcFlag, 1, outerEnd.x, outerEnd.y,
            'L', innerEnd.x, innerEnd.y,
            'A', innerRadius, innerRadius, 0, largeArcFlag, 0, innerStart.x, innerStart.y,
            'Z'
        ].join(' ');
    }

    function placeholderSvg(title, message, key, width, height, chartClassName) {
        return [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ', width, ' ', height, '" class="', escapeXml(chartClassName || 'hc-chart-svg'), '" data-chart-key="', escapeXml(key), '" role="img" aria-label="', escapeXml(title), '" font-family="Segoe UI, Tahoma, sans-serif">',
            '<rect width="100%" height="100%" rx="16" fill="', palette.backgroundStrong, '" stroke="', palette.border, '"/>',
            '<text x="50%" y="42" text-anchor="middle" fill="', palette.text, '" font-size="20" font-weight="600">', escapeXml(title), '</text>',
            '<text x="50%" y="50%" text-anchor="middle" fill="', palette.textMuted, '" font-size="16">', escapeXml(message), '</text>',
            '</svg>'
        ].join('');
    }

    function formatPercent(value) {
        return value.toFixed(1).replace(/\.0$/, '') + '%';
    }

    function formatCount(value) {
        var numeric = Number(value);
        if (!window.isFinite(numeric)) {
            return String(value);
        }
        return numeric.toLocaleString('en-US');
    }

    function splitLegendLabel(label, value) {
        var text = String(label || '');
        var separator = ': ';
        var index = text.lastIndexOf(separator);
        if (index > 0) {
            return {
                name: text.slice(0, index),
                value: formatCount(text.slice(index + separator.length))
            };
        }
        return {
            name: text,
            value: formatCount(value)
        };
    }

    function humanizeLegendName(value) {
        return String(value || '')
            .replace(/([a-z])([A-Z])/g, '$1 $2')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function wrapText(text, maxLineLength, maxLines) {
        var normalized = String(text || '').trim();
        if (!normalized) {
            return [''];
        }

        var words = normalized.split(/\s+/);
        var lines = [];
        var current = '';

        words.forEach(function (word) {
            if (!current) {
                current = word;
                return;
            }
            if ((current + ' ' + word).length <= maxLineLength) {
                current += ' ' + word;
                return;
            }
            lines.push(current);
            current = word;
        });

        if (current) {
            lines.push(current);
        }

        if (lines.length <= maxLines) {
            return lines;
        }

        var trimmed = lines.slice(0, maxLines);
        trimmed[maxLines - 1] = truncateLabel(trimmed[maxLines - 1], maxLineLength);
        return trimmed;
    }

    function multilineText(markup) {
        return [
            '<text x="' + markup.x + '" y="' + markup.y + '" fill="' + markup.fill + '" font-size="' + markup.fontSize + '" font-weight="' + (markup.fontWeight || '400') + '">',
            markup.lines.map(function (line, index) {
                return '<tspan x="' + markup.x + '" dy="' + (index === 0 ? '0' : markup.lineHeight) + '">' + escapeXml(line) + '</tspan>';
            }).join(''),
            '</text>'
        ].join('');
    }

    function createDonutChart(config) {
        var compact = Boolean(config.compact);
        var total = config.values.reduce(function (sum, value) { return sum + value; }, 0);
        var width = compact ? 320 : 360;
        var activeValues = config.values.filter(function (value) { return value > 0; }).length;
        var height = compact ? 244 : 260;
        if (total <= 0) {
            return placeholderSvg(config.title, 'No data in the selected scope.', config.key, width, height, 'hc-chart-svg hc-chart-svg--donut');
        }

        var cx = Math.round(width / 2);
        var cy = compact ? 88 : 94;
        var outerRadius = compact ? 62 : 68;
        var innerRadius = compact ? 38 : 42;
        var angle = -Math.PI / 2;
        var segments = [];
        var legendEntries = [];
        var colors = config.colors;
        var legendTop = cy + outerRadius + (compact ? 22 : 28);
        var legendRowHeight = compact ? 28 : 32;
        var legendMarkerX = compact ? 20 : 24;
        var legendLabelX = compact ? 40 : 46;
        var legendRightX = width - (compact ? 20 : 24);
        var centerPrimaryFontSize = compact ? 23 : 25;
        var centerSecondaryFontSize = compact ? 11 : 12;
        var legendLabelFontSize = compact ? 13 : 14;
        var legendValueFontSize = compact ? 12 : 13;

        segments.push(
            '<circle cx="' + cx + '" cy="' + cy + '" r="' + ((outerRadius + innerRadius) / 2) + '" fill="none" stroke="' + palette.grid + '" stroke-width="' + (outerRadius - innerRadius) + '"/>'
        );

        config.values.forEach(function (value, index) {
            if (value <= 0) {
                return;
            }
            var color = colors[index % colors.length];
            var portion = value / total;
            var nextAngle = angle + (portion * Math.PI * 2);
            var legendLabel = splitLegendLabel(config.labels[index], value);

            if (activeValues === 1) {
                segments.push(
                    '<circle cx="' + cx + '" cy="' + cy + '" r="' + ((outerRadius + innerRadius) / 2) + '" fill="none" stroke="' + color + '" stroke-width="' + (outerRadius - innerRadius) + '"/>'
                );
            } else {
                segments.push('<path d="' + donutSegmentPath(cx, cy, outerRadius, innerRadius, angle, nextAngle) + '" fill="' + color + '" stroke="' + palette.backgroundStrong + '" stroke-width="2"/>');
            }

            legendEntries.push({
                color: color,
                label: legendLabel.name,
                valueText: legendLabel.value,
                fullLabel: config.labels[index],
                percent: (portion * 100),
                displayLabel: truncateLabel(humanizeLegendName(legendLabel.name), 24)
            });
            angle = nextAngle;
        });

        height = Math.max(compact ? 256 : 280, legendTop + (legendEntries.length * legendRowHeight) + 18);
        var legend = legendEntries.map(function (entry, index) {
            var y = legendTop + (index * legendRowHeight);
            return (
                '<g transform="translate(0 ' + y + ')">' +
                    '<title>' + escapeXml(entry.fullLabel + ' (' + formatPercent(entry.percent) + ')') + '</title>' +
                    '<rect x="' + legendMarkerX + '" y="-6.5" width="11" height="11" rx="3" fill="' + entry.color + '"/>' +
                    '<text x="' + legendLabelX + '" y="0" dominant-baseline="middle" fill="' + palette.text + '" font-size="' + legendLabelFontSize + '" font-weight="600">' + escapeXml(entry.displayLabel) + '</text>' +
                    '<text x="' + legendRightX + '" y="0" dominant-baseline="middle" text-anchor="end" fill="' + palette.textMuted + '" font-size="' + legendValueFontSize + '">' + escapeXml(entry.valueText + ' | ' + formatPercent(entry.percent)) + '</text>' +
                '</g>'
            );
        }).join('');

        var centerPrimary = config.centerText || String(total);
        var centerSecondary = config.centerText ? (String(total) + ' total') : 'total';

        return [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ', width, ' ', height, '" class="hc-chart-svg hc-chart-svg--donut" data-chart-key="', escapeXml(config.key), '" role="img" aria-label="', escapeXml(config.title), '" font-family="Segoe UI, Tahoma, sans-serif">',
            '<rect width="100%" height="100%" rx="16" fill="', palette.backgroundStrong, '" stroke="', palette.border, '"/>',
            segments.join(''),
            '<text x="', cx, '" y="', cy - 4, '" text-anchor="middle" fill="', palette.text, '" font-size="', centerPrimaryFontSize, '" font-weight="700">', escapeXml(centerPrimary), '</text>',
            '<text x="', cx, '" y="', cy + 17, '" text-anchor="middle" fill="', palette.textMuted, '" font-size="', centerSecondaryFontSize, '">', escapeXml(centerSecondary), '</text>',
            legend,
            '</svg>'
        ].join('');
    }

    function truncateLabel(label, maxLength) {
        if (label.length <= maxLength) {
            return label;
        }
        return label.slice(0, maxLength - 1) + '…';
    }

    function createHorizontalBarChart(config) {
        var compact = Boolean(config.compact);
        var totalBars = config.values.length;
        var width = compact ? 840 : 960;
        var height = Math.max(compact ? 220 : 236, (compact ? 56 : 64) + (totalBars * (compact ? 24 : 28)));
        if (totalBars === 0) {
            return placeholderSvg(config.title, 'No data in the selected scope.', config.key, width, height, 'hc-chart-svg hc-chart-svg--bar');
        }

        var maxValue = Math.max.apply(null, config.values.concat([0]));
        var total = config.values.reduce(function (sum, value) { return sum + value; }, 0);
        if (maxValue <= 0) {
            return placeholderSvg(config.title, 'No data in the selected scope.', config.key, width, height, 'hc-chart-svg hc-chart-svg--bar');
        }

        var left = compact ? 150 : 184;
        var right = compact ? 136 : 156;
        var top = compact ? 24 : 28;
        var barHeight = compact ? 12 : 14;
        var barGap = compact ? 12 : 14;
        var chartWidth = width - left - right;
        var gridLines = 4;
        var grid = [];
        var bars = [];
        var gridBottom = height - (compact ? 18 : 20);
        var gridLabelY = height - (compact ? 8 : 10);
        var gridFontSize = compact ? 11 : 12;
        var labelFontSize = compact ? 12 : 14;
        var valueFontSize = compact ? 12 : 14;
        var labelMaxLength = compact ? 18 : 22;
        var valueX = width - (compact ? 14 : 16);

        for (var i = 0; i <= gridLines; i += 1) {
            var value = Math.round((maxValue / gridLines) * i);
            var x = left + ((chartWidth / gridLines) * i);
            grid.push('<line x1="' + x + '" y1="' + top + '" x2="' + x + '" y2="' + gridBottom + '" stroke="' + palette.grid + '" stroke-width="1"/>');
            grid.push('<text x="' + x + '" y="' + gridLabelY + '" text-anchor="middle" fill="' + palette.textMuted + '" font-size="' + gridFontSize + '">' + formatCount(value) + '</text>');
        }

        config.labels.forEach(function (label, index) {
            var y = top + (index * (barHeight + barGap));
            var barWidth = maxValue === 0 ? 0 : (config.values[index] / maxValue) * chartWidth;
            var percent = total > 0 ? formatPercent((config.values[index] / total) * 100) : '0%';
            bars.push(
                '<title>' + escapeXml(String(label) + ': ' + formatCount(config.values[index]) + ' (' + percent + ')') + '</title>' +
                '<rect x="' + left + '" y="' + y + '" width="' + chartWidth + '" height="' + barHeight + '" rx="4" fill="' + palette.background + '" stroke="' + palette.grid + '" stroke-width="1"/>' +
                '<text x="' + (left - 12) + '" y="' + (y + (barHeight / 2)) + '" dominant-baseline="middle" text-anchor="end" fill="' + palette.textMuted + '" font-size="' + labelFontSize + '">' + escapeXml(truncateLabel(label, labelMaxLength)) + '</text>' +
                '<rect x="' + left + '" y="' + y + '" width="' + barWidth + '" height="' + barHeight + '" rx="4" fill="' + config.barColor + '"/>' +
                '<text x="' + valueX + '" y="' + (y + (barHeight / 2)) + '" dominant-baseline="middle" text-anchor="end" fill="' + palette.text + '" font-size="' + valueFontSize + '" font-weight="600">' + formatCount(config.values[index]) + ' | ' + percent + '</text>'
            );
        });

        return [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ', width, ' ', height, '" class="hc-chart-svg hc-chart-svg--bar" data-chart-key="', escapeXml(config.key), '" role="img" aria-label="', escapeXml(config.title), '" font-family="Segoe UI, Tahoma, sans-serif">',
            '<rect width="100%" height="100%" rx="16" fill="', palette.backgroundStrong, '" stroke="', palette.border, '"/>',
            grid.join(''),
            bars.join(''),
            '</svg>'
        ].join('');
    }

    function downloadSvg(filename, svgMarkup) {
        var blob = new Blob([svgMarkup], { type: 'image/svg+xml;charset=utf-8' });
        var url = window.URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.setTimeout(function () {
            window.URL.revokeObjectURL(url);
        }, 1000);
    }

    function donutPlaceholder(title, key, message, compact) {
        return placeholderSvg(title, message, key, compact ? 320 : 360, compact ? 244 : 260, 'hc-chart-svg hc-chart-svg--donut');
    }

    function barPlaceholder(title, key, message, compact) {
        return placeholderSvg(title, message, key, compact ? 840 : 960, compact ? 220 : 236, 'hc-chart-svg hc-chart-svg--bar');
    }

    function buildFallbackCharts(message, compact) {
        return {
            recovered_accounts: donutPlaceholder('Recovered Accounts', 'recovered_accounts', message, compact),
            password_quality: donutPlaceholder('Recovered Password Quality', 'password_quality', message, compact),
            hash_reuse: donutPlaceholder('Hash Reuse', 'hash_reuse', message, compact),
            composition_makeup: donutPlaceholder('Composition Makeup', 'composition_makeup', message, compact),
            passwords_count_len: barPlaceholder('Passwords Count by Length', 'passwords_count_len', message, compact)
        };
    }

    function safeChart(factory, fallbackMarkup) {
        try {
            return factory();
        } catch (error) {
            console.error('Analytics chart render failed.', error);
            return fallbackMarkup;
        }
    }

    function buildChartMarkup(payload) {
        var compact = isCompactViewport();
        return {
            recovered_accounts: safeChart(function () {
                return createDonutChart({
                    key: 'recovered_accounts',
                    title: 'Recovered Accounts',
                    labels: payload.recovered_accounts.labels,
                    values: payload.recovered_accounts.values,
                    centerText: payload.recovered_accounts.center_text,
                    colors: [palette.danger, palette.success],
                    compact: compact
                });
            }, donutPlaceholder('Recovered Accounts', 'recovered_accounts', 'Unable to render chart.', compact)),
            password_quality: safeChart(function () {
                return createDonutChart({
                    key: 'password_quality',
                    title: 'Recovered Password Quality',
                    labels: payload.password_quality.labels,
                    values: payload.password_quality.values,
                    centerText: '',
                    colors: [palette.danger, palette.success],
                    compact: compact
                });
            }, donutPlaceholder('Recovered Password Quality', 'password_quality', 'Unable to render chart.', compact)),
            hash_reuse: safeChart(function () {
                return createDonutChart({
                    key: 'hash_reuse',
                    title: 'Hash Reuse',
                    labels: payload.hash_reuse.labels,
                    values: payload.hash_reuse.values,
                    centerText: '',
                    colors: [palette.warning, palette.success],
                    compact: compact
                });
            }, donutPlaceholder('Hash Reuse', 'hash_reuse', 'Unable to render chart.', compact)),
            composition_makeup: safeChart(function () {
                return createDonutChart({
                    key: 'composition_makeup',
                    title: 'Composition Makeup',
                    labels: payload.composition_makeup.labels,
                    values: payload.composition_makeup.values,
                    centerText: '',
                    colors: [palette.danger, palette.warning, palette.warningSoft, palette.success, palette.neutral],
                    compact: compact
                });
            }, donutPlaceholder('Composition Makeup', 'composition_makeup', 'Unable to render chart.', compact)),
            passwords_count_len: safeChart(function () {
                return createHorizontalBarChart({
                    key: 'passwords_count_len',
                    title: 'Passwords Count by Length',
                    labels: payload.passwords_count_len.labels.map(function (value) { return String(value); }),
                    values: payload.passwords_count_len.values,
                    barColor: palette.success,
                    compact: compact
                });
            }, barPlaceholder('Passwords Count by Length', 'passwords_count_len', 'Unable to render chart.', compact))
        };
    }

    function mountChartMarkup(chartMarkup) {
        Object.keys(chartMarkup).forEach(function (key) {
            var slot = document.querySelector('[data-chart-slot="' + key + '"]');
            if (slot) {
                slot.innerHTML = chartMarkup[key];
                slot.dataset.chartRendered = 'true';
            }
        });
    }

    function bindDownloadButtons() {
        document.querySelectorAll('[data-chart-download]').forEach(function (button) {
            if (button.dataset.chartDownloadBound === 'true') {
                return;
            }
            button.dataset.chartDownloadBound = 'true';
            button.addEventListener('click', function () {
                var chartKey = button.dataset.chartDownload;
                if (currentChartMarkup[chartKey]) {
                    downloadSvg(chartKey + '.svg', currentChartMarkup[chartKey]);
                }
            });
        });

        var downloadAllButton = document.querySelector('[data-chart-download-all]');
        if (downloadAllButton && downloadAllButton.dataset.chartDownloadBound !== 'true') {
            downloadAllButton.dataset.chartDownloadBound = 'true';
            downloadAllButton.addEventListener('click', function () {
                Object.keys(currentChartMarkup).forEach(function (chartKey, index) {
                    window.setTimeout(function () {
                        downloadSvg(chartKey + '.svg', currentChartMarkup[chartKey]);
                    }, index * 150);
                });
            });
        }
    }

    function renderAnalyticsCharts() {
        var dataElement = byId('analytics-chart-data');
        var payload;
        var compact = isCompactViewport();
        if (!dataElement) {
            return;
        }

        try {
            payload = JSON.parse(dataElement.textContent || '{}');
            currentChartMarkup = buildChartMarkup(payload);
        } catch (error) {
            console.error('Analytics chart data could not be parsed.', error);
            currentChartMarkup = buildFallbackCharts('Unable to load chart data.', compact);
        }

        mountChartMarkup(currentChartMarkup);
        bindDownloadButtons();
    }

    function initializeAnalyticsCharts() {
        renderAnalyticsCharts();
    }

    var resizeTimer = null;
    function scheduleAnalyticsRender() {
        if (resizeTimer) {
            window.clearTimeout(resizeTimer);
        }
        resizeTimer = window.setTimeout(function () {
            renderAnalyticsCharts();
        }, 120);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeAnalyticsCharts);
    } else {
        initializeAnalyticsCharts();
    }
    window.addEventListener('pageshow', initializeAnalyticsCharts);
    window.addEventListener('resize', scheduleAnalyticsRender);
})();
