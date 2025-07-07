<?php

$logs = [];
$error = false;

$filename = '/var/www/html/modsec-logs/modsec.log';

// Add cache headers for better performance
$cacheTime = 300; // 5 minutes
$lastModified = file_exists($filename) ? filemtime($filename) : time();
$etag = md5($lastModified . filesize($filename));

header('Cache-Control: public, max-age=' . $cacheTime);
header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $lastModified) . ' GMT');
header('ETag: "' . $etag . '"');

// Check if client has cached version
if ((isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= $lastModified) ||
    (isset($_SERVER['HTTP_IF_NONE_MATCH']) && $_SERVER['HTTP_IF_NONE_MATCH'] === '"' . $etag . '"')) {
    header('HTTP/1.1 304 Not Modified');
    exit;
}

// Limit number of logs to process for performance (most recent 1000)
$maxLogs = 1000;
$logCount = 0;

if (file_exists($filename) && is_readable($filename)) {
    // Read file from end to get most recent logs first
    $handle = fopen($filename, 'r');
    if ($handle) {
        // Get file size and read from end
        fseek($handle, 0, SEEK_END);
        $filesize = ftell($handle);
        $lines = [];
        $buffer = '';
        $pos = $filesize;
        
        // Read file backwards to get recent logs first
        while ($pos > 0 && $logCount < $maxLogs) {
            $chunkSize = min(8192, $pos);
            $pos -= $chunkSize;
            fseek($handle, $pos);
            $chunk = fread($handle, $chunkSize);
            $buffer = $chunk . $buffer;
            
            while (($newlinePos = strrpos($buffer, "\n")) !== false && $logCount < $maxLogs) {
                $line = substr($buffer, $newlinePos + 1);
                if (!empty(trim($line))) {
                    array_push($lines, $line); // Lines are added in newest-first order when reading backwards
                    $logCount++;
                }
                $buffer = substr($buffer, 0, $newlinePos);
            }
        }
        
        // Lines are already in newest-first order (descending) from the backwards reading process
        // No need to reverse since we're reading from end of file and using array_push
        
        // Process the collected lines
        $pattern = '/(?P<timestamp>\d+\.\d+).*?\[client (?P<client_ip>[^\]]+)\].*?code (?P<status>\d+).*?phase (?P<phase>\d+)\).*?\[file "(?P<rule_file>[^"]+)"\] \[line "(?P<rule_line>\d+)"\] \[id "(?P<rule_id>\d+)"\] \[msg "(?P<message>[^"]+)"\] \[data "(?P<data>[^"]+)"\] \[severity "(?P<severity>[^"]+)"\] \[ver "(?P<version>[^"]+)"\](?P<tags>(?: \[tag "[^"]+"\])+).*?\[hostname "(?P<hostname>[^"]+)"\] \[uri "(?P<uri>[^"]+)"\] \[unique_id "(?P<unique_id>.*?) client-ip (?P<true_client_ip>[^"]+)"\]/';
        
        // Pre-create timezone object for performance
        $timezone = new DateTimeZone('Australia/Melbourne');
        
        foreach ($lines as $line) {
            if (preg_match($pattern, $line, $matches)) {
                preg_match_all('/\[tag "([^"]+)"\]/', $matches['tags'], $tagMatches);
                $tags = $tagMatches[1];
                
                $parts = parse_url($matches['uri']);
                $domain = $parts['host'] ?? $matches['hostname'];

                $dt = new DateTime('@'.$matches['timestamp']);
                $dt->setTimezone($timezone);
                $datetime = $dt->format('Y-m-d H:i:s T');

                $logEntry = [
                    'datetime' => $datetime,
                    'client' => $matches['client_ip'],
                    'status' => (int)$matches['status'],
                    'phase' => (int)$matches['phase'],
                    'message' => htmlspecialchars($matches['message'], ENT_QUOTES, 'UTF-8'),
                    'rule_file' => htmlspecialchars($matches['rule_file'], ENT_QUOTES, 'UTF-8'),
                    'rule_line' => (int)$matches['rule_line'],
                    'rule_id' => htmlspecialchars($matches['rule_id'], ENT_QUOTES, 'UTF-8'),
                    'data' => htmlspecialchars($matches['data'], ENT_QUOTES, 'UTF-8'),
                    'severity' => htmlspecialchars($matches['severity'], ENT_QUOTES, 'UTF-8'),
                    'version' => htmlspecialchars($matches['version'], ENT_QUOTES, 'UTF-8'),
                    'tags' => array_map(function($tag) { return htmlspecialchars($tag, ENT_QUOTES, 'UTF-8'); }, $tags),
                    'hostname' => htmlspecialchars($domain, ENT_QUOTES, 'UTF-8'),
                    'uri' => htmlspecialchars($matches['uri'], ENT_QUOTES, 'UTF-8'),
                    'unique_id' => htmlspecialchars($matches['unique_id'], ENT_QUOTES, 'UTF-8'),
                    'client_ip' => htmlspecialchars($matches['true_client_ip'], ENT_QUOTES, 'UTF-8'),
                ];

                $logs[] = $logEntry;
            }
        }
        
        fclose($handle);
    } else {                                                                                                                                     
        $error = "Unable to open the file.";
    }
} else {
    $error = "File does not exist or is not readable.";
}

// Step 1: Build a mapping of rule_id => color index
$ruleIdColorMap = [];
$colorPaletteSize = 10; // Number of pastel colors you have in CSS
$colorIdx = 0;
foreach ($logs as $log) {
    $rid = $log['rule_id'];
    if (!isset($ruleIdColorMap[$rid])) {
        $ruleIdColorMap[$rid] = $colorIdx % $colorPaletteSize;
        $colorIdx++;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="style.css">
    <title>ModSecurity Logs Viewer</title>
</head>
<body>
    <div class="container">
        <div class="header-container">
            <h1>ModSecurity Logs Viewer</h1>
            <div class="status-indicator" style="color: #b0bec5; font-size: 0.9em; text-align: center;">
                Showing <?php echo count($logs); ?> most recent entries
                <?php if ($maxLogs < 2000): ?>
                    (limited to <?php echo $maxLogs; ?> for performance)
                <?php endif; ?>
            </div>
            <div class="search-container">
                <input type="text" id="globalSearch" placeholder="Search all columns..." style="padding: 8px 12px; width: 400px; background: #232526; color: #e0e0e0; border: 1px solid #444; border-radius: 4px; font-size: 1em;">
                <span id="clearGlobalSearch" style="display: none; cursor: pointer; color: #aaa; font-size: 1.2em;">&#10005;</span>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th data-col="datetime" class="sortable">Date <span class="sort-icon">&#8595;</span></th>
                    <th data-col="hostname" class="sortable">Target <span class="sort-icon">&#8597;</span></th>
                    <th data-col="message" class="sortable">Message <span class="sort-icon">&#8597;</span></th>
                    <th data-col="rule_id" class="sortable">Rule ID <span class="sort-icon">&#8597;</span></th>
                    <th data-col="client_ip" class="sortable">Source IP <span class="sort-icon">&#8597;</span></th>
                    <th data-col="severity" class="sortable">Severity <span class="sort-icon">&#8597;</span></th>
                </tr>
            </thead>
            <tbody>
<?php
foreach ($logs as $index => $log) {
    // Map severity to color class
    $sev = strtolower($log['severity']);
    $sevClass = "sev-{$sev}";

    // Use the mapping for consistent pastel color per unique rule_id
    $ruleId = $log['rule_id'];
    $colorIdx = $ruleIdColorMap[$ruleId];
    $ruleIdClass = "ruleid-color-$colorIdx";

    // Store minimal data attribute - just the index for lookup
    echo "<tr class='log-row' data-log-index='{$index}'>";
    echo "<td style='width:200px'>" . $log['datetime'] . "</td>";
    echo "<td>" . $log['hostname'] . "</td>";
    echo "<td>" . $log['message'] . "</td>";
    echo "<td class='$ruleIdClass'>" . $log['rule_id'] . "</td>";
    echo "<td>" . $log['client_ip'] . "</td>";
    echo "<td class='$sevClass'>" . $log['severity'] . "</td>";
    echo "</tr>";
}
?>
</tbody>
            </table>
    </div>

    <!-- Modal structure -->
    <div id="rawLogModal" style="display:none; z-index:1000;">
        <div class="modal-header">
            <button id="toggleViewBtn">Raw JSON</button>
            <button id="closeModalBtn">Close</button>
        </div>
        <div id="modalRawLogContent"></div>
    </div>

    <!-- Loading indicator -->
    <div id="loadingIndicator">
        <div class="spinner"></div>
        Processing...
    </div>    <!-- jQuery script -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
    // Store logs data in JavaScript for better performance (properly escaped)
    const logsData = <?php echo json_encode($logs, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
    
    // Performance monitoring
    const perfStart = performance.now();
    
    $(function() {
        // Log performance when page is ready
        const loadTime = performance.now() - perfStart;
        console.log(`Page loaded in ${loadTime.toFixed(2)}ms with ${logsData.length} log entries`);
        
        let modalLastPos = null;

        // --- Pagination variables ---
        const rowsPerPage = 25;
        let currentPage = 1;
        let $allRows = $('tr.log-row');
        let $visibleRows = $allRows; // Track currently visible rows
        let totalRows = $allRows.length;
        let totalPages = Math.ceil(totalRows / rowsPerPage);

        function renderTablePage(page) {
            // Debug logging
            console.log(`Rendering page ${page}, visible rows: ${$visibleRows.length}, total pages: ${totalPages}`);
            
            // Hide all rows first
            $allRows.hide();
            
            // Show only the slice for current page from visible rows
            const startIndex = (page - 1) * rowsPerPage;
            const endIndex = startIndex + rowsPerPage;
            const rowsToShow = $visibleRows.slice(startIndex, endIndex);
            
            console.log(`Showing rows ${startIndex} to ${endIndex - 1} (${rowsToShow.length} rows)`);
            
            rowsToShow.show();
            
            $('#paginationInfo').text(`Page ${page} of ${totalPages} (${$visibleRows.length} total entries)`);
            $('#prevPage').prop('disabled', page === 1);
            $('#nextPage').prop('disabled', page === totalPages);
        }

        function updatePagination() {
            $visibleRows = $allRows.filter(function() {
                return $(this).css('display') !== 'none';
            });
            totalRows = $visibleRows.length;
            totalPages = Math.max(1, Math.ceil(totalRows / rowsPerPage));
            if (currentPage > totalPages) currentPage = totalPages;
            renderTablePage(currentPage);
        }

        // Insert pagination controls after the table
        $('table').after(`
            <div id="paginationControls" style="margin:18px 0; text-align:center;">
                <button id="prevPage">Prev</button>
                <span id="paginationInfo"></span>
                <button id="nextPage">Next</button>
            </div>
        `);

        $('#prevPage').on('click', function() {
            if (currentPage > 1) {
                currentPage--;
                renderTablePage(currentPage);
            }
        });
        $('#nextPage').on('click', function() {
            if (currentPage < totalPages) {
                currentPage++;
                renderTablePage(currentPage);
            }
        });

        // Initial render
        renderTablePage(currentPage);

        // --- Optimized modal functionality ---
        let isFormattedView = true;
        let currentLogData = null;

        function showModal(logIndex) {
            const log = currentSortedData[logIndex];
            if (!log) return;

            // Create a copy and decode HTML entities for display
            const logCopy = {};
            for (const [key, value] of Object.entries(log)) {
                if (typeof value === 'string') {
                    // Decode HTML entities for display in modal
                    const textarea = document.createElement('textarea');
                    textarea.innerHTML = value;
                    logCopy[key] = textarea.value;
                } else if (Array.isArray(value)) {
                    // Handle arrays (like tags)
                    logCopy[key] = value.map(item => {
                        if (typeof item === 'string') {
                            const textarea = document.createElement('textarea');
                            textarea.innerHTML = item;
                            return textarea.value;
                        }
                        return item;
                    });
                } else {
                    logCopy[key] = value;
                }
            }
            
            currentLogData = logCopy;
            displayModalContent();

            const $modal = $('#rawLogModal');
            if (modalLastPos) {
                // Account for scroll position when restoring modal position
                const scrollTop = $(window).scrollTop();
                const scrollLeft = $(window).scrollLeft();
                const maxLeft = scrollLeft + $(window).width() - $modal.outerWidth();
                const maxTop = scrollTop + $(window).height() - $modal.outerHeight();
                
                let left = Math.max(scrollLeft, Math.min(modalLastPos.left, maxLeft));
                let top = Math.max(scrollTop, Math.min(modalLastPos.top, maxTop));
                $modal.css({ left: left + 'px', top: top + 'px' });
            } else {
                const win = $(window);
                const scrollTop = $(window).scrollTop();
                const scrollLeft = $(window).scrollLeft();
                const left = scrollLeft + (win.width() - $modal.outerWidth()) / 2;
                const top = scrollTop + (win.height() - $modal.outerHeight()) / 2;
                $modal.css({ left: left + 'px', top: top + 'px' });
            }
            $modal.show();
            $('body').css('overflow', 'hidden'); // Disable page scrolling when modal is open
        }

        function displayModalContent() {
            if (!currentLogData) return;

            if (isFormattedView) {
                $('#modalRawLogContent').html(formatLogEntry(currentLogData));
                $('#toggleViewBtn').text('Raw JSON');
            } else {
                const rawLog = JSON.stringify(currentLogData, null, 2);
                $('#modalRawLogContent').html(`<pre style="margin: 0; color: #e0e0e0; background: #181a1b; padding: 10px; border-radius: 4px; font-size: 1em; white-space: pre-wrap; word-break: break-all;">${rawLog}</pre>`);
                $('#toggleViewBtn').text('Formatted');
            }
        }
        
        // Create formatted display instead of raw JSON
        const formatLogEntry = (log) => {
            const sections = [
                {
                    title: 'Basic Information',
                    fields: [
                        { label: 'Date/Time', value: log.datetime },
                        { label: 'Severity', value: log.severity },
                        { label: 'Status Code', value: log.status },
                        { label: 'Phase', value: log.phase }
                    ]
                },
                {
                    title: 'Rule Information',
                    fields: [
                        { label: 'Rule ID', value: log.rule_id },
                        { label: 'Message', value: log.message },
                        { label: 'Rule File', value: log.rule_file },
                        { label: 'Rule Line', value: log.rule_line },
                        { label: 'Version', value: log.version }
                    ]
                },
                {
                    title: 'Network Information',
                    fields: [
                        { label: 'Source IP', value: log.client_ip },
                        { label: 'Client', value: log.client },
                        { label: 'Hostname', value: log.hostname },
                        { label: 'URI', value: log.uri }
                    ]
                },
                {
                    title: 'Additional Data',
                    fields: [
                        { label: 'Data', value: log.data },
                        { label: 'Unique ID', value: log.unique_id },
                        { label: 'Tags', value: Array.isArray(log.tags) ? log.tags.join(', ') : log.tags }
                    ]
                }
            ];

            let html = '';
            sections.forEach(section => {
                html += `<div class="modal-section">`;
                html += `<h3 class="modal-section-title">${section.title}</h3>`;
                section.fields.forEach(field => {
                    if (field.value && field.value !== '') {
                        const displayValue = field.label === 'Data' && field.value.length > 100 
                            ? field.value.substring(0, 100) + '...\n' + field.value 
                            : field.value;
                        html += `<div class="modal-field">`;
                        html += `<span class="modal-label">${field.label}:</span>`;
                        html += `<span class="modal-value">${displayValue}</span>`;
                        html += `</div>`;
                    }
                });
                html += `</div>`;
            });

            return html;
        };

        // Use event delegation for better performance
        $('tbody').on('click', '.log-row', function() {
            const logIndex = parseInt($(this).data('log-index'));
            showModal(logIndex);
        });

        $('#closeModalBtn').on('click', function() {
            $('#rawLogModal').hide();
            $('body').css('overflow', ''); // Re-enable page scrolling
        });

        // Close modal with Escape key
        $(document).on('keydown', function(e) {
            if (e.key === 'Escape' && $('#rawLogModal').is(':visible')) {
                $('#rawLogModal').hide();
                $('body').css('overflow', ''); // Re-enable page scrolling
            }
        });

        $('#toggleViewBtn').on('click', function() {
            isFormattedView = !isFormattedView;
            displayModalContent();
        });

        // Draggable modal (updated to allow text selection and prevent close on drag)
        let isDragging = false, offsetX = 0, offsetY = 0, hasDragged = false;
        
        $('#rawLogModal').on('mousedown', function(e) {
            // Don't start dragging if clicking on the close button or text content
            if (e.target.id === 'closeModalBtn' || 
                $(e.target).closest('#modalRawLogContent').length > 0 ||
                $(e.target).hasClass('modal-value') ||
                $(e.target).hasClass('modal-label')) {
                return;
            }
            
            isDragging = true;
            hasDragged = false;
            $(this).css('opacity', '0.8');
            
            // Use offset() for consistent positioning relative to document
            const modalOffset = $(this).offset();
            offsetX = e.pageX - modalOffset.left;
            offsetY = e.pageY - modalOffset.top;
            
            $(document).on('mousemove.draggable', function(e2) {
                if (isDragging) {
                    hasDragged = true;
                    // Use pageX/pageY for consistent positioning relative to document
                    let left = e2.pageX - offsetX;
                    let top = e2.pageY - offsetY;
                    
                    // Account for scroll position in drag boundaries
                    const scrollTop = $(window).scrollTop();
                    const scrollLeft = $(window).scrollLeft();
                    const maxLeft = scrollLeft + $(window).width() - $('#rawLogModal').outerWidth();
                    const maxTop = scrollTop + $(window).height() - $('#rawLogModal').outerHeight();
                    
                    left = Math.max(scrollLeft, Math.min(left, maxLeft));
                    top = Math.max(scrollTop, Math.min(top, maxTop));
                    
                    $('#rawLogModal').css({ left: left + 'px', top: top + 'px', transform: 'none' });
                    modalLastPos = { left: left, top: top };
                }
            });
            
            $(document).on('mouseup.draggable', function() {
                isDragging = false;
                $('#rawLogModal').css('opacity', '1');
                $(document).off('.draggable');
                
                // Prevent click event from firing immediately after drag
                if (hasDragged) {
                    setTimeout(() => { hasDragged = false; }, 100);
                }
            });
        });

        // Close modal when clicking outside of it (but not after dragging)
        $('#rawLogModal').on('click', function(e) {
            if (e.target.id === 'rawLogModal' && !hasDragged) {
                $('#rawLogModal').hide();
                $('body').css('overflow', ''); // Re-enable page scrolling
            }
        });

        // Data-level sorting system
        let sortOrder = { datetime: 'desc' };
        let currentSortedData = [...logsData]; // Copy of data that gets sorted
        let currentSearchData = currentSortedData; // Data after search filtering
        
        // Data is already sorted newest first (descending) from PHP
        console.log('Initial data order - first entry:', currentSortedData[0]?.datetime, 'last entry:', currentSortedData[currentSortedData.length - 1]?.datetime);
        
        // Update UI to reflect initial sort state
        $('th[data-col="datetime"] .sort-icon').html('&#8595;');
        
        // Reset all other column sort icons to neutral state
        $('th[data-col]:not([data-col="datetime"]) .sort-icon').html('&#8597;');

        // Helper functions for sorting
        const isIPv4 = str => /^(\d{1,3}\.){3}\d{1,3}$/.test(str);
        const ip2num = ip => ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
        
        function decodeHtmlForSort(html) {
            const textarea = document.createElement('textarea');
            textarea.innerHTML = html;
            return textarea.value;
        }

        function sortDataByColumn(col, order) {
            currentSortedData.sort(function(a, b) {
                let valA, valB;

                // Get values based on column
                if (col === 'datetime') {
                    // Parse datetime more reliably by removing timezone and using consistent format
                    const parseDateTime = (dateStr) => {
                        // Remove timezone abbreviation (AEDT, AEST, etc.) and parse
                        const cleanDate = dateStr.replace(/\s+[A-Z]{3,4}$/, '');
                        const timestamp = new Date(cleanDate).getTime();
                        console.log(`Parsing "${dateStr}" -> "${cleanDate}" -> ${timestamp}`);
                        return timestamp;
                    };
                    valA = parseDateTime(a.datetime);
                    valB = parseDateTime(b.datetime);
                    
                    // Fallback to string comparison if date parsing fails
                    if (isNaN(valA) || isNaN(valB)) {
                        console.warn('Date parsing failed, falling back to string comparison');
                        valA = a.datetime;
                        valB = b.datetime;
                    }
                } else if (col === 'hostname') {
                    const hostA = decodeHtmlForSort(a.hostname);
                    const hostB = decodeHtmlForSort(b.hostname);
                    if (isIPv4(hostA) && isIPv4(hostB)) {
                        valA = ip2num(hostA);
                        valB = ip2num(hostB);
                    } else {
                        valA = hostA.toLowerCase();
                        valB = hostB.toLowerCase();
                    }
                } else if (col === 'message') {
                    valA = decodeHtmlForSort(a.message).toLowerCase();
                    valB = decodeHtmlForSort(b.message).toLowerCase();
                } else if (col === 'rule_id') {
                    const ruleA = decodeHtmlForSort(a.rule_id);
                    const ruleB = decodeHtmlForSort(b.rule_id);
                    const numA = parseInt(ruleA);
                    const numB = parseInt(ruleB);
                    if (!isNaN(numA) && !isNaN(numB)) {
                        valA = numA;
                        valB = numB;
                    } else {
                        valA = ruleA.toLowerCase();
                        valB = ruleB.toLowerCase();
                    }
                } else if (col === 'client_ip') {
                    const ipA = decodeHtmlForSort(a.client_ip);
                    const ipB = decodeHtmlForSort(b.client_ip);
                    valA = ip2num(ipA);
                    valB = ip2num(ipB);
                } else if (col === 'severity') {
                    valA = decodeHtmlForSort(a.severity).toLowerCase();
                    valB = decodeHtmlForSort(b.severity).toLowerCase();
                } else {
                    valA = a[col];
                    valB = b[col];
                }

                if (valA < valB) return order === 'asc' ? -1 : 1;
                if (valA > valB) return order === 'asc' ? 1 : -1;
                return 0;
            });
        }

        function rebuildTable() {
            const tbody = $('tbody');
            tbody.empty();
            
            // Get rule color mapping based on current sorted data
            const ruleIdColorMap = {};
            const colorPaletteSize = 10;
            let colorIdx = 0;
            currentSortedData.forEach(log => {
                const rid = decodeHtmlForSort(log.rule_id);
                if (!ruleIdColorMap[rid]) {
                    ruleIdColorMap[rid] = colorIdx % colorPaletteSize;
                    colorIdx++;
                }
            });

            currentSortedData.forEach((log, index) => {
                const sev = decodeHtmlForSort(log.severity).toLowerCase();
                const sevClass = `sev-${sev}`;
                const ruleId = decodeHtmlForSort(log.rule_id);
                const colorIdx = ruleIdColorMap[ruleId];
                const ruleIdClass = `ruleid-color-${colorIdx}`;

                const row = `<tr class='log-row' data-log-index='${index}'>
                    <td style='width:200px'>${log.datetime}</td>
                    <td>${log.hostname}</td>
                    <td>${log.message}</td>
                    <td class='${ruleIdClass}'>${log.rule_id}</td>
                    <td>${log.client_ip}</td>
                    <td class='${sevClass}'>${log.severity}</td>
                </tr>`;
                tbody.append(row);
            });

            // Update row references - this is crucial for pagination to work
            $allRows = $('tr.log-row');
            
            // Rebuild search index with new data order
            searchIndex = buildSearchIndex(currentSortedData);
            
            // Reset pagination and apply current search if active
            const currentSearchTerm = $('#globalSearch').val();
            if (currentSearchTerm) {
                // Reapply search with new sorted data
                performSearch(currentSearchTerm);
            } else {
                // Reset pagination to show all entries
                $visibleRows = $allRows;
                totalRows = $allRows.length;
                totalPages = Math.ceil(totalRows / rowsPerPage);
                currentPage = 1;
                renderTablePage(currentPage);
            }
        }

        $('.sortable').on('click', function(e) {
            if ($(e.target).is('input, input *')) return;

            const col = $(this).data('col');
            
            // Debug logging
            console.log(`Sorting by ${col}, current order: ${sortOrder[col] || 'none'}`);
            
            // Toggle sort order
            if (sortOrder[col] === 'asc') {
                sortOrder[col] = 'desc';
            } else if (sortOrder[col] === 'desc') {
                sortOrder[col] = 'asc';
            } else {
                // First time sorting this column
                sortOrder[col] = 'asc';
            }

            console.log(`New sort order for ${col}: ${sortOrder[col]}`);

            // Sort the data
            sortDataByColumn(col, sortOrder[col]);
            
            // Debug logging
            console.log(`Sorted ${currentSortedData.length} entries by ${col} in ${sortOrder[col]} order`);
            console.log('After sort - first entry:', currentSortedData[0]?.datetime, 'last entry:', currentSortedData[currentSortedData.length - 1]?.datetime);
            
            // Rebuild the table with sorted data
            rebuildTable();

            // Update sort icons
            $('.sort-icon').html('&#8597;');
            $(this).find('.sort-icon').html(sortOrder[col] === 'asc' ? '&#8593;' : '&#8595;');
            
            console.log(`Sort complete, now on page ${currentPage} of ${totalPages}`);
        });

        // Optimized search functionality with better performance
        let searchTimeout;
        const $searchInput = $('#globalSearch');
        const $clearSearch = $('#clearGlobalSearch');
        
        // Pre-build search index for better performance
        function buildSearchIndex(dataArray) {
            return dataArray.map((log, index) => {
                // Decode HTML entities for searching
                function decodeHtml(html) {
                    const textarea = document.createElement('textarea');
                    textarea.innerHTML = html;
                    return textarea.value;
                }
                
                return {
                    index,
                    text: [
                        log.datetime,
                        decodeHtml(log.hostname),
                        decodeHtml(log.message),
                        decodeHtml(log.rule_id),
                        decodeHtml(log.client_ip),
                        decodeHtml(log.severity)
                    ].join(' ').toLowerCase()
                };
            });
        }
        
        let searchIndex = buildSearchIndex(currentSortedData);
        
        function performSearch(searchTerm) {
            const term = searchTerm.toLowerCase();
            if (term === '') {
                // Show all rows when search is empty
                $allRows.show();
                $clearSearch.hide();
                
                // Reset pagination to show all entries
                $visibleRows = $allRows;
                totalRows = $allRows.length;
                totalPages = Math.ceil(totalRows / rowsPerPage);
                currentPage = 1;
                renderTablePage(currentPage);
                return;
            }
            
            // Show loading for large datasets
            if (searchIndex.length > 500) {
                $('#loadingIndicator').show();
            }
            
            // Use requestAnimationFrame for better performance
            requestAnimationFrame(() => {
                const matchingIndices = new Set();
                
                // Find matching entries in current search index
                searchIndex.forEach(item => {
                    if (item.text.indexOf(term) !== -1) {
                        matchingIndices.add(item.index);
                    }
                });
                
                // Update DOM in batches
                const batchSize = 50;
                let processed = 0;
                
                function processBatch() {
                    const endIndex = Math.min(processed + batchSize, $allRows.length);
                    
                    for (let i = processed; i < endIndex; i++) {
                        const $row = $allRows.eq(i);
                        const logIndex = parseInt($row.data('log-index'));
                        $row.toggle(matchingIndices.has(logIndex));
                    }
                    
                    processed = endIndex;
                    
                    if (processed < $allRows.length) {
                        requestAnimationFrame(processBatch);
                    } else {
                        $('#loadingIndicator').hide();
                        currentPage = 1;
                        updatePagination();
                    }
                }
                
                processBatch();
            });
        }
        
        $searchInput.on('input keyup', function() {
            const val = $(this).val();
            
            clearTimeout(searchTimeout);
            
            searchTimeout = setTimeout(() => {
                performSearch(val);
                $clearSearch.toggle(val.length > 0);
            }, 200); // Faster response time
        });

        $clearSearch.on('click', function() {
            clearTimeout(searchTimeout);
            $('#loadingIndicator').hide();
            $searchInput.val('');
            $allRows.show();
            $clearSearch.hide();
            
            // Reset pagination
            $visibleRows = $allRows;
            totalRows = $allRows.length;
            totalPages = Math.ceil(totalRows / rowsPerPage);
            currentPage = 1;
            renderTablePage(currentPage);
            
            $searchInput.focus();
        });
        
    });
    </script>
</body>
</html>
