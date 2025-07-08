<?php

$logs = [];
$error = false;

$filename = '/var/www/html/modsec-logs/modsec.log';

// Add cache headers for better performance
$cacheTime = 300; // 5 minutes
$lastModified = file_exists($filename) ? filemtime($filename) : time();
$fileSize = file_exists($filename) ? filesize($filename) : 0;
$etag = md5($lastModified . $fileSize);

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
        <div class="header-section">
            <div class="header-container">
                <h1>ModSecurity Logs Viewer v2.1</h1>
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
        </div>

        <div class="table-container">
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

        <div class="pagination-section">
            <div id="paginationControls">
                <!-- Pagination controls will be inserted here by JavaScript -->
            </div>
        </div>
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
        let modalInitialized = false; // Track if modal has been displayed before

        // --- Pagination variables ---
        let rowsPerPage = 100; // Increased from 25 to 100
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
            $('#firstPage').prop('disabled', page === 1);
            $('#prevPage').prop('disabled', page === 1);
            $('#nextPage').prop('disabled', page === totalPages);
            $('#lastPage').prop('disabled', page === totalPages);
            $('#pageInput').val(page);
        }

        function updatePagination() {
            $visibleRows = $allRows.filter(function() {
                return $(this).css('display') !== 'none';
            });
            totalRows = $visibleRows.length;
            totalPages = Math.max(1, Math.ceil(totalRows / rowsPerPage));
            if (currentPage > totalPages) currentPage = totalPages;
            
            // Update the max attribute for the input
            $('#pageInput').attr('max', totalPages);
            
            renderTablePage(currentPage);
        }

        // Insert pagination controls into the designated container
        $('#paginationControls').html(`
            <button id="firstPage">First</button>
            <button id="prevPage">Prev</button>
            <span class="page-info">
                <input type="number" id="pageInput" min="1">
            </span>
            <button id="nextPage">Next</button>
            <button id="lastPage">Last</button>
            <span class="rows-per-page-container">
                <label for="rowsPerPageSelect">Rows:</label>
                <select id="rowsPerPageSelect">
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100" selected>100</option>
                    <option value="200">200</option>
                    <option value="500">500</option>
                </select>
            </span>
            <span id="paginationInfo" class="pagination-info"></span>
        `);

        $('#firstPage').on('click', function() {
            if (currentPage !== 1) {
                currentPage = 1;
                renderTablePage(currentPage);
            }
        });
        
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
        
        $('#lastPage').on('click', function() {
            if (currentPage !== totalPages) {
                currentPage = totalPages;
                renderTablePage(currentPage);
            }
        });
        
        // Handle direct page input
        $('#pageInput').on('change keypress', function(e) {
            if (e.type === 'keypress' && e.which !== 13) return; // Only process on Enter key or change event
            
            const inputPage = parseInt($(this).val());
            if (inputPage && inputPage >= 1 && inputPage <= totalPages && inputPage !== currentPage) {
                currentPage = inputPage;
                renderTablePage(currentPage);
            } else {
                // Reset to current page if invalid input
                $(this).val(currentPage);
            }
        });

        // Handle rows per page change
        $('#rowsPerPageSelect').on('change', function() {
            rowsPerPage = parseInt($(this).val());
            // Recalculate pagination
            totalPages = Math.ceil($visibleRows.length / rowsPerPage);
            currentPage = 1; // Reset to first page
            $('#pageInput').attr('max', totalPages);
            renderTablePage(currentPage);
        });

        // Initial render
        $('#pageInput').attr('max', totalPages);
        renderTablePage(currentPage);

        // --- Optimized modal functionality ---
        let isFormattedView = true;
        let currentLogData = null;

        function showModal(logIndex) {
            const log = currentSortedData[logIndex];
            if (!log) return;

            // Create a copy but DO NOT decode HTML entities to prevent XSS
            // Keep the data as-is with HTML entities encoded for security
            currentLogData = { ...log };
            displayModalContent();

            const $modal = $('#rawLogModal');
            if (modalLastPos) {
                // Restore previous position and size - user has already positioned/resized modal
                const scrollTop = $(window).scrollTop();
                const scrollLeft = $(window).scrollLeft();
                const maxLeft = scrollLeft + $(window).width() - $modal.outerWidth();
                const maxTop = scrollTop + $(window).height() - $modal.outerHeight();
                
                let left = Math.max(scrollLeft, Math.min(modalLastPos.left, maxLeft));
                let top = Math.max(scrollTop, Math.min(modalLastPos.top, maxTop));
                $modal.css({ left: left + 'px', top: top + 'px' });
            } else if (!modalInitialized) {
                // Only set responsive size on the very first display
                const win = $(window);
                const scrollTop = $(window).scrollTop();
                const scrollLeft = $(window).scrollLeft();
                
                // Calculate responsive size with some padding from window edges
                const padding = 40; // 40px padding from each edge
                const maxWidth = win.width() - (padding * 2);
                const maxHeight = win.height() - (padding * 2);
                
                // Set preferred size but constrain to window size
                const preferredWidth = 900;
                const preferredHeight = 700;
                const modalWidth = Math.min(preferredWidth, maxWidth);
                const modalHeight = Math.min(preferredHeight, maxHeight);
                
                // Center the modal in the viewport
                const left = scrollLeft + (win.width() - modalWidth) / 2;
                const top = scrollTop + (win.height() - modalHeight) / 2;
                
                $modal.css({ 
                    left: left + 'px', 
                    top: top + 'px',
                    width: modalWidth + 'px',
                    height: modalHeight + 'px'
                });
                
                // Mark modal as initialized
                modalInitialized = true;
            } else {
                // Modal has been displayed before but no saved position - just center it
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
                // Create a decoded version of the log data for JSON display
                const decodedLogData = {};
                Object.keys(currentLogData).forEach(key => {
                    if (Array.isArray(currentLogData[key])) {
                        // Handle arrays (like tags)
                        decodedLogData[key] = currentLogData[key].map(item => 
                            typeof item === 'string' ? decodeHtmlEntities(item) : item
                        );
                    } else if (typeof currentLogData[key] === 'string') {
                        // Decode HTML entities for string values
                        decodedLogData[key] = decodeHtmlEntities(currentLogData[key]);
                    } else {
                        // Keep numbers and other types as-is
                        decodedLogData[key] = currentLogData[key];
                    }
                });
                
                const rawLog = JSON.stringify(decodedLogData, null, 2);
                // Use text() instead of html() to prevent XSS execution
                $('#modalRawLogContent').empty().append($('<pre>').css({
                    'margin': '0',
                    'color': '#e0e0e0',
                    'background': '#181a1b',
                    'padding': '10px',
                    'border-radius': '4px',
                    'font-size': '1em',
                    'white-space': 'pre-wrap',
                    'word-break': 'break-all'
                }).text(rawLog));
                $('#toggleViewBtn').text('Formatted');
            }
        }
        
        // Helper function to safely decode HTML entities for display
        function decodeHtmlEntities(str) {
            if (typeof str !== 'string') return str;
            const textarea = document.createElement('textarea');
            textarea.innerHTML = str;
            return textarea.value;
        }

        // Create formatted display instead of raw JSON - XSS SAFE VERSION with readable HTML entities
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

            // Create DOM elements safely to prevent XSS
            const $container = $('<div>');
            
            sections.forEach(section => {
                const $section = $('<div>').addClass('modal-section');
                const $title = $('<h3>').addClass('modal-section-title').text(section.title);
                $section.append($title);
                
                section.fields.forEach(field => {
                    if (field.value && field.value !== '') {
                        const $field = $('<div>').addClass('modal-field');
                        const $label = $('<span>').addClass('modal-label').text(field.label + ':');
                        
                        let displayValue = field.value;
                        
                        // Decode HTML entities for readable display while maintaining security
                        if (typeof displayValue === 'string') {
                            displayValue = decodeHtmlEntities(displayValue);
                        } else if (Array.isArray(displayValue)) {
                            displayValue = displayValue.map(item => 
                                typeof item === 'string' ? decodeHtmlEntities(item) : item
                            ).join(', ');
                        }
                        
                        if (field.label === 'Data' && typeof displayValue === 'string' && displayValue.length > 100) {
                            displayValue = displayValue.substring(0, 100) + '...\n' + displayValue;
                        }
                        
                        // Use .text() to safely display the decoded content without XSS risk
                        const $value = $('<span>').addClass('modal-value').text(displayValue);
                        
                        $field.append($label).append($value);
                        $section.append($field);
                    }
                });
                
                $container.append($section);
            });

            return $container.html();
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

        // Draggable modal (updated to allow text selection, prevent close on drag, and handle resizing)
        let isDragging = false, offsetX = 0, offsetY = 0, hasDragged = false;
        let isResizing = false, initialSize = null;
        let scrollPosition = null;
        
        $('#rawLogModal').on('mousedown', function(e) {
            // Don't start dragging if clicking on the close button, text content, or resize area
            if (e.target.id === 'closeModalBtn' || 
                $(e.target).closest('#modalRawLogContent').length > 0 ||
                $(e.target).hasClass('modal-value') ||
                $(e.target).hasClass('modal-label')) {
                return;
            }
            
            // Check if clicking near the bottom-right corner (resize area)
            const rect = this.getBoundingClientRect();
            const isNearBottomRight = (e.clientX > rect.right - 20) && (e.clientY > rect.bottom - 20);
            
            if (isNearBottomRight) {
                // Track that we're starting a resize operation
                isResizing = true;
                initialSize = { width: rect.width, height: rect.height };
                
                // Prevent text selection during resize
                $('body').addClass('no-select resizing-modal');
                
                // Store current scroll position to prevent unwanted scrolling
                const $content = $('#modalRawLogContent');
                scrollPosition = $content.scrollTop();
                
                // Prevent scrolling during resize by temporarily disabling it
                $content.css('overflow-y', 'hidden');
                
                // Let the browser handle resizing
                return;
            }
            
            isDragging = true;
            hasDragged = false;
            $(this).css('opacity', '0.8');
            
            // Prevent text selection during drag
            $('body').addClass('no-select dragging-modal');
            
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
                
                // Re-enable text selection after drag
                $('body').removeClass('no-select dragging-modal');
                
                // Prevent click event from firing immediately after drag
                if (hasDragged) {
                    setTimeout(() => { hasDragged = false; }, 100);
                }
            });
        });
        
        // Track resize operations to prevent modal closing and content scrolling
        $(document).on('mouseup', function() {
            if (isResizing) {
                const currentRect = document.getElementById('rawLogModal').getBoundingClientRect();
                const hasResized = initialSize && (
                    Math.abs(currentRect.width - initialSize.width) > 5 || 
                    Math.abs(currentRect.height - initialSize.height) > 5
                );
                
                // Re-enable text selection after resize
                $('body').removeClass('no-select resizing-modal');
                
                // Re-enable scrolling and restore scroll position
                const $content = $('#modalRawLogContent');
                $content.css('overflow-y', 'auto');
                
                if (scrollPosition !== null) {
                    $content.scrollTop(scrollPosition);
                    scrollPosition = null;
                }
                
                if (hasResized) {
                    // Prevent modal closing for a short time after resize
                    setTimeout(() => { isResizing = false; }, 150);
                } else {
                    isResizing = false;
                }
                initialSize = null;
            }
        });

        // Close modal when clicking outside of it (but not after dragging or resizing)
        $('#rawLogModal').on('click', function(e) {
            if (e.target.id === 'rawLogModal' && !hasDragged && !isResizing) {
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
        const isIPv4 = str => {
            if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(str)) return false;
            return str.split('.').every(octet => {
                const num = parseInt(octet, 10);
                return num >= 0 && num <= 255 && octet === num.toString();
            });
        };
        const ip2num = ip => {
            const parts = ip.split('.');
            return ((parseInt(parts[0], 10) << 24) >>> 0) +
                   ((parseInt(parts[1], 10) << 16) >>> 0) +
                   ((parseInt(parts[2], 10) << 8) >>> 0) +
                   parseInt(parts[3], 10);
        };
        
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
                    if (isIPv4(ipA) && isIPv4(ipB)) {
                        valA = ip2num(ipA);
                        valB = ip2num(ipB);
                    } else {
                        // Fallback to string comparison for IPv6 or malformed IPs
                        valA = ipA.toLowerCase();
                        valB = ipB.toLowerCase();
                    }
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
                // Update pagination to preserve current page if possible
                $visibleRows = $allRows;
                totalRows = $allRows.length;
                totalPages = Math.ceil(totalRows / rowsPerPage);
                
                // Keep current page if still valid, otherwise go to last valid page
                if (currentPage > totalPages) {
                    currentPage = Math.max(1, totalPages);
                }
                
                $('#pageInput').attr('max', totalPages);
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
                $('#totalPagesSpan').text(totalPages);
                $('#pageInput').attr('max', totalPages);
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
            $('#pageInput').attr('max', totalPages);
            renderTablePage(currentPage);
            
            $searchInput.focus();
        });
        
    });
    </script>
</body>
</html>
