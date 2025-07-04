<?php

$logs = [];
$error = false;

$filename = '/var/www/html/modsec-logs/modsec.log';

if (file_exists($filename) && is_readable($filename)) {
    $handle = fopen($filename, 'r');
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
		$pattern = '/(?P<timestamp>\d+\.\d+).*?\[client (?P<client_ip>[^\]]+)\].*?code (?P<status>\d+).*?phase (?P<phase>\d+)\).*?\[file "(?P<rule_file>[^"]+)"\] \[line "(?P<rule_line>\d+)"\] \[id "(?P<rule_id>\d+)"\] \[msg "(?P<message>[^"]+)"\] \[data "(?P<data>[^"]+)"\] \[severity "(?P<severity>[^"]+)"\] \[ver "(?P<version>[^"]+)"\](?P<tags>(?: \[tag "[^"]+"\])+).*?\[hostname "(?P<hostname>[^"]+)"\] \[uri "(?P<uri>[^"]+)"\] \[unique_id "(?P<unique_id>.*?) client-ip (?P<true_client_ip>[^"]+)"\]/';
			if (preg_match($pattern, $line, $matches)) {

				preg_match_all('/\[tag "([^"]+)"\]/', $matches['tags'], $tagMatches);
				$tags = $tagMatches[1];
				
				$parts = parse_url($matches['uri']);
				$domain = $parts['host'];

				$dt = new DateTime('@'.$matches['timestamp']); // Unix timestamp
				$dt->setTimezone(new DateTimeZone('Australia/Melbourne'));
				$datetime = $dt->format('Y-m-d H:i:s T');

				$logs[] = [
					'datetime' => $datetime,
					'client' => $matches['client_ip'],
					'status' => (int)$matches['status'],
					'phase' => (int)$matches['phase'],
					'message' => $matches['message'],
					'rule_file' => $matches['rule_file'],
					'rule_line' => (int)$matches['rule_line'],
					'rule_id' => $matches['rule_id'],
					'data' => $matches['data'],
					'severity' => $matches['severity'],
					'version' => $matches['version'],
					'tags' => $tags,
					'hostname' => $domain,
					'uri' => $matches['uri'],
					'unique_id' => $matches['unique_id'],
					'client_ip' => $matches['true_client_ip'],
				];

				$logs[count($logs) - 1]['raw_log'] = json_encode($logs[count($logs) - 1], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
			}
		}   
		$logs=array_reverse($logs);                                                                                                                                 
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
        <h1>ModSecurity Logs Viewer</h1>

        <!-- Add this search input above the table -->
        

            <table>
                <thead>
    <tr>
        <th data-col="datetime" class="sortable">Date <span class="sort-icon">&#8595;</span></th>
        <th data-col="hostname" class="sortable" style="white-space:nowrap;">
            <span class="target">
                <span>
                    Target
                    <span class="sort-icon">&#8597;</span>
                </span>
                <span style="position:relative; display:inline-block;">
                    <input type="text" id="hostnameSearch" placeholder="Filter...">
                    <span id="clearHostnameSearch">&#10005;</span>
                </span>
            </span>
        </th>
        <th data-col="message" class="sortable">Message <span class="sort-icon">&#8597;</span></th>
        <th data-col="rule_id" class="sortable">Rule ID <span class="sort-icon">&#8597;</span></th>
        <th data-col="client_ip" class="sortable">Source IP <span class="sort-icon">&#8597;</span></th>
        <th data-col="severity" class="sortable">Severity <span class="sort-icon">&#8597;</span></th>
    </tr>
</thead>
<tbody>
<?php
foreach ($logs as $log) {
    // Map severity to color class
    $sev = strtolower($log['severity']);
    $sevClass = "sev-{$sev}";

    // Use the mapping for consistent pastel color per unique rule_id
    $ruleId = $log['rule_id'];
    $colorIdx = $ruleIdColorMap[$ruleId];
    $ruleIdClass = "ruleid-color-$colorIdx";

    echo "<tr class='log-row' data-raw-log='" . htmlspecialchars($log['raw_log'], ENT_QUOTES, "UTF-8") . "'>";
    echo "<td style='width:200px'>" . $log['datetime'] . "</td>";
    echo "<td>" . htmlspecialchars($log['hostname']) . "</td>";
    echo "<td>" . htmlspecialchars($log['message']) . "</td>";
    echo "<td class='$ruleIdClass'>" . htmlspecialchars($log['rule_id']) . "</td>";
    echo "<td>" . htmlspecialchars($log['client_ip']) . "</td>";
    echo "<td class='$sevClass'>" . htmlspecialchars($log['severity']) . "</td>";
    echo "</tr>";
}
?>
</tbody>
            </table>
    </div>

    <!-- Modal structure -->
    <div id="rawLogModal" style="display:none; z-index:1000;">
        <pre id="modalRawLogContent"></pre>
        <br>
        <button id="closeModalBtn">Close</button>
    </div>

    <!-- jQuery script -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
    $(function() {
        let modalLastPos = null;

        // --- Pagination variables ---
        const rowsPerPage = 25;
        let currentPage = 1;
        let $allRows = $('tr.log-row');
        let totalRows = $allRows.length;
        let totalPages = Math.ceil(totalRows / rowsPerPage);

        function renderTablePage(page) {
            $allRows.hide();
            $allRows.slice((page - 1) * rowsPerPage, page * rowsPerPage).show();
            $('#paginationInfo').text(`Page ${page} of ${totalPages}`);
            $('#prevPage').prop('disabled', page === 1);
            $('#nextPage').prop('disabled', page === totalPages);
        }

        function updatePagination() {
            $allRows = $('tr.log-row:visible, tr.log-row:hidden').filter(function() {
                // Only count rows that are not filtered out
                return $(this).css('display') !== 'none' || $(this).is(':visible');
            });
            totalRows = $allRows.length;
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

        // --- Existing code for row click, modal, sorting, and search ---

        $('.log-row').on('click', function() {
            let rawLogObj = $(this).data('raw-log');
            if (typeof rawLogObj === 'string') {
                try { rawLogObj = JSON.parse(rawLogObj); } catch {}
            }
            // Wrap "data" field at 200 chars
            if (rawLogObj && rawLogObj.data && typeof rawLogObj.data === 'string' && rawLogObj.data.length > 200) {
                rawLogObj.data = rawLogObj.data.replace(/(.{200})/g, '$1\n');
            }
            var rawLog = JSON.stringify(rawLogObj, null, 2);
            $('#modalRawLogContent').text(rawLog);

            var $modal = $('#rawLogModal');
            if (modalLastPos) {
                let left = Math.max(0, Math.min(modalLastPos.left, $(window).width() - $modal.outerWidth()));
                let top = Math.max(0, Math.min(modalLastPos.top, $(window).height() - $modal.outerHeight()));
                $modal.css({ left: left + 'px', top: top + 'px' });
            } else {
                var win = $(window);
                var left = (win.width() - $modal.outerWidth()) / 2;
                var top = (win.height() - $modal.outerHeight()) / 2;
                $modal.css({ left: left + 'px', top: top + 'px' });
            }
            $modal.show();
        });

        $('#closeModalBtn').on('click', function() {
            $('#rawLogModal').hide();
        });

        // Draggable modal
        let isDragging = false, offsetX = 0, offsetY = 0;
        $('#rawLogModal').on('mousedown', function(e) {
            if (e.target.id === 'closeModalBtn') return;
            isDragging = true;
            // Make modal transparent while dragging
            $(this).css('opacity', '0.8');
            offsetX = e.clientX - $(this).position().left;
            offsetY = e.clientY - $(this).position().top;
            $(document).on('mousemove.draggable', function(e2) {
                if (isDragging) {
                    let left = e2.clientX - offsetX;
                    let top = e2.clientY - offsetY;
                    // Clamp to viewport
                    left = Math.max(0, Math.min(left, $(window).width() - $('#rawLogModal').outerWidth()));
                    top = Math.max(0, Math.min(top, $(window).height() - $('#rawLogModal').outerHeight()));
                    $('#rawLogModal').css({ left: left + 'px', top: top + 'px', transform: 'none' });
                    modalLastPos = { left: left, top: top };
                }
            });
            $(document).on('mouseup.draggable', function() {
                isDragging = false;
                // Restore modal opacity
                $('#rawLogModal').css('opacity', '1');
                $(document).off('.draggable');
            });
        });

        // Sorting logic
        let sortOrder = { datetime: 'desc' };
        $('th[data-col="datetime"] .sort-icon').html('&#8595;');

        $('.sortable').on('click', function(e) {
            // Prevent sorting if the click was on the input inside the header
            if ($(e.target).is('input, input *')) return;

            const col = $(this).data('col');
            const table = $(this).closest('table');
            const tbody = table.find('tbody');
            const rows = tbody.find('tr').toArray();
            const colIdx = $(this).index();

            sortOrder[col] = sortOrder[col] === 'asc' ? 'desc' : 'asc';

            rows.sort(function(a, b) {
                let tdA = $(a).find('td').eq(colIdx).text();
                let tdB = $(b).find('td').eq(colIdx).text();

                if (col === 'datetime') {
                    let dateA = Date.parse(tdA);
                    let dateB = Date.parse(tdB);
                    if (!isNaN(dateA) && !isNaN(dateB)) {
                        tdA = dateA;
                        tdB = dateB;
                    }
                } else if (col === 'client_ip') {
                    // Sort IP addresses numerically
                    function ip2num(ip) {
                        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
                    }
                    tdA = ip2num(tdA);
                    tdB = ip2num(tdB);
                } else if (col === 'hostname') {
                    // Helper to check if a string is an IPv4 address
                    function isIPv4(str) {
                        return /^(\d{1,3}\.){3}\d{1,3}$/.test(str);
                    }
                    function ip2num(ip) {
                        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
                    }
                    const aIsIp = isIPv4(tdA);
                    const bIsIp = isIPv4(tdB);
                    if (aIsIp && bIsIp) {
                        tdA = ip2num(tdA);
                        tdB = ip2num(tdB);
                    }
                    // else: leave as strings for normal comparison
                } else {
                    let numA = parseFloat(tdA.replace(/[^\d.-]/g, ''));
                    let numB = parseFloat(tdB.replace(/[^\d.-]/g, ''));
                    if (!isNaN(numA) && !isNaN(numB)) {
                        tdA = numA;
                        tdB = numB;
                    }
                }

                if (tdA < tdB) return sortOrder[col] === 'asc' ? -1 : 1;
                if (tdA > tdB) return sortOrder[col] === 'asc' ? 1 : -1;
                return 0;
            });

            tbody.empty().append(rows);

            $('.sort-icon').html('&#8597;');
            $(this).find('.sort-icon').html(sortOrder[col] === 'asc' ? '&#8593;' : '&#8595;');

            // Re-bind click handler for modal after sorting
            $('.log-row').off('click').on('click', function() {
                let rawLogObj = $(this).data('raw-log');
                if (typeof rawLogObj === 'string') {
                    try { rawLogObj = JSON.parse(rawLogObj); } catch {}
                }
                // Wrap "data" field at 200 chars
                if (rawLogObj && rawLogObj.data && typeof rawLogObj.data === 'string' && rawLogObj.data.length > 200) {
                    rawLogObj.data = rawLogObj.data.replace(/(.{200})/g, '$1\n');
                }
                var rawLog = JSON.stringify(rawLogObj, null, 2);
                $('#modalRawLogContent').text(rawLog);

                var $modal = $('#rawLogModal');
                if (modalLastPos) {
                    let left = Math.max(0, Math.min(modalLastPos.left, $(window).width() - $modal.outerWidth()));
                    let top = Math.max(0, Math.min(modalLastPos.top, $(window).height() - $modal.outerHeight()));
                    $modal.css({ left: left + 'px', top: top + 'px' });
                } else {
                    var win = $(window);
                    var left = (win.width() - $modal.outerWidth()) / 2;
                    var top = (win.height() - $modal.outerHeight()) / 2;
                    $modal.css({ left: left + 'px', top: top + 'px' });
                }
                $modal.show();
            });
        });

        // Search functionality
        $('#hostnameSearch').on('input', function() {
            var val = $(this).val().toLowerCase();
            $('tr.log-row').each(function() {
                var hostname = $(this).find('td').eq(1).text().toLowerCase();
                $(this).toggle(hostname.indexOf(val) !== -1);
            });
            $('#clearHostnameSearch').toggle($(this).val().length > 0);
            // After filtering, re-apply pagination:
            $allRows = $('tr.log-row').filter(function() {
                return $(this).css('display') !== 'none';
            });
            totalRows = $allRows.length;
            totalPages = Math.max(1, Math.ceil(totalRows / rowsPerPage));
            currentPage = 1;
            renderTablePage(currentPage);
        });

        $('#clearHostnameSearch').on('click', function() {
            $('#hostnameSearch').val('').trigger('input').focus();
            $(this).hide();
        });
    });
    </script>
</body>
</html>
