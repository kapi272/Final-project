// Autonomous IoT Cyber Defense System - SOC Terminal Client
document.addEventListener("DOMContentLoaded", () => {
    const ssePill = document.getElementById("sse-status-pill");
    const sseIndicator = document.getElementById("sse-indicator");
    const bannedCountEl = document.getElementById("metric-banned-count");
    const trapsCountEl = document.getElementById("metric-traps-count");
    const mitigationTableBody = document.getElementById("mitigation-table-body");
    const terminalFeed = document.getElementById("terminal-feed");
    const resetBansBtn = document.getElementById("btn-reset-bans");

    let totalTraps = 0;
    let activeBansCount = 0;
    let currentLogFilter = 'all';
    let currentTrafficMode = "simulated";
    let registeredDevices = [];
    let activeSnapshotDevice = null;
    let currentSnapshotObjectUrl = null;
    let liveSnapshotActive = false;
    let liveSnapshotTimer = null;
    let liveSnapshotSession = 0;
    let liveSnapshotLastFrameTs = 0;
    const terminalLogsBuffer = [];

    // Helper: Safely append text to an element to prevent DOM XSS
    function createSafeElement(tag, text, classes = "") {
        const el = document.createElement(tag);
        if (classes) el.className = classes;
        el.textContent = text;
        return el;
    }

    // Format UNIX timestamp according to Indian Date & Time Standards (IST / Asia/Kolkata: DD/MM/YYYY, HH:mm:ss)
    function formatDateTime(ts) {
        if (!ts) return "--/--/----, --:--:--";
        const ms = typeof ts === "number" && ts < 1e11 ? ts * 1000 : ts;
        const d = new Date(ms);
        if (isNaN(d.getTime())) return "--/--/----, --:--:--";
        return d.toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false
        });
    }
    const formatTime = formatDateTime;

    // Append log line to general activity terminal feed console with 6-column SIEM layout
    function appendTerminalLog(arg1, arg2, arg3 = "info", arg4 = "system") {
        let stream, message, severity, category, source, protocol;

        if (typeof arg1 === "object" && arg1 !== null) {
            stream = arg1.stream || "SYSTEM";
            category = arg1.category || "system";
            severity = arg1.severity || "INFO";
            if (severity === "CRITICAL") severity = "CRIT";
            source = arg1.source || "--";
            protocol = arg1.protocol || "--";
            message = arg1.message || "";
        } else {
            stream = arg1;
            message = arg2;
            const type = arg3;
            category = arg4;
            severity = type === "threat" ? "CRIT" : (type === "warning" ? "WARN" : "INFO");
            source = category === "honeypot" ? "ATTACKER" : (category === "quarantine" || category === "iot" ? "IOT_NODE" : "SOC_CTRL");
            protocol = category === "honeypot" ? "SSH:2222" : (category === "mitigation" ? "NETFILTER" : (category === "iot" ? "MQTT:1883" : "HTTP:8050"));
        }

        const line = document.createElement("div");
        line.dataset.category = category;
        line.className = "flex items-center space-x-2 py-1 px-3 border-b border-slate-900/60 hover:bg-slate-900/40 transition-colors min-w-[860px]";

        // Filter visibility logic
        if (currentLogFilter !== "all" && currentLogFilter !== category) {
            line.style.display = "none";
        } else {
            line.style.display = "flex";
        }

        const nowEpoch = Date.now() / 1000;
        const nowIst = formatDateTime(nowEpoch);

        // Store structured record in in-memory export buffer
        terminalLogsBuffer.push({
            timestamp_ist: nowIst,
            timestamp_epoch: nowEpoch,
            stream: stream,
            severity: severity,
            source: source,
            protocol: protocol,
            message: message,
            category: category
        });
        if (terminalLogsBuffer.length > 2000) {
            terminalLogsBuffer.shift();
        }

        // 1. Date & Time Column (Indian Standard IST: DD/MM/YYYY, HH:mm:ss)
        const timeSpan = createSafeElement("span", nowIst, "w-[145px] shrink-0 text-slate-400 select-none text-[10px] font-mono tracking-tight");

        // 2. Stream Badge Column
        let streamStyle = "text-sky-400 bg-sky-950/40 border-sky-800/40";
        if (category === "quarantine") {
            streamStyle = "text-red-400 bg-red-950/50 border-red-700/60";
        } else if (category === "honeypot") {
            streamStyle = "text-amber-400 bg-amber-950/40 border-amber-800/40";
        } else if (category === "mitigation") {
            streamStyle = "text-rose-400 bg-rose-950/40 border-rose-800/40";
        } else if (category === "iot") {
            streamStyle = "text-emerald-400 bg-emerald-950/40 border-emerald-800/40";
        }
        const streamSpan = createSafeElement("span", stream, `w-[88px] shrink-0 text-center font-mono text-[9px] font-bold px-1.5 py-0.5 rounded border ${streamStyle} truncate`);

        // 3. Severity Badge Column (supports CRIT, HIGH, WARN, NORM, SYS, INFO)
        let sevStyle = "text-slate-300 bg-slate-800/80 border-slate-700";
        if (severity === "CRIT") {
            sevStyle = "text-white bg-red-900/90 border-red-500 font-extrabold shadow-sm shadow-red-950";
        } else if (severity === "HIGH") {
            sevStyle = "text-rose-300 bg-rose-950/90 border-rose-700 font-bold";
        } else if (severity === "WARN") {
            sevStyle = "text-amber-300 bg-amber-950/90 border-amber-700 font-bold";
        } else if (severity === "NORM" || severity === "LIVE") {
            sevStyle = "text-emerald-300 bg-emerald-950/80 border-emerald-700 font-bold";
        } else if (severity === "SYS") {
            sevStyle = "text-sky-300 bg-sky-950/80 border-sky-700 font-bold";
        } else {
            sevStyle = "text-slate-300 bg-slate-800 border-slate-700";
        }
        const sevSpan = createSafeElement("span", severity, `w-[56px] shrink-0 text-center font-mono text-[9px] px-1 py-0.5 rounded border ${sevStyle}`);

        // 4. Source/Node Badge Column
        const sourceSpan = createSafeElement("span", source, "w-[115px] shrink-0 font-mono text-[10px] text-sky-300 font-semibold truncate bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800 text-center");

        // 5. Protocol Badge Column
        const protoSpan = createSafeElement("span", protocol, "w-[85px] shrink-0 font-mono text-[10px] text-indigo-300 text-center truncate bg-indigo-950/40 px-1 py-0.5 rounded border border-indigo-900/50");

        // 6. Payload & Event Details Column (with full hover tooltip)
        const dataSpan = createSafeElement("span", message, "flex-1 min-w-[300px] text-slate-300 text-[11px] truncate");
        dataSpan.title = message;

        line.appendChild(timeSpan);
        line.appendChild(streamSpan);
        line.appendChild(sevSpan);
        line.appendChild(sourceSpan);
        line.appendChild(protoSpan);
        line.appendChild(dataSpan);

        terminalFeed.appendChild(line);

        if (line.style.display !== "none") {
            terminalFeed.scrollTop = terminalFeed.scrollHeight;
        }

        // Cap terminal lines at 250 to keep browser memory lightweight
        while (terminalFeed.childNodes.length > 250) {
            terminalFeed.removeChild(terminalFeed.firstChild);
        }
    }

    // Filter switching handler
    window.setLogFilter = function(filter) {
        currentLogFilter = filter;
        const categories = ["all", "honeypot", "mitigation", "quarantine", "iot", "system"];
        
        categories.forEach(cat => {
            const btn = document.getElementById(`filter-btn-${cat}`);
            if (!btn) return;
            if (cat === filter) {
                if (filter === "quarantine") {
                    btn.className = "px-2 py-0.5 rounded font-bold bg-red-950/80 border border-red-700 text-red-300 transition-all";
                } else if (filter === "mitigation") {
                    btn.className = "px-2 py-0.5 rounded font-bold bg-rose-950/80 border border-rose-700 text-rose-300 transition-all";
                } else if (filter === "honeypot") {
                    btn.className = "px-2 py-0.5 rounded font-bold bg-amber-950/80 border border-amber-700 text-amber-300 transition-all";
                } else if (filter === "iot") {
                    btn.className = "px-2 py-0.5 rounded font-bold bg-emerald-950/80 border border-emerald-700 text-emerald-300 transition-all";
                } else {
                    btn.className = "px-2 py-0.5 rounded font-bold bg-sky-950/80 border border-sky-700 text-sky-300 transition-all";
                }
            } else {
                btn.className = "px-2 py-0.5 rounded font-semibold bg-slate-800/50 hover:bg-slate-800 border border-transparent hover:border-slate-700 text-slate-400 hover:text-slate-200 transition-all";
            }
        });

        // Toggle visibility of each log line in DOM
        const lines = terminalFeed.querySelectorAll("div[data-category]");
        lines.forEach(line => {
            if (filter === "all" || line.dataset.category === filter) {
                line.style.display = "flex";
            } else {
                line.style.display = "none";
            }
        });

        terminalFeed.scrollTop = terminalFeed.scrollHeight;
    };

    // Manual console clear
    window.clearConsole = function() {
        terminalFeed.innerHTML = "";
        terminalLogsBuffer.length = 0;
        appendTerminalLog({
            stream: "SYSTEM",
            category: "system",
            severity: "INFO",
            source: "soc_admin",
            protocol: "HTTP:8050",
            message: "Console buffer cleared. Session stream active."
        });
    };

    // Open General Activity Logs export modal
    window.openExportLogsModal = function() {
        const modal = document.getElementById("export-logs-modal");
        if (!modal) return;
        modal.classList.remove("hidden");

        // Automatically match the current active log category tab
        const scopeRadios = document.querySelectorAll('input[name="export-scope"]');
        scopeRadios.forEach(radio => {
            radio.checked = (radio.value === currentLogFilter);
        });

        window.updateExportPreviewCount();
    };

    // Close General Activity Logs export modal
    window.closeExportLogsModal = function() {
        const modal = document.getElementById("export-logs-modal");
        if (modal) modal.classList.add("hidden");
    };

    // Update real-time matching count in modal
    window.updateExportPreviewCount = function() {
        const selectedRadio = document.querySelector('input[name="export-scope"]:checked');
        const scope = selectedRadio ? selectedRadio.value : "all";
        const count = scope === "all" 
            ? terminalLogsBuffer.length 
            : terminalLogsBuffer.filter(l => l.category === scope).length;

        const countEl = document.getElementById("export-match-count");
        if (countEl) {
            countEl.textContent = `${count} ${count === 1 ? 'record' : 'records'} ready`;
        }
    };

    // Download filtered logs in JSON, CSV, or LOG format
    window.downloadActivityLogs = function() {
        const selectedScopeRadio = document.querySelector('input[name="export-scope"]:checked');
        const scope = selectedScopeRadio ? selectedScopeRadio.value : "all";

        const selectedFormatRadio = document.querySelector('input[name="export-format"]:checked');
        const format = selectedFormatRadio ? selectedFormatRadio.value : "json";

        const filteredLogs = scope === "all"
            ? [...terminalLogsBuffer]
            : terminalLogsBuffer.filter(l => l.category === scope);

        if (filteredLogs.length === 0) {
            alert(`No logs currently recorded in category "${scope.toUpperCase()}".`);
            return;
        }

        let content = "";
        let mimeType = "application/json;charset=utf-8;";
        let fileExt = "json";

        if (format === "csv") {
            mimeType = "text/csv;charset=utf-8;";
            fileExt = "csv";
            const headers = ["Timestamp (IST)", "Timestamp (Epoch)", "Stream", "Severity", "Source/Node", "Protocol", "Payload & Event Data", "Category"];
            const escapeCsv = (val) => {
                if (val === null || val === undefined) return '""';
                const str = String(val).replace(/"/g, '""');
                return `"${str}"`;
            };
            const rows = filteredLogs.map(log => [
                escapeCsv(log.timestamp_ist),
                escapeCsv(log.timestamp_epoch),
                escapeCsv(log.stream),
                escapeCsv(log.severity),
                escapeCsv(log.source),
                escapeCsv(log.protocol),
                escapeCsv(log.message),
                escapeCsv(log.category)
            ].join(","));
            content = [headers.map(h => `"${h}"`).join(","), ...rows].join("\r\n");
        } else if (format === "log") {
            mimeType = "text/plain;charset=utf-8;";
            fileExt = "log";
            content = filteredLogs.map(log => 
                `[${log.timestamp_ist}] [${log.stream}] [${log.severity}] [${log.source}] [${log.protocol}] ${log.message}`
            ).join("\n");
        } else {
            mimeType = "application/json;charset=utf-8;";
            fileExt = "json";
            content = JSON.stringify(filteredLogs, null, 2);
        }

        const now = new Date();
        const dateStamp = now.toISOString().slice(0, 10);
        const timeStamp = now.toTimeString().slice(0, 8).replace(/:/g, "-");
        const filename = `soc_activity_logs_${scope}_${dateStamp}_${timeStamp}.${fileExt}`;

        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        window.closeExportLogsModal();

        appendTerminalLog({
            stream: "SYSTEM",
            category: "system",
            severity: "INFO",
            source: "soc_admin",
            protocol: "HTTP:8050",
            message: `Exported ${filteredLogs.length} ${scope.toUpperCase()} log records as ${fileExt.toUpperCase()} (${filename}).`
        });
    };

    // Add or update row in live mitigation table
    function addMitigationRow(record, prepend = true) {
        const rowKey = record.id ? `row-id-${record.id}` : `row-ip-${record.src_ip.replace(/[^a-zA-Z0-9]/g, '_')}`;
        const existingRow = document.getElementById(rowKey);
        if (existingRow) {
            existingRow.remove();
        }

        const tr = document.createElement("tr");
        tr.id = rowKey;
        if (record.src_ip) {
            tr.dataset.srcIp = record.src_ip;
        }
        tr.className = "border-b border-slate-800/80 hover:bg-slate-800/40 transition-colors";

        // Timestamp (Indian Standard IST: DD/MM/YYYY, HH:mm:ss)
        const tdTime = createSafeElement("td", formatDateTime(record.timestamp), "px-4 py-2 text-slate-400 font-mono text-xs whitespace-nowrap");
        
        // Target IP (Clickable for deep forensics)
        const tdIp = document.createElement("td");
        tdIp.className = "px-4 py-2";
        if (record.src_ip && record.src_ip !== "0.0.0.0/0") {
            const ipBtn = createSafeElement("button", record.src_ip, "font-mono text-sm text-sky-400 hover:text-sky-300 hover:underline font-semibold flex items-center space-x-1.5");
            const searchIcon = createSafeElement("span", "🔍", "text-[10px] text-slate-500 opacity-70");
            ipBtn.appendChild(searchIcon);
            ipBtn.onclick = () => window.openIpForensics(record.src_ip);
            tdIp.appendChild(ipBtn);
        } else {
            tdIp.appendChild(createSafeElement("span", record.src_ip || "0.0.0.0/0", "font-mono text-sm text-slate-400 font-semibold"));
        }

        // Action badge
        const tdAction = document.createElement("td");
        tdAction.className = "px-4 py-2";
        let badgeClass = "px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-rose-950/60 border border-rose-800 text-rose-400";
        if (record.action === "UNBAN" || record.action === "DEVICE_RESTORED") {
            badgeClass = "px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-emerald-950/60 border border-emerald-800 text-emerald-400";
        } else if (record.action === "RESET_ALL_BANS" || record.action === "DEVICE_BLOCKED") {
            badgeClass = "px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-amber-950/60 border border-amber-800 text-amber-400";
        }
        const actionBadge = createSafeElement("span", record.action || "IPTABLES_DROP", badgeClass);
        tdAction.appendChild(actionBadge);

        // Reason
        const tdReason = createSafeElement("td", record.reason, "px-4 py-2 text-xs text-slate-300 max-w-xs truncate");

        // Unban Action Button
        const tdControls = document.createElement("td");
        tdControls.className = "px-4 py-2 text-right";
        if (record.action === "IPTABLES_DROP") {
            const unbanBtn = createSafeElement("button", "Unban", "px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-rose-900/60 border border-slate-700 text-slate-300 hover:text-white transition-colors");
            unbanBtn.onclick = () => unbanIp(record.src_ip);
            tdControls.appendChild(unbanBtn);
        }

        tr.appendChild(tdTime);
        tr.appendChild(tdIp);
        tr.appendChild(tdAction);
        tr.appendChild(tdReason);
        tr.appendChild(tdControls);

        if (prepend && mitigationTableBody.firstChild) {
            mitigationTableBody.insertBefore(tr, mitigationTableBody.firstChild);
        } else {
            mitigationTableBody.appendChild(tr);
        }
    }

    // Update node topology card UI
    function updateNodeStatus(nodeId, state) {
        const card = document.getElementById(`card-${nodeId}`);
        const badge = document.getElementById(`badge-${nodeId}`);
        if (!card || !badge) return;

        if (state === "quarantined") {
            card.className = "p-4 rounded-lg bg-red-950/30 border border-red-600 shadow-lg shadow-red-950/40 transition-all";
            badge.className = "px-2 py-0.5 rounded-full text-[11px] font-bold tracking-wide uppercase bg-red-950 border border-red-500 text-red-400 animate-pulse";
            badge.textContent = "QUARANTINED";
        } else {
            card.className = "p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all";
            badge.className = "px-2 py-0.5 rounded-full text-[11px] font-bold tracking-wide uppercase bg-emerald-950/60 border border-emerald-800 text-emerald-400";
            badge.textContent = "PRODUCTION";
        }
    }

    // Initial status fetch
    async function fetchInitialStatus() {
        try {
            const res = await fetch("/api/defense/status");
            const data = await res.json();
            if (data.status === "success") {
                const payload = data.data;
                activeBansCount = payload.banned_count || 0;
                bannedCountEl.textContent = activeBansCount;
                registeredDevices = Array.isArray(payload.registered_devices) ? payload.registered_devices : [];
                currentTrafficMode = payload.traffic_mode === "live" ? "live" : "simulated";

                // Pre-populate node states
                if (payload.node_states) {
                    for (const [nodeId, state] of Object.entries(payload.node_states)) {
                        updateNodeStatus(nodeId, state);
                    }
                }

                // Pre-populate mitigation rows in descending order
                if (payload.recent_mitigations) {
                    mitigationTableBody.replaceChildren();
                    payload.recent_mitigations.forEach(r => addMitigationRow(r, false));
                }

                renderLiveDevices();
                applyTrafficModeUI(currentTrafficMode);
            }
        } catch (e) {
            appendTerminalLog({
                stream: "SYSTEM",
                category: "system",
                severity: "WARN",
                source: "soc_ui",
                protocol: "HTTP:8050",
                message: `Failed to load initial status: ${e}`
            });
        }
    }

    // Connect SSE Stream
    function connectSSE() {
        appendTerminalLog({
            stream: "STREAM",
            category: "system",
            severity: "INFO",
            source: "sse_bus",
            protocol: "HTTP:8050",
            message: "Connecting to telemetry event stream /api/stream..."
        });
        const eventSource = new EventSource("/api/stream");

        eventSource.addEventListener("open", () => {
            sseIndicator.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse";
            ssePill.className = "inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950/40 border border-emerald-800 text-emerald-400";
            document.getElementById("sse-text").textContent = "STREAM LIVE";
            appendTerminalLog({
                stream: "STREAM",
                category: "system",
                severity: "INFO",
                source: "sse_bus",
                protocol: "HTTP:8050",
                message: "Connected to realtime security bus. Stream active."
            });
        });

        eventSource.addEventListener("connected", (e) => {
            appendTerminalLog({
                stream: "STREAM",
                category: "system",
                severity: "INFO",
                source: "sse_bus",
                protocol: "HTTP:8050",
                message: "Session handshake synchronized."
            });
        });

        eventSource.addEventListener("heartbeat", () => {
            // Heartbeat received
        });

        eventSource.addEventListener("honeypot_hit", (e) => {
            totalTraps++;
            trapsCountEl.textContent = totalTraps;
            try {
                const payload = JSON.parse(e.data);
                const ev = payload.data || {};
                const src = ev.src_ip || "unknown";
                const user = ev.username || "";
                const pwd = ev.password ? `(pwd: ${ev.password})` : "";
                const cmd = ev.input_command ? `cmd: "${ev.input_command}"` : "";
                const proto = ev.dst_port ? (ev.dst_port === 2223 ? "TELNET:2223" : "SSH:2222") : "SSH:2222";
                const sev = ev.input_command ? "CRIT" : (ev.eventid && ev.eventid.includes("failed") ? "HIGH" : "WARN");
                const detail = ev.input_command 
                    ? `Critical exploit command injection: '${ev.input_command}'`
                    : (ev.username ? `Auth Failed: [${user} / ${ev.password || ''}] -> ${ev.eventid}` : (ev.message || ev.eventid || "Recon probe hit"));
                appendTerminalLog({
                    stream: "HONEYPOT",
                    category: "honeypot",
                    severity: sev,
                    source: src,
                    protocol: proto,
                    message: detail
                });
            } catch (err) {
                appendTerminalLog({
                    stream: "HONEYPOT",
                    category: "honeypot",
                    severity: "WARN",
                    source: "ATTACKER",
                    protocol: "SSH:2222",
                    message: "Raw hit frame received."
                });
            }
            loadAnalytics();
        });

        eventSource.addEventListener("mitigation_alert", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const rec = payload.data || {};
                const rowKey = rec.id
                    ? `row-id-${rec.id}`
                    : (rec.src_ip ? `row-ip-${rec.src_ip.replace(/[^a-zA-Z0-9]/g, '_')}` : null);
                const action = rec.action || "IPTABLES_DROP";
                const alreadyRendered = Boolean(rowKey && document.getElementById(rowKey));
                if (!alreadyRendered && (action === "IPTABLES_DROP" || action === "BLOCK")) {
                    activeBansCount++;
                    bannedCountEl.textContent = activeBansCount;
                }
                addMitigationRow(rec);
                if (action === "DEVICE_BLOCKED" || action === "DEVICE_RESTORED") {
                    fetchInitialStatus();
                }
                const logMsg = action === "DEVICE_RESTORED"
                    ? `DEVICE RESTORED: ${rec.reason}`
                    : (action === "DEVICE_BLOCKED"
                        ? `LOGICAL QUARANTINE ENFORCED: ${rec.reason}`
                        : `AUTONOMOUS BAN ENFORCED: ${rec.reason} (Chain: IOT_DEFENSE_BLOCKLIST)`);
                appendTerminalLog({
                    stream: "MITIGATION",
                    category: "mitigation",
                    severity: rec.severity || "CRIT",
                    source: rec.src_ip || "unknown",
                    protocol: "NETFILTER",
                    message: logMsg
                });
            } catch (err) {
                appendTerminalLog({
                    stream: "MITIGATION",
                    category: "mitigation",
                    severity: "CRIT",
                    source: "NETFILTER",
                    protocol: "IPTABLES",
                    message: "Mitigation alert received."
                });
            }
            loadAnalytics();
        });

        eventSource.addEventListener("unban_alert", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const ip = (payload.data && payload.data.ip) || "";
                if (ip && mitigationTableBody) {
                    const legacyRow = document.getElementById(`row-ip-${ip.replace(/[^a-zA-Z0-9]/g, '_')}`);
                    if (legacyRow) legacyRow.remove();
                    mitigationTableBody.querySelectorAll("tr").forEach((tr) => {
                        if (tr.dataset.srcIp === ip) {
                            tr.remove();
                        }
                    });
                }
                if (activeBansCount > 0) activeBansCount--;
                bannedCountEl.textContent = activeBansCount;
                appendTerminalLog({
                    stream: "MITIGATION",
                    category: "mitigation",
                    severity: "INFO",
                    source: ip || "unknown",
                    protocol: "NETFILTER",
                    message: `Manual unban executed by ${(payload.data && payload.data.unbanned_by) || 'soc_admin'}`
                });
                fetchInitialStatus();
                loadAnalytics();
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("reset_alert", () => {
            activeBansCount = 0;
            bannedCountEl.textContent = "0";
            mitigationTableBody.innerHTML = "";
            appendTerminalLog({
                stream: "MITIGATION",
                category: "mitigation",
                severity: "INFO",
                source: "0.0.0.0/0",
                protocol: "NETFILTER",
                message: "All firewall drop rules flushed from Linux kernel."
            });
        });

        eventSource.addEventListener("database_reset_alert", () => {
            activeBansCount = 0;
            bannedCountEl.textContent = "0";
            totalTraps = 0;
            trapsCountEl.textContent = "0";
            mitigationTableBody.replaceChildren();
            window.clearConsole();
            fetchInitialStatus();
            loadAnalytics();
            appendTerminalLog({
                stream: "ADMIN",
                category: "system",
                severity: "INFO",
                source: "soc_admin",
                protocol: "SQLITE:DB",
                message: "Database audit history, threat analytics, and bans wiped clean."
            });
        });

        eventSource.addEventListener("mode_changed", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const nextMode = payload.data && payload.data.mode === "live" ? "live" : "simulated";
                applyTrafficModeUI(nextMode);
                appendTerminalLog({
                    stream: "SYSTEM",
                    category: "system",
                    severity: "SYS",
                    source: "mode_ctrl",
                    protocol: "SOC:MODE",
                    message: `Traffic mode switched to ${nextMode.toUpperCase()} (${nextMode === "live" ? "Simulated feeds paused; Real Device Mesh active" : "Virtual IoT simulators & Red Team controls active"}).`
                });
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("device_registered", (e) => {
            try {
                const payload = JSON.parse(e.data);
                if (payload.data) {
                    upsertDeviceLocal(payload.data);
                    appendTerminalLog({
                        stream: "IOT MESH",
                        category: "iot",
                        severity: "INFO",
                        source: payload.data.device_id,
                        protocol: (payload.data.protocol || "MQTT").toUpperCase(),
                        message: `Onboarded real IoT device '${payload.data.name}' (${payload.data.ip_address}:${payload.data.port})`
                    });
                }
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("device_updated", (e) => {
            try {
                const payload = JSON.parse(e.data);
                if (payload.data) {
                    upsertDeviceLocal(payload.data);
                    if (activeSnapshotDevice && payload.data.device_id === activeSnapshotDevice && payload.data.blocked) {
                        stopLiveSnapshotStream();
                        const imgEl = document.getElementById("snapshot-preview-img");
                        const fallbackEl = document.getElementById("snapshot-fallback-msg");
                        const statusText = document.getElementById("snapshot-status-text");
                        if (imgEl) {
                            imgEl.removeAttribute("src");
                            imgEl.classList.add("hidden");
                        }
                        if (currentSnapshotObjectUrl) {
                            URL.revokeObjectURL(currentSnapshotObjectUrl);
                            currentSnapshotObjectUrl = null;
                        }
                        if (fallbackEl) {
                            fallbackEl.textContent = "Camera stream halted: Device quarantined by SOC policy.";
                            fallbackEl.classList.remove("hidden");
                        }
                        if (statusText) statusText.textContent = "Stream blocked (403 Quarantined)";
                    }
                }
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("device_deleted", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const devId = payload.data && payload.data.device_id;
                if (devId) {
                    if (activeSnapshotDevice === devId) {
                        window.closeSnapshotModal();
                    }
                    registeredDevices = registeredDevices.filter(d => d.device_id !== devId);
                    renderLiveDevices();
                    updateModeMetrics();
                }
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("device_telemetry_blocked", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const info = payload.data || {};
                appendTerminalLog({
                    stream: "QUARANTINE",
                    category: "quarantine",
                    severity: "WARN",
                    source: info.device_id || info.ip_address || "device",
                    protocol: info.channel || "NETFILTER",
                    message: `Blocked ${info.channel || "telemetry"} packet dropped from logically quarantined device ${info.device_id || ""} (${info.ip_address || ""})`
                });
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("node_quarantined", (e) => {
            try {
                const payload = JSON.parse(e.data);
                updateNodeStatus(payload.data.node_id, "quarantined");
                appendTerminalLog({
                    stream: "QUARANTINE",
                    category: "quarantine",
                    severity: "CRIT",
                    source: payload.data.node_id,
                    protocol: "DOCKER-API",
                    message: "Dynamic containment triggered: Detached from 172.20.0.0/24 -> Attached to iot_quarantine_net"
                });
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("node_restored", (e) => {
            try {
                const payload = JSON.parse(e.data);
                updateNodeStatus(payload.data.node_id, "production");
                appendTerminalLog({
                    stream: "QUARANTINE",
                    category: "quarantine",
                    severity: "INFO",
                    source: payload.data.node_id,
                    protocol: "DOCKER-API",
                    message: "Container restored: Reconnected to production mesh network (iot_production_net)"
                });
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("iot_telemetry", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const data = payload.data || {};
                const topic = data.topic || "home/iot";
                const val = data.payload || "";
                let dev = data.device_id || "iot_node";
                if (!data.device_id) {
                    if (topic.includes("temperature") || topic.includes("sensor")) dev = "temp_sensor_01";
                    else if (topic.includes("bulb") || topic.includes("device")) dev = "smart_bulb_01";
                }
                const protoLabel = topic.startsWith("http/webhook/") ? "HTTP:HOOK" : "MQTT:1883";
                appendTerminalLog({
                    stream: "IOT MESH",
                    category: "iot",
                    severity: "INFO",
                    source: dev,
                    protocol: protoLabel,
                    message: `Telemetry Payload: ${val} (Topic: ${topic})`
                });
            } catch (err) {
                appendTerminalLog({
                    stream: "IOT MESH",
                    category: "iot",
                    severity: "INFO",
                    source: "iot_node",
                    protocol: "MQTT:1883",
                    message: "Telemetry packet received."
                });
            }
        });

        eventSource.addEventListener("error", () => {
            sseIndicator.className = "w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping";
            ssePill.className = "inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-semibold bg-rose-950/40 border border-rose-800 text-rose-400";
            document.getElementById("sse-text").textContent = "RECONNECTING";
        });
    }

    // Manual Unban
    async function unbanIp(ip) {
        try {
            const res = await fetch("/api/defense/unban", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip: ip, admin_user: "soc_admin" })
            });
            const data = await res.json();
            if (data.status !== "success") {
                alert(`Unban failed: ${data.message}`);
            }
        } catch (e) {
            alert(`Error: ${e}`);
        }
    }

    // Global Reset Bans
    resetBansBtn.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to flush all active firewall drop rules?")) return;
        try {
            await fetch("/api/defense/reset-bans", { method: "POST" });
        } catch (e) {
            alert(`Error: ${e}`);
        }
    });

    // Complete Database Wipe & Reset
    window.resetDatabase = async function() {
        if (!confirm("⚠️ Are you sure you want to completely RESET the database?\n\nThis will permanently delete all audit history, clear active firewall bans, and wipe threat intelligence analytics for a clean presentation demo.")) {
            return;
        }
        try {
            const res = await fetch("/api/defense/reset-database", { method: "POST" });
            const data = await res.json();
            if (data.status === "success") {
                mitigationTableBody.innerHTML = "";
                activeBansCount = 0;
                bannedCountEl.textContent = "0";
                totalTraps = 0;
                trapsCountEl.textContent = "0";
                window.clearConsole();
                loadAnalytics();
                appendTerminalLog({
                    stream: "ADMIN",
                    category: "system",
                    severity: "INFO",
                    source: "soc_admin",
                    protocol: "SQLITE:DB",
                    message: "Database and audit ledger completely wiped clean."
                });
            } else {
                alert(`Reset failed: ${data.message}`);
            }
        } catch (e) {
            alert(`Error resetting database: ${e}`);
        }
    };

    // Wire Node Simulate Buttons
    window.infectNode = async function(nodeId) {
        try {
            await fetch(`/api/simulate/infect/${nodeId}`, { method: "POST" });
        } catch (e) {
            alert(`Error isolating node: ${e}`);
        }
    };

    window.restoreNode = async function(nodeId) {
        try {
            await fetch(`/api/simulate/restore/${nodeId}`, { method: "POST" });
        } catch (e) {
            alert(`Error restoring node: ${e}`);
        }
    };

    const ATTACK_IP_POOLS = {
        "brute-force": ["198.51.100.99", "198.51.100.142", "198.51.100.205", "203.0.113.45", "192.0.2.81"],
        "exploit": ["203.0.113.88", "203.0.113.154", "203.0.113.219", "198.51.100.175", "192.0.2.114"],
        "port-sweep": ["198.51.100.77", "198.51.100.188", "192.0.2.63", "203.0.113.92", "192.0.2.199"]
    };
    const attackRotationIndex = { "brute-force": 0, "exploit": 0, "port-sweep": 0 };

    // Show/hide inline custom IP input on Red Team simulation cards
    window.toggleCustomAttackIp = function(cardKey) {
        const selectEl = document.getElementById(`select-ip-${cardKey}`);
        const customInputEl = document.getElementById(`custom-ip-${cardKey}`);
        if (!selectEl || !customInputEl) return;

        if (selectEl.value === "custom") {
            customInputEl.classList.remove("hidden");
            customInputEl.focus();
        } else {
            customInputEl.classList.add("hidden");
        }
    };

    // Wire Option A: Multi-IP Red Team Adversary Simulation Triggers
    window.triggerAttack = async function(attackType) {
        const cardKey = attackType.replace(/[^a-zA-Z0-9]/g, '');
        const btn = document.getElementById(`btn-attack-${cardKey}`);
        const selectEl = document.getElementById(`select-ip-${cardKey}`);
        const customInputEl = document.getElementById(`custom-ip-${cardKey}`);
        const proto = attackType === "port-sweep" ? "TCP:SWEEP" : "SSH:2222";
        const sev = attackType === "exploit" ? "CRIT" : "HIGH";

        const selection = selectEl ? selectEl.value : "rotate";
        let requestPayload = { mode: "single" };
        let displaySource = "";

        if (selection === "swarm") {
            requestPayload = { mode: "swarm" };
            displaySource = "SWARM (5 IPs)";
        } else if (selection === "rotate") {
            const pool = ATTACK_IP_POOLS[attackType] || ["198.51.100.99"];
            const idx = attackRotationIndex[attackType] || 0;
            const rotatedIp = pool[idx % pool.length];
            attackRotationIndex[attackType] = idx + 1;
            requestPayload = { src_ip: rotatedIp, mode: "single" };
            displaySource = rotatedIp;
        } else if (selection === "custom") {
            const customIp = customInputEl ? customInputEl.value.trim() : "";
            if (!customIp) {
                appendTerminalLog({
                    stream: "ADVERSARY",
                    category: "honeypot",
                    severity: "WARN",
                    source: "CUSTOM_IP",
                    protocol: proto,
                    message: "Please enter a valid IPv4 or IPv6 address before launching custom simulation."
                });
                if (customInputEl) customInputEl.focus();
                return;
            }
            requestPayload = { src_ip: customIp, mode: "single" };
            displaySource = customIp;
        } else {
            requestPayload = { src_ip: selection, mode: "single" };
            displaySource = selection;
        }

        const originalContent = btn ? btn.innerHTML : "";
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="animate-spin mr-1">⚙️</span> Launching ${attackType}...`;
            btn.classList.add("opacity-75");
        }

        appendTerminalLog({
            stream: "ADVERSARY",
            category: "honeypot",
            severity: sev,
            source: displaySource,
            protocol: proto,
            message: `Initiating ${attackType.toUpperCase()} intrusion simulation from ${displaySource}...`
        });

        try {
            const res = await fetch(`/api/simulate/attack/${attackType}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(requestPayload)
            });
            const data = await res.json();
            if (res.ok && data.status === "success") {
                appendTerminalLog({
                    stream: "ADVERSARY",
                    category: "honeypot",
                    severity: sev,
                    source: displaySource,
                    protocol: proto,
                    message: `Simulation payload delivered: ${data.message}`
                });
                if (data.data && Array.isArray(data.data.already_banned) && data.data.already_banned.length > 0) {
                    appendTerminalLog({
                        stream: "MITIGATION",
                        category: "mitigation",
                        severity: "INFO",
                        source: data.data.already_banned.join(", "),
                        protocol: "NETFILTER",
                        message: `Idempotent defense skip: IP(s) already actively banned in IOT_DEFENSE_BLOCKLIST (${data.data.already_banned.join(", ")}).`
                    });
                }
                if (data.data && Array.isArray(data.data.allowlist_protected) && data.data.allowlist_protected.length > 0) {
                    appendTerminalLog({
                        stream: "SYSTEM",
                        category: "mitigation",
                        severity: "WARN",
                        source: data.data.allowlist_protected.join(", "),
                        protocol: "ALLOWLIST",
                        message: `Safety Allowlist blocked ban on protected IP(s): ${data.data.allowlist_protected.join(", ")}.`
                    });
                }
                await fetchInitialStatus();
                loadAnalytics();
            } else {
                const errMsg = data.detail || data.message || `HTTP ${res.status}`;
                appendTerminalLog({
                    stream: "ADVERSARY",
                    category: "honeypot",
                    severity: "WARN",
                    source: displaySource,
                    protocol: proto,
                    message: `Simulation rejected: ${errMsg}`
                });
            }
        } catch (err) {
            appendTerminalLog({
                stream: "ADVERSARY",
                category: "honeypot",
                severity: "CRIT",
                source: displaySource,
                protocol: proto,
                message: `Network error triggering simulation: ${err}`
            });
        } finally {
            setTimeout(() => {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = originalContent;
                    btn.classList.remove("opacity-75");
                }
            }, 1000);
        }
    };

    // Threat Intelligence & Log Analytics Loader
    async function loadAnalytics() {
        try {
            const res = await fetch("/api/defense/analytics");
            const data = await res.json();
            if (data.status !== "success") return;

            const stats = data.data || {};
            const total = stats.total_threat_events || 0;
            const bd = stats.attack_breakdown || {};

            const totalEl = document.getElementById("analytics-total-threats");
            if (totalEl) totalEl.textContent = `${total} Events Analyzed`;

            // Attack Distribution Values & Bars
            const brute = bd.brute_force || 0;
            const exploit = bd.exploit || 0;
            const probe = bd.probe || 0;

            const brutePct = total > 0 ? Math.round((brute / total) * 100) : 0;
            const exploitPct = total > 0 ? Math.round((exploit / total) * 100) : 0;
            const probePct = total > 0 ? Math.round((probe / total) * 100) : 0;

            const bruteVal = document.getElementById("dist-brute-val");
            const bruteBar = document.getElementById("dist-brute-bar");
            if (bruteVal) bruteVal.textContent = `${brute} (${brutePct}%)`;
            if (bruteBar) bruteBar.style.width = `${brutePct}%`;

            const exploitVal = document.getElementById("dist-exploit-val");
            const exploitBar = document.getElementById("dist-exploit-bar");
            if (exploitVal) exploitVal.textContent = `${exploit} (${exploitPct}%)`;
            if (exploitBar) exploitBar.style.width = `${exploitPct}%`;

            const probeVal = document.getElementById("dist-probe-val");
            const probeBar = document.getElementById("dist-probe-bar");
            if (probeVal) probeVal.textContent = `${probe} (${probePct}%)`;
            if (probeBar) probeBar.style.width = `${probePct}%`;

            // Top Usernames
            const userContainer = document.getElementById("intel-usernames");
            if (userContainer) {
                userContainer.innerHTML = "";
                const users = stats.top_usernames || [];
                if (users.length === 0) {
                    userContainer.appendChild(createSafeElement("span", "none yet", "text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-500"));
                } else {
                    users.forEach(([u, count]) => {
                        userContainer.appendChild(createSafeElement("span", `${u} (${count})`, "text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-800 text-indigo-300"));
                    });
                }
            }

            // Top Passwords
            const passContainer = document.getElementById("intel-passwords");
            if (passContainer) {
                passContainer.innerHTML = "";
                const passes = stats.top_passwords || [];
                if (passes.length === 0) {
                    passContainer.appendChild(createSafeElement("span", "none yet", "text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-500"));
                } else {
                    passes.forEach(([p, count]) => {
                        passContainer.appendChild(createSafeElement("span", `${p} (${count})`, "text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300"));
                    });
                }
            }

            // Port Breakdown
            const ports = stats.target_ports || {};
            const p2222 = document.getElementById("port-2222-count");
            const p2223 = document.getElementById("port-2223-count");
            const p1883 = document.getElementById("port-1883-count");
            if (p2222) p2222.textContent = ports["2222"] || 0;
            if (p2223) p2223.textContent = ports["2223"] || 0;
            if (p1883) p1883.textContent = ports["1883"] || 0;

        } catch (e) {
            console.error("Error loading analytics:", e);
        }
    }

    // Modal Control & Deep Forensics Inspection
    window.openAnalyticsModal = function() {
        const modal = document.getElementById("analytics-modal");
        if (modal) modal.classList.remove("hidden");
        loadAnalytics();
    };

    window.closeAnalyticsModal = function() {
        const modal = document.getElementById("analytics-modal");
        if (modal) modal.classList.add("hidden");
    };

    window.openIpForensics = function(ip) {
        window.openAnalyticsModal();
        const input = document.getElementById("forensic-ip-input");
        if (input) input.value = ip;
        window.inspectIpForensics(ip);
    };

    window.inspectIpForensics = async function(customIp = null) {
        const input = document.getElementById("forensic-ip-input");
        const ip = (customIp || (input ? input.value : "")).trim();
        const container = document.getElementById("forensic-result-container");
        if (!container) return;

        if (!ip) {
            container.replaceChildren(
                createSafeElement("div", "Please enter a valid IP address to inspect.", "text-amber-400")
            );
            return;
        }

        container.replaceChildren(
            createSafeElement("div", `Querying forensic logs for ${ip}...`, "text-slate-400 animate-pulse")
        );

        try {
            const res = await fetch(`/api/defense/forensics/${encodeURIComponent(ip)}`);
            const data = await res.json();
            if (data.status !== "success") {
                container.replaceChildren(
                    createSafeElement("div", `Could not find forensics for IP: ${ip}`, "text-rose-400")
                );
                return;
            }

            const info = data.data || {};
            const events = info.events || [];
            const mitigations = info.mitigations || [];
            const isBanned = info.is_banned;

            const wrapper = document.createDocumentFragment();
            const headerRow = createSafeElement("div", "", "flex items-center justify-between pb-2 border-b border-slate-800");
            const leftGroup = createSafeElement("div", "", "flex items-center space-x-2");
            leftGroup.appendChild(createSafeElement("span", info.src_ip || ip, "text-sm font-mono font-bold text-white"));
            leftGroup.appendChild(createSafeElement(
                "span",
                isBanned ? "KERNEL DROPPED" : "UNBLOCKED",
                `px-2 py-0.5 rounded text-[10px] font-bold ${isBanned ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-slate-800 text-slate-300'}`
            ));
            headerRow.appendChild(leftGroup);
            headerRow.appendChild(createSafeElement("span", `${info.total_events || 0} Captured Intrusions`, "text-xs font-mono text-slate-400"));
            wrapper.appendChild(headerRow);

            if (mitigations.length > 0) {
                const mitBox = createSafeElement("div", "", "p-2.5 rounded bg-rose-950/30 border border-rose-900/60 text-xs");
                mitBox.appendChild(createSafeElement("span", "Active Autonomous Mitigation: ", "font-bold text-rose-300"));
                mitBox.appendChild(createSafeElement("span", `${mitigations[0].reason} (${mitigations[0].action})`, "text-slate-300"));
                wrapper.appendChild(mitBox);
            }

            if (events.length === 0) {
                wrapper.appendChild(createSafeElement("div", "No individual packets recorded in live window for this IP.", "text-slate-400 italic py-2"));
            } else {
                const seqWrap = createSafeElement("div", "", "max-h-60 overflow-y-auto space-y-1.5 pt-1");
                seqWrap.appendChild(createSafeElement("div", "Chronological Forensic Sequence:", "text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1"));
                events.forEach(ev => {
                    const rowEl = createSafeElement("div", "", "flex items-start space-x-2 p-1.5 rounded bg-slate-900/80 border border-slate-800/80 text-[11px]");
                    rowEl.appendChild(createSafeElement("span", formatDateTime(ev.timestamp), "font-mono text-slate-400 shrink-0 text-[10px]"));
                    rowEl.appendChild(createSafeElement("span", ev.eventid || "event", "font-mono px-1 rounded bg-slate-800 text-sky-400 text-[10px] shrink-0"));
                    const detailCell = createSafeElement("span", "", "flex-1 text-slate-300 break-all");
                    if (ev.username) {
                        detailCell.appendChild(createSafeElement("span", `${ev.username}:${ev.password || ''} `, "text-amber-300"));
                    }
                    if (ev.input_command) {
                        detailCell.appendChild(createSafeElement("code", `cmd: ${ev.input_command} `, "text-rose-400 font-mono text-[11px]"));
                    }
                    if (ev.message) {
                        detailCell.appendChild(document.createTextNode(ev.message));
                    }
                    rowEl.appendChild(detailCell);
                    seqWrap.appendChild(rowEl);
                });
                wrapper.appendChild(seqWrap);
            }

            container.replaceChildren(wrapper);
        } catch (e) {
            container.replaceChildren(
                createSafeElement("div", `Error retrieving forensic data: ${e}`, "text-rose-400")
            );
        }
    };

    // Download Full SOC Audit Report (JSON)
    window.downloadSocAuditReport = async function() {
        try {
            const res = await fetch("/api/defense/export");
            const data = await res.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `soc_audit_report_${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            appendTerminalLog({
                stream: "AUDIT",
                category: "system",
                severity: "INFO",
                source: "soc_admin",
                protocol: "HTTP:8050",
                message: "SOC Forensic Audit Report downloaded successfully."
            });
        } catch (e) {
            alert(`Error downloading report: ${e}`);
        }
    };

    // --- Simulated vs Live Traffic Mode & Real-World IoT / CCTV Onboarding ---

    function updateLiveEndpointUrls() {
        const host = window.location.hostname || "localhost";
        const port = window.location.port ? `:${window.location.port}` : "";
        const mqttEl = document.getElementById("live-endpoint-mqtt");
        const webhookEl = document.getElementById("live-endpoint-webhook");
        const decoyEl = document.getElementById("live-endpoint-honeypot");
        if (mqttEl) mqttEl.textContent = `mqtt://${host}:1883 • Topic: home/#`;
        if (webhookEl) webhookEl.textContent = `POST ${window.location.protocol}//${host}${port}/api/devices/ingest/<device_id>`;
        if (decoyEl) decoyEl.textContent = `ssh://${host}:2222 (Real attackers logged live)`;
    }

    function updateModeMetrics() {
        const nodesLabel = document.getElementById("metric-nodes-label");
        const nodesValue = document.getElementById("metric-nodes-value");
        const nodesBadge = document.getElementById("metric-nodes-badge");
        const isoLabel = document.getElementById("metric-isolation-label");
        const isoValue = document.getElementById("metric-isolation-value");
        const isoBadge = document.getElementById("metric-isolation-badge");

        if (currentTrafficMode === "live") {
            const total = registeredDevices.length;
            const online = registeredDevices.filter(d => !d.blocked && d.status === "ONLINE").length;
            const quarantined = registeredDevices.filter(d => d.blocked).length;
            if (nodesLabel) nodesLabel.textContent = "Registered Live Devices";
            if (nodesValue) nodesValue.textContent = `${online} / ${total}`;
            if (nodesBadge) nodesBadge.textContent = "LAN / MQTT / HTTP";
            if (isoLabel) isoLabel.textContent = "Live Policy Mode";
            if (isoValue) isoValue.textContent = "LIVE ACTIVE";
            if (isoBadge) isoBadge.textContent = `${quarantined} Quarantined`;
        } else {
            if (nodesLabel) nodesLabel.textContent = "Virtual IoT Nodes";
            if (nodesValue) nodesValue.textContent = "4 / 4";
            if (nodesBadge) nodesBadge.textContent = "172.20.0.0/24";
            if (isoLabel) isoLabel.textContent = "Quarantine Isolation";
            if (isoValue) isoValue.textContent = "ARMED";
            if (isoBadge) isoBadge.textContent = "internal: true";
        }
    }

    function applyTrafficModeUI(mode) {
        currentTrafficMode = mode === "live" ? "live" : "simulated";
        const btnSim = document.getElementById("mode-btn-simulated");
        const btnLive = document.getElementById("mode-btn-live");
        const simTopo = document.getElementById("section-simulated-topology");
        const simRed = document.getElementById("section-simulated-redteam");
        const liveSec = document.getElementById("section-live-devices");

        if (currentTrafficMode === "live") {
            if (btnSim) btnSim.className = "px-2.5 py-1 rounded-md font-semibold transition-all text-slate-400 hover:text-slate-200";
            if (btnLive) btnLive.className = "px-2.5 py-1 rounded-md font-semibold transition-all bg-emerald-600 text-white shadow-sm";
            if (simTopo) simTopo.classList.add("hidden");
            if (simRed) simRed.classList.add("hidden");
            if (liveSec) liveSec.classList.remove("hidden");
            updateLiveEndpointUrls();
            renderLiveDevices();
        } else {
            if (btnSim) btnSim.className = "px-2.5 py-1 rounded-md font-semibold transition-all bg-sky-600 text-white shadow-sm";
            if (btnLive) btnLive.className = "px-2.5 py-1 rounded-md font-semibold transition-all text-slate-400 hover:text-slate-200";
            if (simTopo) simTopo.classList.remove("hidden");
            if (simRed) simRed.classList.remove("hidden");
            if (liveSec) liveSec.classList.add("hidden");
        }
        updateModeMetrics();
    }

    window.setTrafficMode = async function(targetMode) {
        const cleanMode = targetMode === "live" ? "live" : "simulated";
        if (cleanMode === currentTrafficMode) return;
        try {
            const res = await fetch("/api/system/mode", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ mode: cleanMode })
            });
            const data = await res.json();
            if (res.ok && data.status === "success") {
                applyTrafficModeUI(cleanMode);
                await fetchInitialStatus();
            } else {
                appendTerminalLog({
                    stream: "SYSTEM",
                    category: "system",
                    severity: "WARN",
                    source: "mode_ctrl",
                    protocol: "HTTP:8050",
                    message: `Failed to switch traffic mode: ${data.detail || data.message || res.status}`
                });
            }
        } catch (err) {
            appendTerminalLog({
                stream: "SYSTEM",
                category: "system",
                severity: "CRIT",
                source: "mode_ctrl",
                protocol: "HTTP:8050",
                message: `Network error switching mode: ${err}`
            });
        }
    };

    function upsertDeviceLocal(device) {
        const idx = registeredDevices.findIndex(d => d.device_id === device.device_id);
        if (idx >= 0) {
            registeredDevices[idx] = device;
        } else {
            registeredDevices.unshift(device);
        }
        renderLiveDevices();
        updateModeMetrics();
    }

    function getDeviceIcon(deviceType) {
        if (deviceType === "cctv_camera") return "📹";
        if (deviceType === "smart_actuator") return "💡";
        if (deviceType === "edge_gateway") return "📡";
        return "🌡️";
    }

    function renderLiveDevices() {
        const grid = document.getElementById("live-devices-grid");
        if (!grid) return;

        if (!registeredDevices || registeredDevices.length === 0) {
            const emptyBox = createSafeElement("div", "", "md:col-span-3 p-6 rounded-lg bg-slate-950/70 border border-dashed border-slate-700 text-center space-y-2");
            emptyBox.appendChild(createSafeElement("div", "No real-world IoT or CCTV devices registered yet.", "text-sm font-semibold text-slate-300"));
            emptyBox.appendChild(createSafeElement("div", "Click '+ Add Real IoT Device' to onboard a LAN CCTV camera (RTSP/HTTP snapshot), ESP32 sensor, Raspberry Pi, or MQTT device.", "text-xs text-slate-500"));
            grid.replaceChildren(emptyBox);
            return;
        }

        const frag = document.createDocumentFragment();
        registeredDevices.forEach((dev) => {
            const isBlocked = Boolean(dev.blocked);
            const status = dev.status || "MONITORING";
            let cardBorder = "bg-slate-950/70 border-slate-800";
            let badgeCls = "bg-sky-950/70 border-sky-800 text-sky-300";
            if (isBlocked || status === "QUARANTINED") {
                cardBorder = "bg-red-950/30 border-red-600 shadow-lg shadow-red-950/30";
                badgeCls = "bg-red-950 border-red-500 text-red-400 animate-pulse";
            } else if (status === "ONLINE") {
                cardBorder = "bg-slate-950/70 border-emerald-800/60";
                badgeCls = "bg-emerald-950/70 border-emerald-700 text-emerald-400";
            } else if (status === "UNREACHABLE") {
                cardBorder = "bg-slate-950/70 border-amber-800/60";
                badgeCls = "bg-amber-950/70 border-amber-700 text-amber-400";
            }

            const card = createSafeElement("div", "", `p-4 rounded-lg border transition-all flex flex-col justify-between space-y-3 ${cardBorder}`);

            // Top row: icon + name + badge
            const topWrap = createSafeElement("div", "", "space-y-1.5");
            const headerRow = createSafeElement("div", "", "flex items-center justify-between gap-2");
            const nameGroup = createSafeElement("div", "", "flex items-center space-x-2 min-w-0");
            nameGroup.appendChild(createSafeElement("span", getDeviceIcon(dev.device_type), "text-base shrink-0"));
            nameGroup.appendChild(createSafeElement("span", dev.name || dev.device_id, "font-semibold text-sm text-slate-100 truncate"));
            headerRow.appendChild(nameGroup);
            headerRow.appendChild(createSafeElement("span", status, `px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wide uppercase border shrink-0 ${badgeCls}`));
            topWrap.appendChild(headerRow);

            // Metadata
            topWrap.appendChild(createSafeElement(
                "div",
                `ID: ${dev.device_id} • ${dev.ip_address}:${dev.port} (${(dev.protocol || "").toUpperCase()})`,
                "text-[11px] font-mono text-slate-400 break-all"
            ));
            if (dev.mqtt_topic) {
                topWrap.appendChild(createSafeElement("div", `MQTT: ${dev.mqtt_topic}`, "text-[11px] font-mono text-emerald-400/90 truncate"));
            }
            if (dev.snapshot_url) {
                topWrap.appendChild(createSafeElement("div", `Snapshot: ${dev.snapshot_url}`, "text-[10px] font-mono text-sky-400/80 truncate"));
            }
            const seenStr = dev.last_seen ? `Last Seen: ${formatDateTime(dev.last_seen)}` : "Awaiting live traffic or health probe";
            topWrap.appendChild(createSafeElement("div", seenStr, "text-[10px] font-mono text-slate-500"));
            if (dev.last_payload) {
                const payloadBox = createSafeElement("div", `Last Payload: ${dev.last_payload}`, "text-[10px] font-mono text-slate-300 bg-slate-900/90 border border-slate-800 rounded px-2 py-1 truncate");
                payloadBox.title = dev.last_payload;
                topWrap.appendChild(payloadBox);
            }
            card.appendChild(topWrap);

            // Actions row
            const actionsRow = createSafeElement("div", "", "flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-800/80");
            const probeBtn = createSafeElement("button", "Probe", "px-2 py-1 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors");
            probeBtn.onclick = () => window.probeDevice(dev.device_id);
            actionsRow.appendChild(probeBtn);

            if (dev.snapshot_configured) {
                const snapBtn = createSafeElement("button", "📷 Snapshot", "px-2 py-1 text-[11px] rounded bg-sky-950/60 hover:bg-sky-900 border border-sky-800 text-sky-300 font-medium transition-colors");
                snapBtn.onclick = () => window.openSnapshotModal(dev.device_id, dev.name || dev.device_id);
                actionsRow.appendChild(snapBtn);
            }

            if (isBlocked) {
                const unblockBtn = createSafeElement("button", "Restore", "flex-1 py-1 px-2 text-[11px] rounded bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 font-medium transition-colors");
                unblockBtn.onclick = () => window.unblockLiveDevice(dev.device_id);
                actionsRow.appendChild(unblockBtn);
            } else {
                const blockBtn = createSafeElement("button", "Quarantine", "flex-1 py-1 px-2 text-[11px] rounded bg-rose-950/50 hover:bg-rose-900 border border-rose-800 text-rose-300 font-medium transition-colors");
                blockBtn.onclick = () => window.blockLiveDevice(dev.device_id);
                actionsRow.appendChild(blockBtn);
            }

            const delBtn = createSafeElement("button", "✕", "px-2 py-1 text-[11px] rounded bg-slate-900 hover:bg-rose-950 border border-slate-800 hover:border-rose-800 text-slate-400 hover:text-rose-300 transition-colors");
            delBtn.title = "Remove device";
            delBtn.onclick = () => window.confirmDeleteDevice(dev.device_id, dev.name || dev.device_id);
            actionsRow.appendChild(delBtn);

            card.appendChild(actionsRow);
            frag.appendChild(card);
        });
        grid.replaceChildren(frag);
    }

    window.syncDeviceDefaults = function() {
        const typeEl = document.getElementById("dev-input-type");
        const protoEl = document.getElementById("dev-input-proto");
        const portEl = document.getElementById("dev-input-port");
        if (!typeEl || !protoEl || !portEl) return;

        if (protoEl.value === "mqtt") {
            portEl.value = "1883";
        } else if (protoEl.value === "http_webhook") {
            portEl.value = "80";
        } else if (typeEl.value === "cctv_camera") {
            portEl.value = "554";
        }
    };

    window.openAddDeviceModal = function() {
        const modal = document.getElementById("add-device-modal");
        const form = document.getElementById("form-add-device");
        const errBox = document.getElementById("add-device-error");
        const tokenBox = document.getElementById("device-token-reveal");
        if (form) form.reset();
        if (errBox) {
            errBox.textContent = "";
            errBox.classList.add("hidden");
        }
        if (tokenBox) tokenBox.classList.add("hidden");
        window.syncDeviceDefaults();
        if (modal) modal.classList.remove("hidden");
    };

    window.closeAddDeviceModal = function() {
        const modal = document.getElementById("add-device-modal");
        const tokenVal = document.getElementById("device-token-value");
        const tokenCurl = document.getElementById("device-token-curl");
        const tokenBox = document.getElementById("device-token-reveal");
        if (tokenVal) tokenVal.textContent = "";
        if (tokenCurl) tokenCurl.textContent = "";
        if (tokenBox) tokenBox.classList.add("hidden");
        if (modal) modal.classList.add("hidden");
    };

    window.submitAddDevice = async function(event) {
        if (event) event.preventDefault();
        const errBox = document.getElementById("add-device-error");
        const tokenBox = document.getElementById("device-token-reveal");
        const tokenVal = document.getElementById("device-token-value");
        const tokenCurl = document.getElementById("device-token-curl");
        if (errBox) {
            errBox.textContent = "";
            errBox.classList.add("hidden");
        }

        const payload = {
            device_id: (document.getElementById("dev-input-id")?.value || "").trim(),
            name: (document.getElementById("dev-input-name")?.value || "").trim(),
            device_type: document.getElementById("dev-input-type")?.value || "cctv_camera",
            protocol: document.getElementById("dev-input-proto")?.value || "rtsp_http",
            ip_address: (document.getElementById("dev-input-ip")?.value || "").trim(),
            port: parseInt(document.getElementById("dev-input-port")?.value || "554", 10),
            mqtt_topic: (document.getElementById("dev-input-topic")?.value || "").trim(),
            snapshot_url: (document.getElementById("dev-input-snapshot")?.value || "").trim()
        };

        try {
            const res = await fetch("/api/devices", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (!res.ok || data.status !== "success") {
                if (errBox) {
                    errBox.textContent = data.detail || data.message || `Failed to register device (HTTP ${res.status})`;
                    errBox.classList.remove("hidden");
                }
                return;
            }

            const dev = data.data && data.data.device ? data.data.device : null;
            if (dev) {
                const rawToken = dev.ingest_token || "";
                const publicCopy = { ...dev };
                delete publicCopy.ingest_token;
                upsertDeviceLocal(publicCopy);

                if (tokenBox && tokenVal && rawToken) {
                    tokenVal.textContent = rawToken;
                    const host = window.location.hostname || "localhost";
                    const portPart = window.location.port ? `:${window.location.port}` : "";
                    if (tokenCurl) {
                        tokenCurl.textContent = `Example Webhook: curl -X POST ${window.location.protocol}//${host}${portPart}/api/devices/ingest/${dev.device_id} -H "X-Device-Token: ${rawToken}" -H "Content-Type: application/json" -d '{"payload":{"motion":true}}'`;
                    }
                    tokenBox.classList.remove("hidden");
                }
            }
        } catch (err) {
            if (errBox) {
                errBox.textContent = `Network error registering device: ${err}`;
                errBox.classList.remove("hidden");
            }
        }
    };

    window.copyIngestToken = async function() {
        const tokenText = document.getElementById("device-token-value")?.textContent || "";
        if (!tokenText || !navigator.clipboard) return;
        try {
            await navigator.clipboard.writeText(tokenText);
            appendTerminalLog({
                stream: "SYSTEM",
                category: "system",
                severity: "INFO",
                source: "soc_ui",
                protocol: "CLIPBOARD",
                message: "Copied one-time device ingest token to clipboard."
            });
        } catch (err) {
            console.error(err);
        }
    };

    window.probeDevice = async function(deviceId) {
        try {
            const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/probe`, { method: "POST" });
            const data = await res.json();
            if (res.ok && data.status === "success" && data.data && data.data.device) {
                upsertDeviceLocal(data.data.device);
                appendTerminalLog({
                    stream: "IOT MESH",
                    category: "iot",
                    severity: data.data.device.status === "ONLINE" ? "INFO" : "WARN",
                    source: deviceId,
                    protocol: "TCP:PROBE",
                    message: data.message
                });
            }
        } catch (err) {
            appendTerminalLog({
                stream: "IOT MESH",
                category: "iot",
                severity: "WARN",
                source: deviceId,
                protocol: "TCP:PROBE",
                message: `Health probe failed: ${err}`
            });
        }
    };

    window.probeAllDevices = async function() {
        for (const dev of registeredDevices) {
            await window.probeDevice(dev.device_id);
        }
    };

    function updateLiveStreamButtonUI() {
        const btn = document.getElementById("btn-toggle-live-stream");
        if (!btn) return;
        if (liveSnapshotActive) {
            btn.textContent = "⏸ Pause Video";
            btn.className = "px-3 py-1 text-xs font-semibold rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-700 text-rose-300 transition-colors";
        } else {
            btn.textContent = "▶ Live Video";
            btn.className = "px-3 py-1 text-xs font-semibold rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 transition-colors";
        }
    }

    function stopLiveSnapshotStream() {
        liveSnapshotActive = false;
        liveSnapshotSession += 1;
        if (liveSnapshotTimer) {
            clearTimeout(liveSnapshotTimer);
            liveSnapshotTimer = null;
        }
        updateLiveStreamButtonUI();
    }

    async function loadSnapshotIntoModal(deviceId, sessionToken) {
        const statusText = document.getElementById("snapshot-status-text");
        const imgEl = document.getElementById("snapshot-preview-img");
        const fallbackEl = document.getElementById("snapshot-fallback-msg");
        const isFirstFrame = !imgEl || imgEl.classList.contains("hidden");

        if (isFirstFrame) {
            if (fallbackEl) {
                fallbackEl.textContent = "Fetching camera frame via SSRF-guarded proxy...";
                fallbackEl.classList.remove("hidden");
            }
            if (statusText) statusText.textContent = `Requesting frame for ${deviceId}...`;
        }

        try {
            const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/snapshot?t=${Date.now()}`);
            if (sessionToken !== liveSnapshotSession || activeSnapshotDevice !== deviceId) {
                return;
            }
            if (!res.ok) {
                let errDetail = `HTTP ${res.status}`;
                try {
                    const errJson = await res.json();
                    errDetail = errJson.detail || errJson.message || errDetail;
                } catch (_) {}
                stopLiveSnapshotStream();
                if (imgEl) {
                    imgEl.removeAttribute("src");
                    imgEl.classList.add("hidden");
                }
                if (currentSnapshotObjectUrl) {
                    URL.revokeObjectURL(currentSnapshotObjectUrl);
                    currentSnapshotObjectUrl = null;
                }
                if (fallbackEl) {
                    fallbackEl.textContent = `Snapshot unavailable: ${errDetail}`;
                    fallbackEl.classList.remove("hidden");
                }
                if (statusText) statusText.textContent = `Snapshot error (${res.status})`;
                return;
            }
            const blob = await res.blob();
            if (sessionToken !== liveSnapshotSession || activeSnapshotDevice !== deviceId) {
                return;
            }
            const nextUrl = URL.createObjectURL(blob);
            const oldUrl = currentSnapshotObjectUrl;
            currentSnapshotObjectUrl = nextUrl;

            if (imgEl) {
                imgEl.src = nextUrl;
                imgEl.classList.remove("hidden");
            }
            if (oldUrl) {
                URL.revokeObjectURL(oldUrl);
            }
            if (fallbackEl) fallbackEl.classList.add("hidden");

            const nowMs = Date.now();
            let fpsLabel = "";
            if (liveSnapshotActive && liveSnapshotLastFrameTs > 0) {
                const deltaSec = Math.max(0.05, (nowMs - liveSnapshotLastFrameTs) / 1000);
                const fps = Math.min(30, 1 / deltaSec).toFixed(1);
                fpsLabel = `LIVE VIDEO (${fps} fps) • `;
            }
            liveSnapshotLastFrameTs = nowMs;

            if (statusText) {
                statusText.textContent = `${fpsLabel}Captured via SSRF proxy at ${formatDateTime(nowMs / 1000)} IST`;
            }

            if (liveSnapshotActive && sessionToken === liveSnapshotSession && activeSnapshotDevice === deviceId) {
                liveSnapshotTimer = setTimeout(() => {
                    if (liveSnapshotActive && sessionToken === liveSnapshotSession && activeSnapshotDevice === deviceId) {
                        loadSnapshotIntoModal(deviceId, sessionToken);
                    }
                }, 120);
            }
        } catch (err) {
            if (sessionToken !== liveSnapshotSession) return;
            stopLiveSnapshotStream();
            if (fallbackEl) {
                fallbackEl.textContent = `Snapshot request failed: ${err}`;
                fallbackEl.classList.remove("hidden");
            }
            if (statusText) statusText.textContent = "Network error";
        }
    }

    window.toggleLiveSnapshotStream = function() {
        if (!activeSnapshotDevice) return;
        if (liveSnapshotActive) {
            stopLiveSnapshotStream();
            const statusText = document.getElementById("snapshot-status-text");
            if (statusText) statusText.textContent = `Paused live video at ${formatDateTime(Date.now() / 1000)} IST`;
        } else {
            liveSnapshotActive = true;
            liveSnapshotSession += 1;
            liveSnapshotLastFrameTs = 0;
            updateLiveStreamButtonUI();
            loadSnapshotIntoModal(activeSnapshotDevice, liveSnapshotSession);
        }
    };

    window.openSnapshotModal = function(deviceId, deviceName) {
        stopLiveSnapshotStream();
        activeSnapshotDevice = deviceId;
        liveSnapshotSession += 1;
        liveSnapshotLastFrameTs = 0;

        const dev = registeredDevices.find(d => d.device_id === deviceId);
        const isVideoUrl = dev && dev.snapshot_url && /(\/video\b|\/stream\b|mjpeg)/i.test(dev.snapshot_url);
        liveSnapshotActive = Boolean(isVideoUrl);
        updateLiveStreamButtonUI();

        const modal = document.getElementById("snapshot-modal");
        const titleEl = document.getElementById("snapshot-modal-title");
        const imgEl = document.getElementById("snapshot-preview-img");
        if (imgEl) {
            imgEl.removeAttribute("src");
            imgEl.classList.add("hidden");
        }
        if (currentSnapshotObjectUrl) {
            URL.revokeObjectURL(currentSnapshotObjectUrl);
            currentSnapshotObjectUrl = null;
        }
        if (titleEl) titleEl.textContent = `CCTV Snapshot — ${deviceName || deviceId}`;
        if (modal) modal.classList.remove("hidden");
        loadSnapshotIntoModal(deviceId, liveSnapshotSession);
    };

    window.refreshCurrentSnapshot = function() {
        if (activeSnapshotDevice) {
            if (liveSnapshotTimer) {
                clearTimeout(liveSnapshotTimer);
                liveSnapshotTimer = null;
            }
            liveSnapshotSession += 1;
            loadSnapshotIntoModal(activeSnapshotDevice, liveSnapshotSession);
        }
    };

    window.closeSnapshotModal = function() {
        stopLiveSnapshotStream();
        const modal = document.getElementById("snapshot-modal");
        const imgEl = document.getElementById("snapshot-preview-img");
        if (imgEl) {
            imgEl.removeAttribute("src");
            imgEl.classList.add("hidden");
        }
        if (currentSnapshotObjectUrl) {
            URL.revokeObjectURL(currentSnapshotObjectUrl);
            currentSnapshotObjectUrl = null;
        }
        activeSnapshotDevice = null;
        if (modal) modal.classList.add("hidden");
    };

    window.blockLiveDevice = async function(deviceId) {
        try {
            const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/block`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ reason: "Operator logical quarantine" })
            });
            const data = await res.json();
            if (res.ok && data.status === "success") {
                if (data.data && data.data.device) upsertDeviceLocal(data.data.device);
                await fetchInitialStatus();
            }
        } catch (err) {
            appendTerminalLog({
                stream: "QUARANTINE",
                category: "quarantine",
                severity: "WARN",
                source: deviceId,
                protocol: "HTTP:8050",
                message: `Error blocking device: ${err}`
            });
        }
    };

    window.unblockLiveDevice = async function(deviceId) {
        try {
            const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/unblock`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ admin_user: "soc_admin" })
            });
            const data = await res.json();
            if (res.ok && data.status === "success") {
                if (data.data && data.data.device) upsertDeviceLocal(data.data.device);
                await fetchInitialStatus();
            }
        } catch (err) {
            appendTerminalLog({
                stream: "QUARANTINE",
                category: "quarantine",
                severity: "WARN",
                source: deviceId,
                protocol: "HTTP:8050",
                message: `Error restoring device: ${err}`
            });
        }
    };

    function showConfirmModal(title, message, onConfirm) {
        const modal = document.getElementById("confirm-modal");
        const titleEl = document.getElementById("confirm-modal-title");
        const msgEl = document.getElementById("confirm-modal-message");
        const okBtn = document.getElementById("confirm-modal-ok");
        if (titleEl) titleEl.textContent = title;
        if (msgEl) msgEl.textContent = message;
        if (okBtn) {
            okBtn.onclick = async () => {
                window.closeConfirmModal();
                await onConfirm();
            };
        }
        if (modal) modal.classList.remove("hidden");
    }

    window.closeConfirmModal = function() {
        const modal = document.getElementById("confirm-modal");
        const okBtn = document.getElementById("confirm-modal-ok");
        if (okBtn) okBtn.onclick = null;
        if (modal) modal.classList.add("hidden");
    };

    window.confirmDeleteDevice = function(deviceId, deviceName) {
        showConfirmModal(
            "Remove Real-World Device",
            `Remove '${deviceName}' (${deviceId}) from the Live Traffic registry?`,
            async () => {
                try {
                    const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}`, { method: "DELETE" });
                    if (res.ok) {
                        registeredDevices = registeredDevices.filter(d => d.device_id !== deviceId);
                        renderLiveDevices();
                        updateModeMetrics();
                        appendTerminalLog({
                            stream: "IOT MESH",
                            category: "iot",
                            severity: "INFO",
                            source: deviceId,
                            protocol: "HTTP:8050",
                            message: `Removed real device '${deviceName}' from live monitoring.`
                        });
                    }
                } catch (err) {
                    console.error(err);
                }
            }
        );
    };

    // Keyboard shortcut to close modals
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            window.closeExportLogsModal();
            window.closeAnalyticsModal();
            window.closeAddDeviceModal();
            window.closeSnapshotModal();
            window.closeConfirmModal();
        }
    });

    // Initialize
    fetchInitialStatus();
    loadAnalytics();
    connectSSE();
});

