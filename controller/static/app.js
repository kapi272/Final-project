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
        if (record.action === "UNBAN") {
            badgeClass = "px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-emerald-950/60 border border-emerald-800 text-emerald-400";
        } else if (record.action === "RESET_ALL_BANS") {
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

                // Pre-populate node states
                if (payload.node_states) {
                    for (const [nodeId, state] of Object.entries(payload.node_states)) {
                        updateNodeStatus(nodeId, state);
                    }
                }

                // Pre-populate mitigation rows in descending order
                if (payload.recent_mitigations) {
                    mitigationTableBody.innerHTML = "";
                    payload.recent_mitigations.forEach(r => addMitigationRow(r, false));
                }
            }
        } catch (e) {
            appendTerminalLog("SYSTEM", `Failed to load initial status: ${e}`, "threat", "system");
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
                activeBansCount++;
                bannedCountEl.textContent = activeBansCount;
                addMitigationRow(rec);
                appendTerminalLog({
                    stream: "MITIGATION",
                    category: "mitigation",
                    severity: rec.severity || "CRIT",
                    source: rec.src_ip || "unknown",
                    protocol: "NETFILTER",
                    message: `AUTONOMOUS BAN ENFORCED: ${rec.reason} (Chain: IOT_DEFENSE_BLOCKLIST)`
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
                const ip = payload.data.ip;
                const row = document.getElementById(`row-ip-${ip.replace(/[^a-zA-Z0-9]/g, '_')}`);
                if (row) row.remove();
                if (activeBansCount > 0) activeBansCount--;
                bannedCountEl.textContent = activeBansCount;
                appendTerminalLog({
                    stream: "MITIGATION",
                    category: "mitigation",
                    severity: "INFO",
                    source: ip,
                    protocol: "NETFILTER",
                    message: `Manual unban executed by ${payload.data.unbanned_by || 'soc_admin'}`
                });
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
            mitigationTableBody.innerHTML = "";
            window.clearConsole();
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
                let dev = "iot_node";
                if (topic.includes("temperature") || topic.includes("sensor")) dev = "temp_sensor_01";
                else if (topic.includes("bulb") || topic.includes("device")) dev = "smart_bulb_01";
                appendTerminalLog({
                    stream: "IOT MESH",
                    category: "iot",
                    severity: "INFO",
                    source: dev,
                    protocol: "MQTT:1883",
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

    // Wire Option A: Red Team Adversary Simulation Triggers
    window.triggerAttack = async function(attackType) {
        const btnId = `btn-attack-${attackType.replace(/[^a-zA-Z0-9]/g, '')}`;
        const btn = document.getElementById(btnId);
        const originalContent = btn ? btn.innerHTML : "";

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="animate-spin mr-1">⚙️</span> Launching ${attackType}...`;
            btn.classList.add("opacity-75");
        }

        const attackerIp = attackType === "exploit" ? "203.0.113.88" : (attackType === "port-sweep" ? "198.51.100.77" : "198.51.100.99");
        const proto = attackType === "exploit" ? "SSH:2222" : (attackType === "port-sweep" ? "TCP:SWEEP" : "SSH:2222");

        appendTerminalLog({
            stream: "ADVERSARY",
            category: "honeypot",
            severity: attackType === "exploit" ? "CRIT" : "HIGH",
            source: attackerIp,
            protocol: proto,
            message: `Initiating ${attackType.toUpperCase()} intrusion attack simulation...`
        });

        try {
            const res = await fetch(`/api/simulate/attack/${attackType}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" }
            });
            const data = await res.json();
            if (data.status === "success") {
                appendTerminalLog({
                    stream: "ADVERSARY",
                    category: "honeypot",
                    severity: attackType === "exploit" ? "CRIT" : "HIGH",
                    source: attackerIp,
                    protocol: proto,
                    message: `Simulation payload delivered: ${data.message}`
                });
            } else {
                appendTerminalLog({
                    stream: "ADVERSARY",
                    category: "honeypot",
                    severity: "WARN",
                    source: attackerIp,
                    protocol: proto,
                    message: `Simulation request error: ${data.message}`
                });
            }
        } catch (err) {
            appendTerminalLog({
                stream: "ADVERSARY",
                category: "honeypot",
                severity: "CRIT",
                source: attackerIp,
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
            container.innerHTML = `<div class="text-amber-400">Please enter a valid IP address to inspect.</div>`;
            return;
        }

        container.innerHTML = `<div class="text-slate-400 animate-pulse">Querying forensic logs for ${ip}...</div>`;

        try {
            const res = await fetch(`/api/defense/forensics/${encodeURIComponent(ip)}`);
            const data = await res.json();
            if (data.status !== "success") {
                container.innerHTML = `<div class="text-rose-400">Could not find forensics for IP: ${ip}</div>`;
                return;
            }

            const info = data.data || {};
            const events = info.events || [];
            const mitigations = info.mitigations || [];
            const isBanned = info.is_banned;

            let html = `
                <div class="flex items-center justify-between pb-2 border-b border-slate-800">
                    <div class="flex items-center space-x-2">
                        <span class="text-sm font-mono font-bold text-white">${info.src_ip}</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isBanned ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-slate-800 text-slate-300'}">
                            ${isBanned ? 'KERNEL DROPPED' : 'UNBLOCKED'}
                        </span>
                    </div>
                    <span class="text-xs font-mono text-slate-400">${info.total_events} Captured Intrusions</span>
                </div>
            `;

            if (mitigations.length > 0) {
                html += `
                    <div class="p-2.5 rounded bg-rose-950/30 border border-rose-900/60 text-xs">
                        <span class="font-bold text-rose-300">Active Autonomous Mitigation:</span>
                        <span class="text-slate-300 ml-1">${mitigations[0].reason} (${mitigations[0].action})</span>
                    </div>
                `;
            }

            if (events.length === 0) {
                html += `<div class="text-slate-400 italic py-2">No individual packets recorded in live window for this IP.</div>`;
            } else {
                html += `
                    <div class="max-h-60 overflow-y-auto space-y-1.5 pt-1">
                        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">Chronological Forensic Sequence:</div>
                `;
                events.forEach(ev => {
                    const timeStr = formatDateTime(ev.timestamp);
                    const cmdStr = ev.input_command ? `<code class="text-rose-400 font-mono text-[11px]">cmd: ${ev.input_command}</code>` : '';
                    const credStr = ev.username ? `<span class="text-amber-300">${ev.username}:${ev.password || ''}</span>` : '';
                    html += `
                        <div class="flex items-start space-x-2 p-1.5 rounded bg-slate-900/80 border border-slate-800/80 text-[11px]">
                            <span class="font-mono text-slate-400 shrink-0 text-[10px]">${timeStr}</span>
                            <span class="font-mono px-1 rounded bg-slate-800 text-sky-400 text-[10px] shrink-0">${ev.eventid}</span>
                            <span class="flex-1 text-slate-300">${credStr} ${cmdStr} ${ev.message || ''}</span>
                        </div>
                    `;
                });
                html += `</div>`;
            }

            container.innerHTML = html;
        } catch (e) {
            container.innerHTML = `<div class="text-rose-400">Error retrieving forensic data: ${e}</div>`;
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

    // Keyboard shortcut to close modals
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            window.closeExportLogsModal();
            window.closeAnalyticsModal();
        }
    });

    // Initialize
    fetchInitialStatus();
    loadAnalytics();
    connectSSE();
});

