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

    // Helper: Safely append text to an element to prevent DOM XSS
    function createSafeElement(tag, text, classes = "") {
        const el = document.createElement(tag);
        if (classes) el.className = classes;
        el.textContent = text;
        return el;
    }

    // Format UNIX timestamp
    function formatTime(ts) {
        if (!ts) return "--:--:--";
        const d = new Date(ts * 1000);
        return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    // Append log line to terminal feed console
    function appendTerminalLog(prefix, message, type = "info") {
        const line = document.createElement("div");
        line.className = "flex items-start space-x-2 py-0.5 border-b border-slate-900/60";

        const timeSpan = createSafeElement("span", `[${formatTime(Date.now() / 1000)}]`, "text-slate-500 select-none");
        let badgeColor = "text-sky-400";
        if (type === "threat") badgeColor = "text-rose-400 font-bold";
        else if (type === "warning") badgeColor = "text-amber-400";
        else if (type === "success") badgeColor = "text-emerald-400";

        const prefixSpan = createSafeElement("span", `[${prefix}]`, badgeColor);
        const msgSpan = createSafeElement("span", message, "text-slate-300 break-all");

        line.appendChild(timeSpan);
        line.appendChild(prefixSpan);
        line.appendChild(msgSpan);

        terminalFeed.appendChild(line);
        terminalFeed.scrollTop = terminalFeed.scrollHeight;

        // Cap terminal lines at 150 to keep browser memory lightweight
        while (terminalFeed.childNodes.length > 150) {
            terminalFeed.removeChild(terminalFeed.firstChild);
        }
    }

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

        // Timestamp
        const tdTime = createSafeElement("td", formatTime(record.timestamp), "px-4 py-2 text-slate-400 font-mono text-xs whitespace-nowrap");
        
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
            appendTerminalLog("SYSTEM", `Failed to load initial status: ${e}`, "threat");
        }
    }

    // Connect SSE Stream
    function connectSSE() {
        appendTerminalLog("STREAM", "Connecting to telemetry event stream /api/stream...", "info");
        const eventSource = new EventSource("/api/stream");

        eventSource.addEventListener("open", () => {
            sseIndicator.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse";
            ssePill.className = "inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950/40 border border-emerald-800 text-emerald-400";
            document.getElementById("sse-text").textContent = "STREAM LIVE";
            appendTerminalLog("STREAM", "Connected to realtime security bus.", "success");
        });

        eventSource.addEventListener("connected", (e) => {
            appendTerminalLog("STREAM", "Session handshake synchronized.", "success");
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
                appendTerminalLog("HONEYPOT", `Trap hit from ${src} -> ${ev.eventid} ${user} ${pwd} ${cmd}`.trim(), "warning");
            } catch (err) {
                appendTerminalLog("HONEYPOT", "Raw hit received.", "warning");
            }
            // Refresh Threat Intelligence
            loadAnalytics();
        });

        eventSource.addEventListener("mitigation_alert", (e) => {
            try {
                const payload = JSON.parse(e.data);
                const rec = payload.data || {};
                activeBansCount++;
                bannedCountEl.textContent = activeBansCount;
                addMitigationRow(rec);
                appendTerminalLog("MITIGATION", `AUTONOMOUS BAN ENFORCED: ${rec.src_ip} -> ${rec.reason}`, "threat");
            } catch (err) {
                appendTerminalLog("MITIGATION", "Mitigation alert received.", "threat");
            }
            // Refresh Threat Intelligence
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
                appendTerminalLog("ADMIN", `Manual unban executed for IP: ${ip}`, "info");
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("reset_alert", () => {
            activeBansCount = 0;
            bannedCountEl.textContent = "0";
            mitigationTableBody.innerHTML = "";
            appendTerminalLog("ADMIN", "All firewall drop rules have been reset.", "info");
        });

        eventSource.addEventListener("database_reset_alert", () => {
            activeBansCount = 0;
            bannedCountEl.textContent = "0";
            totalTraps = 0;
            trapsCountEl.textContent = "0";
            mitigationTableBody.innerHTML = "";
            loadAnalytics();
            appendTerminalLog("ADMIN", "Database audit history and analytics wiped clean by admin.", "success");
        });

        eventSource.addEventListener("node_quarantined", (e) => {
            try {
                const payload = JSON.parse(e.data);
                updateNodeStatus(payload.data.node_id, "quarantined");
                appendTerminalLog("QUARANTINE", `Dynamic containment triggered: ${payload.data.node_id} isolated to iot_quarantine_net.`, "threat");
            } catch (err) {
                console.error(err);
            }
        });

        eventSource.addEventListener("node_restored", (e) => {
            try {
                const payload = JSON.parse(e.data);
                updateNodeStatus(payload.data.node_id, "production");
                appendTerminalLog("QUARANTINE", `Container restored: ${payload.data.node_id} reconnected to iot_production_net.`, "success");
            } catch (err) {
                console.error(err);
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
                loadAnalytics();
                appendTerminalLog("ADMIN", "Database and audit ledger completely wiped clean.", "success");
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

        appendTerminalLog("ADVERSARY", `Initiating ${attackType.toUpperCase()} intrusion attack simulation...`, "warning");

        try {
            const res = await fetch(`/api/simulate/attack/${attackType}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" }
            });
            const data = await res.json();
            if (data.status === "success") {
                appendTerminalLog("ADVERSARY", `Simulation payload delivered: ${data.message}`, "threat");
            } else {
                appendTerminalLog("ADVERSARY", `Simulation request error: ${data.message}`, "warning");
            }
        } catch (err) {
            appendTerminalLog("ADVERSARY", `Network error triggering simulation: ${err}`, "threat");
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
                    const timeStr = formatTime(ev.timestamp);
                    const cmdStr = ev.input_command ? `<code class="text-rose-400 font-mono text-[11px]">cmd: ${ev.input_command}</code>` : '';
                    const credStr = ev.username ? `<span class="text-amber-300">${ev.username}:${ev.password || ''}</span>` : '';
                    html += `
                        <div class="flex items-start space-x-2 p-1.5 rounded bg-slate-900/80 border border-slate-800/80 text-[11px]">
                            <span class="font-mono text-slate-500">${timeStr}</span>
                            <span class="font-mono px-1 rounded bg-slate-800 text-sky-400 text-[10px]">${ev.eventid}</span>
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
            appendTerminalLog("AUDIT", "SOC Forensic Audit Report downloaded successfully.", "success");
        } catch (e) {
            alert(`Error downloading report: ${e}`);
        }
    };

    // Initialize
    fetchInitialStatus();
    loadAnalytics();
    connectSSE();
});

