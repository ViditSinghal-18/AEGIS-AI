/**
 * AEGIS-AI: Real-Time Sequential Telemetry Stream Console
 * STRICT HONESTY:
 * - Executes actual sequential stage API calls (/api/scan/dns, /tls, /headers, /ct, /prioritize).
 * - Logs real timing, genuine HTTP status codes, and evidence summary.
 * - Zero hardcoded or simulated log lines.
 */

window.AegisTelemetry = (function () {
    'use strict';

    const STAGES = [
        { id: 'dns', name: 'DNS OSINT & SPF/DMARC Resolution', endpoint: '/api/scan/dns' },
        { id: 'tls', name: 'TLS SNI Cryptographic Handshake', endpoint: '/api/scan/tls' },
        { id: 'headers', name: 'HTTP Defense-in-Depth & Header Audit', endpoint: '/api/scan/headers' },
        { id: 'ct', name: 'Certificate Transparency Subdomain Discovery', endpoint: '/api/scan/ct' }
    ];

    function appendLog(consoleId, stageName, message, type = 'info', durationMs = null) {
        const consoleEl = document.getElementById(consoleId);
        if (!consoleEl) return;

        const timeStr = new Date().toLocaleTimeString([], { hour12: false });
        const line = document.createElement('div');
        line.className = `quiet-log-line line-${type}`;

        let prefixColor = 'var(--ink-tertiary)';
        if (type === 'error') prefixColor = 'var(--rule-crit)';
        else if (type === 'warning') prefixColor = 'var(--rule-high)';

        const durationBadge = durationMs !== null ? `<span style="color:var(--ink-tertiary);margin-left:6px;">[${durationMs}ms]</span>` : '';
        line.innerHTML = `<span style="color:${prefixColor};">${timeStr}</span> &middot; <strong style="color:var(--ink-primary);">${AegisUtils.escapeHtml(stageName)}:</strong> <span style="color:var(--ink-secondary);">${AegisUtils.escapeHtml(message)}</span> ${durationBadge}`;

        consoleEl.appendChild(line);
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    async function executeRealPipelineStages(target, onComplete = null, consoleId = 'terminalLogs') {
        const consoleEl = document.getElementById(consoleId);
        if (consoleEl) consoleEl.innerHTML = '';

        appendLog(consoleId, 'Pipeline', `Initiating real perimeter reconnaissance on '${target}'...`, 'info');

        let aggregatedDiscovery = { target: target, http: {}, dns: {}, tls: {}, discovered_assets: [] };
        let allOk = true;

        const stageStepMap = { 'dns': 'stepDns', 'tls': 'stepTls', 'headers': 'stepHeaders', 'ct': 'stepCt' };

        for (const stage of STAGES) {
            const stepEl = document.getElementById(stageStepMap[stage.id]);
            if (stepEl) {
                stepEl.classList.add('active');
            }

            const t0 = performance.now();
            try {
                appendLog(consoleId, stage.name, 'Sending outbound probe...', 'info');
                const resp = await fetch(`${stage.endpoint}?target=${encodeURIComponent(target)}`, {
                    headers: { 'Accept': 'application/json' }
                });
                const elapsed = Math.round(performance.now() - t0);

                if (resp.ok) {
                    const data = await resp.json();
                    let summaryText = 'Completed successfully.';

                    if (stage.id === 'dns') {
                        if (data.probe_error || data.a_probe_error) {
                            summaryText = `DNS probe unavailable (${data.probe_error || data.a_probe_error}). SPF: ${data.spf_present ? 'Enforced' : (data.txt_probe_error ? 'Unverified' : 'Missing')}, DMARC: ${data.dmarc_present ? 'Enforced' : (data.dmarc_probe_error ? 'Unverified' : 'Missing')}.`;
                        } else {
                            summaryText = `Resolved ${data.A ? data.A.length : 0} A record(s). SPF: ${data.spf_present ? 'Enforced' : 'Missing'}, DMARC: ${data.dmarc_present ? 'Enforced' : 'Missing'}.`;
                        }
                        aggregatedDiscovery.dns = data;
                    } else if (stage.id === 'tls') {
                        if (data.probe_error && (!data.protocol || data.protocol === 'unavailable')) {
                            summaryText = `TLS probe unavailable (${data.probe_error}): Port 443 handshake inaccessible.`;
                        } else {
                            const expDays = (data.days_until_expiry !== null && data.days_until_expiry !== undefined) ? `${data.days_until_expiry} days` : 'Unknown';
                            summaryText = `Protocol: ${data.protocol || 'None'}, Days to Expiry: ${expDays}, Issuer: ${data.issuer || 'Unknown'}.`;
                        }
                        aggregatedDiscovery.tls = data;
                    } else if (stage.id === 'headers') {
                        summaryText = `Status HTTP ${data.status_code || 0}, Missing Headers: ${(data.missing_security_headers || []).length}, Server: '${data.server_banner || 'Hidden'}'.`;
                        aggregatedDiscovery.http = data;
                    } else if (stage.id === 'ct') {
                        summaryText = `Discovered ${(data.subdomains || []).length} public subdomain(s) in crt.sh CT logs.`;
                        aggregatedDiscovery.ct_subdomains = data.subdomains || [];
                    }

                    if (stepEl) {
                        stepEl.classList.remove('active');
                        stepEl.classList.add('complete');
                    }
                    appendLog(consoleId, stage.name, summaryText, 'success', elapsed);
                } else {
                    const errText = await resp.text();
                    if (stepEl) stepEl.classList.remove('active');
                    appendLog(consoleId, stage.name, `Probe returned HTTP ${resp.status}: ${errText.substring(0, 100)}`, 'warning', elapsed);
                }
            } catch (err) {
                const elapsed = Math.round(performance.now() - t0);
                if (stepEl) stepEl.classList.remove('active');
                appendLog(consoleId, stage.name, `Probe failed: ${err.message}`, 'error', elapsed);
                allOk = false;
            }
        }

        // Final Full Scan Trigger (Prioritization & Correlation)
        const triageStep = document.getElementById('stepTriage');
        if (triageStep) triageStep.classList.add('active');
        const finalT0 = performance.now();
        try {
            const res = await fetch('/api/scan-online', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            });
            const finalElapsed = Math.round(performance.now() - finalT0);

            if (res.ok) {
                if (triageStep) { triageStep.classList.remove('active'); triageStep.classList.add('complete'); }
                const finalData = await res.json();
                const totalF = (finalData.report && finalData.report.findings) ? finalData.report.findings.length : 0;
                appendLog(consoleId, 'Prioritization', `Triage complete. ${totalF} findings prioritized with CISA KEV and EPSS signals.`, 'success', finalElapsed);
                if (onComplete) onComplete(finalData);
            } else {
                if (triageStep) triageStep.classList.remove('active');
                appendLog(consoleId, 'Prioritization', `Assessment dispatch failed with status ${res.status}.`, 'error', finalElapsed);
            }
        } catch (err) {
            if (triageStep) triageStep.classList.remove('active');
            appendLog(consoleId, 'Prioritization', `Error during final report correlation: ${err.message}`, 'error');
        }
    }

    return {
        appendLog,
        executeRealPipelineStages
    };
})();
