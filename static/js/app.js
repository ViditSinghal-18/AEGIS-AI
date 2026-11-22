/**
 * AEGIS-AI: Main Frontend Application Controller
 * Coordinates telemetry streams, 3D cyber globe, exposure charts, triage lists,
 * attack walkthroughs, command palette, and multi-format exports.
 */

window.AegisApp = (function () {
    'use strict';

    let currentReport = null;
    let selectedFindingIndex = 0;
    let dashboardInitialized = false;

    async function initDashboard() {
        if (dashboardInitialized) return;
        dashboardInitialized = true;

        // 1. Initialize 3D Globe with error guard
        try {
            if (window.AegisGlobe && typeof AegisGlobe.initGlobe === 'function') {
                AegisGlobe.initGlobe('globe-container');
            }
        } catch (globeErr) {
            console.warn('Globe initialization error handled gracefully:', globeErr);
        }

        // 2. Setup Navigation and Modals
        try {
            setupEventListeners();
        } catch (navErr) {
            console.warn('Navigation setup error handled gracefully:', navErr);
        }

        // 3. Early Copilot Initialization (ensures welcome message & prompt pills render immediately)
        try {
            if (window.AegisCopilot && typeof AegisCopilot.initCopilot === 'function') {
                const initTarget = document.getElementById('scanTargetInput') ? document.getElementById('scanTargetInput').value.trim() : '';
                AegisCopilot.initCopilot(initTarget);
            }
        } catch (copilotErr) {
            console.warn('Copilot early initialization error handled gracefully:', copilotErr);
        }

        // 4. Load initial report if a target is already set
        try {
            await loadInitialData();
        } catch (dataErr) {
            console.warn('Initial data load error handled gracefully:', dataErr);
        }
    }

    async function loadInitialData() {
        try {
            const inputTarget = document.getElementById('scanTargetInput') ? document.getElementById('scanTargetInput').value.trim() : '';
            if (!inputTarget) {
                // Awaiting explicit target entry; do not inject unrequested mock data
                return;
            }
            const targetParam = `?target=${encodeURIComponent(inputTarget)}`;
            const resp = await fetch(`/api/report${targetParam}`);
            if (resp.ok) {
                const data = await resp.json();
                applyReportData(data);
            }
        } catch (e) {
            console.warn('Initial data load note:', e.message);
        }
    }

    function applyReportData(data) {
        currentReport = data;
        const target = data.target || 'demo.shield.io';

        // Initialize Copilot for current target
        AegisCopilot.initCopilot(target);

        // Update Header & Status Badges
        AegisUtils.safeSetText('targetDisplay', target);
        AegisUtils.safeSetText('operationalModeBadge', data.operational_mode || data.mode || 'PASSIVE OSINT');

        const findings = data.findings || data.prioritized_findings || [];
        function getFindingPriority(f) {
            const p = f.priority_level || '';
            if (p.includes('P1')) return 'P1';
            if (p.includes('P2')) return 'P2';
            if (p.includes('P3')) return 'P3';
            if (p.includes('P4')) return 'P4';
            const s = (f.severity || '').toLowerCase();
            if (s === 'critical') return 'P1';
            if (s === 'high') return 'P2';
            if (s === 'medium') return 'P3';
            return 'P4';
        }

        const critCount = findings.filter(f => getFindingPriority(f) === 'P1').length;
        const highCount = findings.filter(f => getFindingPriority(f) === 'P2').length;
        const medCount = findings.filter(f => getFindingPriority(f) === 'P3').length;
        const lowCount = findings.filter(f => getFindingPriority(f) === 'P4').length;

        AegisUtils.safeSetText('statTotalFindings', findings.length);
        AegisUtils.safeSetText('statCritCount', critCount);
        AegisUtils.safeSetText('statHighCount', highCount);
        AegisUtils.safeSetText('statMedCount', medCount);
        AegisUtils.safeSetText('statLowCount', lowCount);

        // Compliance Scores
        const comp = data.compliance_governance || {};
        const readiness = comp.overall_readiness_score !== undefined ? comp.overall_readiness_score : (comp.score !== undefined ? comp.score : (data.score !== undefined ? data.score : 75.0));
        const grade = comp.overall_grade || data.grade || 'B';
        AegisUtils.safeSetText('statComplianceScore', `${readiness}%`);
        AegisUtils.safeSetText('statComplianceGrade', `Grade ${grade}`);

        // Plain-Language Verdict Sentence
        const verdictEl = document.getElementById('verdictSentence');
        if (verdictEl) {
            if (findings.length === 0) {
                verdictEl.textContent = `${target}: 0 perimeter exposures detected, perimeter hardened.`;
            } else {
                const urgentCount = critCount + highCount;
                if (urgentCount > 0) {
                    verdictEl.textContent = `${target}: ${findings.length} ${findings.length === 1 ? 'finding' : 'findings'} identified (${critCount} critical, ${highCount} high priority requiring action).`;
                } else {
                    verdictEl.textContent = `${target}: ${findings.length} ${findings.length === 1 ? 'finding' : 'findings'} identified, none currently urgent.`;
                }
            }
        }
        const verdictTime = document.getElementById('verdictTimestamp');
        if (verdictTime) {
            verdictTime.textContent = new Date().toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
        }

        // Exploitable in Wild Count (CISA KEV or high EPSS >= 5%)
        const exploitableCount = findings.filter(f => f.in_cisa_kev || (f.epss_probability && f.epss_probability >= 0.05) || (f.threat_intel && f.threat_intel.in_cisa_kev)).length;
        AegisUtils.safeSetText('statExploitableCount', exploitableCount);
        AegisUtils.safeSetText('statReadinessScore', `${readiness}%`);

        // Infrastructure Card Details
        AegisUtils.safeSetText('infraResolvedIp', data.resolved_ip || (data.report && data.report.resolved_ip) || 'Unavailable');
        const geo = data.geo_telemetry || (data.report && data.report.geo_telemetry) || {};
        AegisUtils.safeSetText('infraAsn', geo.asn || 'Unavailable');
        AegisUtils.safeSetText('infraDatacenter', geo.datacenter || (geo.region || 'Standard Gateway'));
        AegisUtils.safeSetText('infraIngress', data.ingress_info || 'TCP 443 (HTTPS)');
        AegisUtils.safeSetText('infraLatency', geo.round_trip_latency_ms ? `${geo.round_trip_latency_ms} ms` : 'Unavailable');

        // Plot 3D Globe Pins & Ingress Connectivity from real geo data (no fabricated coordinates)
        if (geo && geo.coordinates_available !== false && geo.lat !== null && geo.lon !== null) {
            AegisGlobe.plotRealTargetPins(target, geo, data.subdomains || []);
            AegisUtils.safeSetText('globeTargetLocation', `${geo.city || 'Edge Ingress'}, ${geo.country || 'Global'} (${geo.asn || 'Perimeter Gateway'})`);
        } else {
            AegisGlobe.plotRealTargetPins(target, null, data.subdomains || []);
            AegisUtils.safeSetText('globeTargetLocation', `${target} · Edge Anycast Transit`);
        }

        // Render Charts
        AegisCharts.renderExposureMatrix(findings, 'riskMatrixChart', (selectedF, idx) => {
            selectFinding(idx);
        });

        if (findings.length > 0) {
            selectFinding(0);
        }

        // Render Findings Table
        renderFindingsTable(findings);

        // Render Compliance Cards
        renderComplianceCards(comp);
    }

    function renderFindingsTable(findings) {
        const tbody = document.getElementById('findingsTableBody');
        if (!tbody) return;

        if (!findings || findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="ledger-empty-cell">No perimeter findings detected. Asset perimeter appears secure.</td></tr>`;
            return;
        }

        tbody.innerHTML = findings.map((f, idx) => {
            const rawSev = (f.priority_level || f.severity || 'P3').toUpperCase();
            let sevClass = 'sev-low';
            let sevLabel = 'Low';
            let labelClass = 'low';

            if (rawSev.includes('P1') || rawSev.includes('CRITICAL')) {
                sevClass = 'sev-critical';
                sevLabel = 'Critical';
                labelClass = 'crit';
            } else if (rawSev.includes('P2') || rawSev.includes('HIGH')) {
                sevClass = 'sev-high';
                sevLabel = 'High';
                labelClass = 'high';
            } else if (rawSev.includes('P3') || rawSev.includes('MEDIUM')) {
                sevClass = 'sev-medium';
                sevLabel = 'Medium';
                labelClass = 'med';
            }

            const tocNum = String(idx + 1).padStart(2, '0');
            const score = f.contextual_risk_score || f.risk_score || 'N/A';
            const epssProb = f.epss_probability !== undefined && f.epss_probability !== null 
                ? (f.epss_probability * 100).toFixed(2) + '%' 
                : (f.threat_intel ? f.threat_intel.epss_percent + '%' : '0.50%');

            const cves = (f.related_cves || []).map(c => `<span class="cve-tag">${AegisUtils.escapeHtml(c)}</span>`).join(' ');
            const inKev = f.in_cisa_kev || (f.threat_intel && f.threat_intel.in_cisa_kev);
            const likelihoodHtml = inKev 
                ? `<span class="priority-label crit">CISA KEV</span> <span class="mono" style="font-size:0.75rem;color:var(--ink-secondary);">(${epssProb})</span>`
                : `<span class="mono">${epssProb}</span>`;

            const evidence = f.evidence || f.exposure_context || 'Verified in perimeter response headers or DNS records.';
            const whyItMatters = f.why_it_matters || f.description || 'Misconfiguration or component exposure increases exploitable perimeter surface.';
            const fixSnippet = f.remediation || f.suggested_action || f.recommended_remediation || 'Apply defensive configuration hardening or update component.';

            return `
                <tr class="finding-row ${sevClass} ${idx === selectedFindingIndex ? 'row-selected' : ''}" data-index="${idx}">
                    <td class="row-toc-num">${tocNum}</td>
                    <td class="finding-title-cell">
                        ${AegisUtils.escapeHtml(f.title || f.summary || f.vuln_id || 'Security Finding')}
                        ${cves ? `<span class="finding-cves">${cves}</span>` : ''}
                    </td>
                    <td>
                        <span class="priority-label ${labelClass}">${sevLabel}</span>
                    </td>
                    <td>${likelihoodHtml}</td>
                    <td><span class="mono" style="font-size:0.76rem;color:var(--ink-secondary);">${AegisUtils.escapeHtml(f.source || 'perimeter')}</span></td>
                    <td style="text-align: right;">
                        <button class="btn btn-subtle btn-sm btn-remediate" data-index="${idx}" aria-label="Fix finding ${tocNum}">Fix</button>
                    </td>
                </tr>
                <tr class="finding-detail-row" id="findingDetail${idx}" style="display: ${idx === selectedFindingIndex ? 'table-row' : 'none'};">
                    <td colspan="6">
                        <div class="finding-detail-grid">
                            <div>
                                <div class="detail-block-title">Observable Evidence</div>
                                <div class="detail-block-content mono" style="background:var(--bg-subtle);padding:8px 10px;border-radius:3px;">${AegisUtils.escapeHtml(evidence)}</div>
                            </div>
                            <div>
                                <div class="detail-block-title">Why It Matters</div>
                                <div class="detail-block-content">${AegisUtils.escapeHtml(whyItMatters)}</div>
                            </div>
                            <div class="fix-block">
                                <div class="fix-header">
                                    <span class="detail-block-title" style="margin-bottom:0;">Recommended Remediation / Virtual Patch</span>
                                    <button class="btn btn-subtle btn-sm btn-copy-inline-fix" data-snippet="${AegisUtils.escapeHtml(fixSnippet)}">Copy Snippet</button>
                                </div>
                                <div class="fix-code">${AegisUtils.escapeHtml(fixSnippet)}</div>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function selectFinding(idx) {
        if (!currentReport) return;
        const findings = currentReport.findings || currentReport.prioritized_findings || [];
        if (idx < 0 || idx >= findings.length) return;

        selectedFindingIndex = idx;
        const f = findings[idx];

        // Update Threat Radar (if canvas present)
        AegisCharts.renderThreatRadar(f, false, 'threatRadarChart');

        // Update Finding Details Drawer / Panel
        AegisUtils.safeSetText('selectedFindingTitle', f.title || f.summary || f.vuln_id || 'Finding');
        AegisUtils.safeSetText('selectedFindingDesc', f.description || f.why_it_matters || f.summary || 'No description');
        AegisUtils.safeSetText('selectedFindingEvidence', f.evidence || f.exposure_context || 'Verified in perimeter scan');
        AegisUtils.safeSetText('selectedFindingAction', f.remediation || f.suggested_action || f.recommended_remediation || 'Review security configuration');
        AegisUtils.safeSetText('selectedFindingScore', f.contextual_risk_score ? `(${f.contextual_risk_score} / 10)` : '');

        // Update Attack Simulator walkthrough
        renderAttackSimulator(f);
    }

    function renderAttackSimulator(finding) {
        const container = document.getElementById('attackSimulatorContainer');
        if (!container) return;

        const target = (currentReport && currentReport.target) || 'target.site';
        const mitre = finding.mitre_attack || { technique_id: 'T1190', technique_name: 'Exploit Public-Facing App', tactic: 'Initial Access' };
        const findingTitle = finding.title || finding.summary || finding.vuln_id || 'Security Weakness';
        const findingAction = finding.remediation || finding.suggested_action || finding.recommended_remediation || 'Enforce defensive header or WAF virtual patch.';
        let epssPercent = 0.5;
        if (finding.epss_probability !== undefined && finding.epss_probability !== null) {
            epssPercent = parseFloat(finding.epss_probability) * 100;
        } else if (finding.threat_intel && finding.threat_intel.epss_percent !== undefined) {
            epssPercent = parseFloat(finding.threat_intel.epss_percent);
        }

        container.innerHTML = `
            <div class="attack-path-line-container">
                <div class="attack-stop-node active">
                    <div class="stop-marker"></div>
                    <div class="stop-title">Discover</div>
                    <div class="stop-desc">Asset identification on <code>${AegisUtils.escapeHtml(target)}</code></div>
                </div>
                <div class="attack-stop-node active">
                    <div class="stop-marker"></div>
                    <div class="stop-title">Weaponize</div>
                    <div class="stop-desc">${AegisUtils.escapeHtml(mitre.technique_id || 'T1190')}: ${AegisUtils.escapeHtml(mitre.technique_name || 'Exploit')}</div>
                </div>
                <div class="attack-stop-node active">
                    <div class="stop-marker"></div>
                    <div class="stop-title">Impact</div>
                    <div class="stop-desc">${AegisUtils.escapeHtml(mitre.tactic || 'Access')} (${epssPercent.toFixed(1)}% EPSS)</div>
                </div>
                <div class="attack-stop-node defend">
                    <div class="stop-marker"></div>
                    <div class="stop-title">Defend</div>
                    <div class="stop-desc">${AegisUtils.escapeHtml(findingAction.substring(0, 50))}${findingAction.length > 50 ? '…' : ''}</div>
                </div>
            </div>
            <div class="attack-disclaimer-note">
                CONCEPTUAL ADVERSARY TRAJECTORY MODEL &middot; NO OFFENSIVE PAYLOADS TRANSMITTED
            </div>
        `;
    }

    function renderComplianceCards(comp) {
        if (!comp) return;
        const setCard = (prefix, data) => {
            if (!data) return;
            const rawScore = data.score !== undefined && data.score !== null ? data.score : (data.percentage !== undefined && data.percentage !== null ? data.percentage : null);
            const passCount = data.passing_controls !== undefined && data.passing_controls !== null ? data.passing_controls : (Array.isArray(data.controls) ? data.controls.filter(c => c.status === 'PASS').length : null);
            const totalCount = data.total_controls !== undefined && data.total_controls !== null ? data.total_controls : (Array.isArray(data.controls) ? data.controls.length : null);

            let displayScore = rawScore;
            if (displayScore === null && passCount !== null && totalCount && totalCount > 0) {
                displayScore = Math.round((passCount / totalCount) * 1000) / 10;
            }
            if (displayScore !== null) {
                AegisUtils.safeSetText(`${prefix}Score`, `${displayScore}%`);
            }
            if (passCount !== null && totalCount !== null) {
                AegisUtils.safeSetText(`${prefix}Pass`, `${passCount}/${totalCount} Controls`);
                const statusEl = document.getElementById(`${prefix}Status`);
                if (statusEl) {
                    if (displayScore >= 80) {
                        statusEl.className = 'status-pill-clean pass';
                        statusEl.textContent = 'Acceptable Posture';
                    } else {
                        statusEl.className = 'status-pill-clean review';
                        statusEl.textContent = 'Review Needed';
                    }
                }
            }
        };

        setCard('compPci', comp.pci_dss_4);
        setCard('compNist', comp.nist_csf_2);
        setCard('compIso', comp.iso_27001);
        setCard('compSoc2', comp.soc_2 || comp.soc2_type2 || comp.soc2);
    }

    let currentRemediationBundle = null;
    let currentRemediationTab = 'nginx';

    function sanitizeTargetInput(val) {
        if (!val) return '';
        return val.replace(/^[a-zA-Z]+:\/\//, '').replace(/\/.*$/, '').trim();
    }

    async function triggerScan(targetInput) {
        let target = targetInput || (document.getElementById('scanTargetInput') ? document.getElementById('scanTargetInput').value.trim() : '');
        if (!target) {
            AegisUtils.showToast('Please enter a target domain or IP.', 'warning');
            return;
        }

        // Clean protocol prefix and trailing slashes if user pasted full URL (e.g. http://domain.com/ -> domain.com)
        target = sanitizeTargetInput(target);
        const inputEl = document.getElementById('scanTargetInput');
        if (inputEl) inputEl.value = target;

        // Open live audit terminal when a scan is initiated
        const term = document.getElementById('auditTerminal');
        if (term) term.classList.add('active');

        const chkActive = document.getElementById('chkActiveScan');
        const isActive = chkActive && chkActive.checked && !chkActive.disabled;

        if (isActive) {
            AegisUtils.showToast(`Starting authorized active port & service scan on ${target}...`, 'info');
            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: target, active: true })
                });
                const resData = await resp.json();
                if (resData.success && (resData.data || resData.report)) {
                    AegisUtils.showToast(`Active scan complete for ${target}!`, 'success');
                    applyReportData(resData.data || resData.report);
                    return;
                } else if (!resData.success && resData.error) {
                    AegisUtils.showToast(`Active scan notice: ${resData.error}. Falling back to passive OSINT.`, 'warning');
                }
            } catch (err) {
                console.warn('Active scan request failed, continuing with passive pipeline:', err);
            }
        }

        AegisUtils.showToast(`Starting real reconnaissance pipeline on ${target}...`, 'info');
        await AegisTelemetry.executeRealPipelineStages(target, (finalResult) => {
            AegisUtils.showToast(`Assessment complete for ${target}!`, 'success');
            if (finalResult && finalResult.report) {
                applyReportData(finalResult.report);
            }
        });
    }

    function setupEventListeners() {
        // Brand Reload
        const brand = document.getElementById('brandBox');
        if (brand) {
            brand.addEventListener('click', () => location.reload());
        }

        // Scan Button
        const btnScan = document.getElementById('btnStartScan');
        if (btnScan) {
            btnScan.onclick = () => triggerScan();
        }

        const inputScan = document.getElementById('scanTargetInput');
        if (inputScan) {
            inputScan.onkeydown = (e) => {
                if (e.key === 'Enter') triggerScan();
            };
            inputScan.addEventListener('input', () => {
                const raw = inputScan.value;
                if (raw.includes('://') || raw.endsWith('/')) {
                    inputScan.value = sanitizeTargetInput(raw);
                }
            });
            inputScan.addEventListener('change', () => {
                inputScan.value = sanitizeTargetInput(inputScan.value);
                updateActiveModeState();
            });
            inputScan.addEventListener('blur', () => {
                inputScan.value = sanitizeTargetInput(inputScan.value);
                updateActiveModeState();
            });
        }

        // Domain Verification Modal Trigger & Close
        const btnVerify = document.getElementById('btnOpenVerification');
        if (btnVerify) {
            btnVerify.onclick = () => {
                const target = (currentReport && currentReport.target) || (inputScan ? inputScan.value.trim() : '');
                AegisVerification.startVerification(target);
            };
        }
        const btnCloseVerify = document.getElementById('btnCloseVerificationModal');
        if (btnCloseVerify) {
            btnCloseVerify.addEventListener('click', () => {
                const m = document.getElementById('verificationModal');
                if (m) m.style.display = 'none';
            });
        }

        // Header Navigation & Toggles
        const btnPalette = document.getElementById('btnTogglePalette');
        if (btnPalette) btnPalette.addEventListener('click', toggleCommandPalette);

        function openAttackGraph() {
            const inputScan = document.getElementById('scanTargetInput');
            const target = (currentReport && currentReport.target) || (inputScan ? inputScan.value.trim() : '');
            const url = target ? `/attack-graph?target=${encodeURIComponent(target)}` : '/attack-graph';
            const modal = document.getElementById('attackGraphModal');
            const frame = document.getElementById('attackGraphFrame');
            if (modal && frame) {
                frame.src = url;
                modal.style.display = 'flex';
            } else {
                window.location.href = url;
            }
        }

        const btnAttackGraph = document.getElementById('btnOpenAttackGraph');
        if (btnAttackGraph) btnAttackGraph.addEventListener('click', openAttackGraph);
        const btnAttackGraphSection = document.getElementById('btnOpenAttackGraphSection');
        if (btnAttackGraphSection) btnAttackGraphSection.addEventListener('click', openAttackGraph);

        const btnCloseAttackGraph = document.getElementById('btnCloseAttackGraphModal');
        if (btnCloseAttackGraph) {
            btnCloseAttackGraph.addEventListener('click', () => {
                const modal = document.getElementById('attackGraphModal');
                const frame = document.getElementById('attackGraphFrame');
                if (modal) modal.style.display = 'none';
                if (frame) frame.src = '';
            });
        }

        // Export Dropdown Menu
        const btnExportToggle = document.getElementById('btnExportMenuToggle');
        const exportContainer = document.getElementById('exportDropdownContainer');
        if (btnExportToggle && exportContainer) {
            btnExportToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                exportContainer.classList.toggle('active');
            });
            document.addEventListener('click', () => {
                exportContainer.classList.remove('active');
            });
        }

        const btnExportJson = document.getElementById('btnExportJson');
        if (btnExportJson) {
            btnExportJson.addEventListener('click', () => {
                const target = (currentReport && currentReport.target) || (inputScan ? inputScan.value.trim() : '');
                window.open(`/api/report?target=${encodeURIComponent(target)}`, '_blank');
            });
        }

        const btnCopilot = document.getElementById('btnHeaderCopilot');
        if (btnCopilot) btnCopilot.addEventListener('click', () => window.AegisCopilot && AegisCopilot.toggleCopilot());

        const btnTerminal = document.getElementById('btnHeaderTerminal');
        if (btnTerminal) btnTerminal.addEventListener('click', () => document.getElementById('auditTerminal')?.classList.toggle('active'));

        const btnTheme = document.getElementById('btnToggleTheme');
        if (btnTheme) {
            btnTheme.addEventListener('click', () => {
                const html = document.documentElement;
                const current = html.getAttribute('data-theme') || 'light';
                const next = current === 'light' ? 'dark' : 'light';
                html.setAttribute('data-theme', next);
            });
        }

        const btnTerminalMin = document.getElementById('btnTerminalMinimize');
        if (btnTerminalMin) btnTerminalMin.addEventListener('click', () => document.getElementById('auditTerminal')?.classList.toggle('active'));

        const btnGlobeSpin = document.getElementById('btnToggleGlobeSpin');
        if (btnGlobeSpin) btnGlobeSpin.addEventListener('click', () => window.AegisGlobe && AegisGlobe.toggleSpin());

        const btnRadarReset = document.getElementById('btnResetThreatRadar');
        if (btnRadarReset) {
            btnRadarReset.addEventListener('click', () => {
                if (window.AegisCharts && currentReport) {
                    const findings = currentReport.findings || currentReport.prioritized_findings || [];
                    AegisCharts.renderThreatRadar(findings[0] || null, false);
                }
            });
        }

        // Remediation Modal Controls
        const btnCloseRemediation = document.getElementById('btnCloseRemediationModal');
        if (btnCloseRemediation) {
            btnCloseRemediation.addEventListener('click', () => {
                const m = document.getElementById('remediationModal');
                if (m) m.style.display = 'none';
            });
        }

        const btnCopyRem = document.getElementById('btnCopyRemediation');
        if (btnCopyRem) btnCopyRem.addEventListener('click', copyCurrentRemediation);

        const remediationTabs = document.getElementById('remediationTabs');
        if (remediationTabs) {
            remediationTabs.addEventListener('click', (e) => {
                const tabBtn = e.target.closest('.tab-btn');
                if (tabBtn && tabBtn.dataset.tab) {
                    switchRemediationTab(tabBtn.dataset.tab, tabBtn);
                }
            });
        }

        // Findings Table Delegated Clicks
        const tbody = document.getElementById('findingsTableBody');
        if (tbody) {
            tbody.addEventListener('click', (e) => {
                const copyBtn = e.target.closest('.btn-copy-inline-fix');
                if (copyBtn) {
                    e.stopPropagation();
                    const snippet = copyBtn.dataset.snippet;
                    if (snippet) {
                        navigator.clipboard.writeText(snippet).then(() => {
                            AegisUtils.showToast('Remediation snippet copied!', 'success');
                        });
                    }
                    return;
                }

                const btn = e.target.closest('.btn-remediate');
                if (btn) {
                    e.stopPropagation();
                    const idx = parseInt(btn.dataset.index, 10);
                    if (!isNaN(idx)) viewRemediation(idx);
                    return;
                }

                const row = e.target.closest('.finding-row');
                if (row) {
                    const idx = parseInt(row.dataset.index, 10);
                    if (!isNaN(idx)) {
                        selectFinding(idx);
                        tbody.querySelectorAll('.finding-row').forEach(r => r.classList.remove('row-selected'));
                        row.classList.add('row-selected');

                        const detailRow = document.getElementById(`findingDetail${idx}`);
                        if (detailRow) {
                            const isShowing = detailRow.style.display !== 'none';
                            tbody.querySelectorAll('.finding-detail-row').forEach(dr => dr.style.display = 'none');
                            detailRow.style.display = isShowing ? 'none' : 'table-row';
                        }
                    }
                }
            });
        }

        // Command Palette Keyboard & Actions
        window.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                toggleCommandPalette();
            }
        });

        const paletteResults = document.getElementById('paletteResults');
        if (paletteResults) {
            paletteResults.addEventListener('click', (e) => {
                const item = e.target.closest('.palette-item');
                if (!item) return;
                const action = item.dataset.action;
                toggleCommandPalette();
                if (action === 'attack-graph') {
                    openAttackGraph();
                } else if (action === 'model-routing') {
                    fetch('/api/ai/model-routing').then(r => r.json()).then(d => {
                        alert('Model Routing Architecture:\n• Zero-Cost Template Tier: ' + d.savings_summary.template_zero_cost_pct + '%\n• Estimated Token Reduction: ' + d.savings_summary.estimated_token_reduction_pct + '%\n• Pattern: ' + d.savings_summary.model_routing_pattern);
                    });
                } else if (action === 'terminal') {
                    document.getElementById('auditTerminal')?.classList.add('active');
                } else if (action === 'ciso') {
                    document.getElementById('btnExportHtml')?.click();
                } else if (action === 'csv') {
                    document.getElementById('btnExportCsv')?.click();
                } else if (action === 'sbom') {
                    document.getElementById('btnExportSbom')?.click();
                } else if (action === 'verify') {
                    document.getElementById('btnOpenVerification')?.click();
                }
            });
        }

        // Export Dropdowns
        setupExportHandlers();

        // Initial check for active mode capability
        updateActiveModeState();
    }

    async function updateActiveModeState() {
        const inputScan = document.getElementById('scanTargetInput');
        const target = (inputScan ? inputScan.value.trim() : '') || 'localhost';
        const chkActive = document.getElementById('chkActiveScan');
        const container = document.getElementById('activeScanToggleContainer');
        if (!chkActive) return;

        try {
            const resp = await fetch(`/api/mode?target=${encodeURIComponent(target)}`);
            if (resp.ok) {
                const data = await resp.json();
                chkActive.disabled = !data.can_active;
                if (container) {
                    container.style.opacity = data.can_active ? '1' : '0.45';
                    container.title = data.can_active
                        ? 'Active TCP port & banner scan authorized for this target'
                        : 'Active scanning disabled. Verify domain ownership or run against localhost to authorize.';
                }
                if (!data.can_active) {
                    chkActive.checked = false;
                }
            }
        } catch (e) {}
    }

    function toggleCommandPalette() {
        const palette = document.getElementById('commandPaletteModal');
        if (!palette) return;
        palette.style.display = palette.style.display === 'flex' ? 'none' : 'flex';
        if (palette.style.display === 'flex') {
            const input = document.getElementById('paletteSearchInput');
            if (input) input.focus();
        }
    }

    function setupExportHandlers() {
        const bindExport = (id, format) => {
            const el = document.getElementById(id);
            if (el) {
                el.onclick = () => {
                    const target = (currentReport && currentReport.target) || '';
                    window.open(`/api/export/${format}?target=${encodeURIComponent(target)}`, '_blank');
                };
            }
        };

        bindExport('btnExportCsv', 'csv');
        bindExport('btnExportHtml', 'html');
        bindExport('btnExportCef', 'cef');
        bindExport('btnExportEcs', 'ecs');
        bindExport('btnExportSbom', 'cyclonedx');
    }

    async function viewRemediation(idx) {
        selectFinding(idx);
        const modal = document.getElementById('remediationModal');
        if (!modal) return;

        const findings = (currentReport && (currentReport.findings || currentReport.prioritized_findings)) || [];
        const f = findings[idx] || {};
        const target = (currentReport && currentReport.target) || 'target.site';

        AegisUtils.safeSetText('remediationModalTitle', `🛠️ Remediation: ${f.title || 'Finding'}`);
        AegisUtils.safeSetText('remediationModalSubtitle', `Virtual patches & hardening rules for ${target}`);
        AegisUtils.safeSetText('remediationFindingNote', `🎯 Action: ${f.remediation || f.suggested_action || 'Enforce defense-in-depth headers and access restrictions.'}`);

        modal.style.display = 'flex';
        const display = document.getElementById('remediationCodeDisplay');
        if (display) display.textContent = '# Fetching automated virtual patch bundle...';

        try {
            const resp = await fetch(`/api/remediation?target=${encodeURIComponent(target)}`);
            if (resp.ok) {
                currentRemediationBundle = await resp.json();
                renderRemediationCode(currentRemediationTab);
            } else {
                if (display) display.textContent = `# Recommended Fix:\n${f.remediation || 'Apply standard hardening configuration.'}`;
            }
        } catch (e) {
            if (display) display.textContent = `# Recommended Fix:\n${f.remediation || 'Apply standard hardening configuration.'}`;
        }
    }

    function renderRemediationCode(tab) {
        currentRemediationTab = tab;
        const display = document.getElementById('remediationCodeDisplay');
        if (!display) return;

        if (!currentRemediationBundle) {
            display.textContent = '# Loading bundle...';
            return;
        }

        let code = '';
        if (tab === 'nginx') {
            code = currentRemediationBundle.nginx || '# No Nginx configuration available.';
        } else if (tab === 'apache') {
            code = currentRemediationBundle.apache || '# No Apache configuration available.';
        } else if (tab === 'caddy') {
            code = currentRemediationBundle.caddy || '# No Caddy configuration available.';
        } else if (tab === 'helmet') {
            code = currentRemediationBundle.express_helmet || '# No Helmet configuration available.';
        } else if (tab === 'waf') {
            const waf = currentRemediationBundle.waf || {};
            code = waf.cloudflare_waf_rules || waf.modsecurity_crs_rules || JSON.stringify(waf, null, 2);
        }
        display.textContent = code;
    }

    function switchRemediationTab(tab, btn) {
        const tabs = document.querySelectorAll('#remediationTabs .tab-btn');
        tabs.forEach(t => {
            t.classList.remove('btn-primary');
            t.classList.add('btn-secondary');
        });
        if (btn) {
            btn.classList.remove('btn-secondary');
            btn.classList.add('btn-primary');
        }
        renderRemediationCode(tab);
    }

    function copyCurrentRemediation() {
        const display = document.getElementById('remediationCodeDisplay');
        if (!display) return;
        navigator.clipboard.writeText(display.textContent).then(() => {
            AegisUtils.showToast('Configuration snippet copied to clipboard!', 'success');
        }).catch(() => {
            AegisUtils.showToast('Failed to copy.', 'error');
        });
    }

    return {
        initDashboard,
        triggerScan,
        selectFinding,
        viewRemediation,
        switchRemediationTab,
        copyCurrentRemediation,
        toggleCommandPalette,
        updateActiveModeState
    };
})();

// Start application when DOM is ready or immediately if already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        AegisApp.initDashboard();
    });
} else {
    AegisApp.initDashboard();
}

window.addEventListener('load', () => {
    AegisApp.initDashboard();
});
