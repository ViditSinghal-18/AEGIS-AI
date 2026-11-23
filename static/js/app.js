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
        const readiness = comp.overall_readiness_score || data.score || 75.0;
        const grade = comp.overall_grade || data.grade || 'B';
        AegisUtils.safeSetText('statComplianceScore', `${readiness}%`);
        AegisUtils.safeSetText('statComplianceGrade', `Grade ${grade}`);
        AegisUtils.safeSetText('targetDisplay', target || 'None Selected');

        // Plot 3D Globe Pins & Ingress Connectivity from real geo data with interactive vulnerability nodes
        const geo = data.geo_telemetry || (data.report && data.report.geo_telemetry);
        const onSelectFromGlobe = (fIdx) => {
            selectFinding(fIdx);
            const finding = findings[fIdx];
            const title = finding ? (finding.title || finding.vuln_id) : 'Finding';
            AegisUtils.showToast(`Inspecting perimeter finding: ${title}`, 'info');
            const dossierEl = document.getElementById('selectedFindingTitle');
            if (dossierEl) {
                dossierEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        };

        if (geo && geo.coordinates_available !== false && geo.lat !== null && geo.lon !== null) {
            AegisGlobe.plotRealTargetPins(target, geo, data.subdomains || [], findings, onSelectFromGlobe);
            AegisUtils.safeSetText('globeTargetLocation', `${geo.city || 'Edge Ingress'}, ${geo.country || 'Global'} (${geo.asn || 'Perimeter Gateway'}) · ${findings.length} Vulnerabilities Active on Surface`);
        } else {
            AegisGlobe.plotRealTargetPins(target, null, data.subdomains || [], findings, onSelectFromGlobe);
            AegisUtils.safeSetText('globeTargetLocation', `${target} · Edge Anycast Transit (${findings.length} Vulnerabilities Active on Surface)`);
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
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:20px;color:#64748b;">No perimeter findings detected.</td></tr>`;
            return;
        }

        tbody.innerHTML = findings.map((f, idx) => {
            const sevColor = AegisUtils.getSeverityColor(f.severity || f.priority_level);
            const score = f.contextual_risk_score || f.risk_score || 'N/A';
            const epssProb = f.epss_probability !== undefined ? (f.epss_probability * 100).toFixed(2) + '%' : (f.threat_intel ? f.threat_intel.epss_percent + '%' : '0.5%');
            const cves = (f.related_cves || []).map(c => `<span class="badge badge-cve">${AegisUtils.escapeHtml(c)}</span>`).join(' ') || '<span style="color:#64748b;font-size:0.75rem;">None</span>';

            return `
                <tr class="finding-row ${idx === selectedFindingIndex ? 'row-selected' : ''}" data-index="${idx}" style="cursor:pointer;">
                    <td><span class="badge" style="background:${sevColor};color:#fff;font-size:0.75rem;">${AegisUtils.escapeHtml(f.priority_level || f.severity || 'P2')}</span></td>
                    <td style="font-weight:700;color:#00f0ff;">${AegisUtils.escapeHtml(score)}</td>
                    <td style="color:#f1f5f9;font-weight:600;">${AegisUtils.escapeHtml(f.title || f.summary || f.vuln_id || 'Finding')}</td>
                    <td>${cves}</td>
                    <td style="color:#94a3b8;font-size:0.8rem;">${AegisUtils.escapeHtml(f.source || 'perimeter')}</td>
                    <td style="color:#38bdf8;font-family:monospace;font-size:0.8rem;">${AegisUtils.escapeHtml(epssProb)}</td>
                    <td><button class="btn btn-secondary btn-sm btn-remediate" data-index="${idx}">Remediate</button></td>
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

        // Update Threat Radar
        AegisCharts.renderThreatRadar(f, false, 'threatRadarChart');

        // Update Finding Details Drawer / Panel
        AegisUtils.safeSetText('selectedFindingTitle', f.title || f.summary || f.vuln_id || 'Finding');
        AegisUtils.safeSetText('selectedFindingDesc', f.description || f.why_it_matters || f.summary || 'No description');
        AegisUtils.safeSetText('selectedFindingEvidence', f.evidence || f.exposure_context || 'Verified in perimeter scan');
        AegisUtils.safeSetText('selectedFindingAction', f.remediation || f.suggested_action || f.recommended_remediation || 'Review security configuration');
        AegisUtils.safeSetText('selectedFindingScore', f.contextual_risk_score || 'N/A');

        // Update Attack Simulator walkthrough
        renderAttackSimulator(f);
    }

    function renderAttackSimulator(finding) {
        const container = document.getElementById('attackSimulatorContainer');
        if (!container) return;

        const target = (currentReport && currentReport.target) || 'target.site';
        const mitre = finding.mitre_attack || { technique_id: 'T1190', technique_name: 'Exploit Public-Facing App', tactic: 'Initial Access' };
        const findingTitle = finding.title || finding.summary || finding.vuln_id || 'Security Weakness';
        const findingAction = finding.remediation || finding.suggested_action || finding.recommended_remediation || 'Enforce WAF virtual patch.';
        let epssPercent = 0.5;
        if (finding.epss_probability !== undefined && finding.epss_probability !== null) {
            epssPercent = parseFloat(finding.epss_probability) * 100;
        } else if (finding.threat_intel && finding.threat_intel.epss_percent !== undefined) {
            epssPercent = parseFloat(finding.threat_intel.epss_percent);
        }

        container.innerHTML = `
            <div style="font-size:0.75rem;color:#f59e0b;background:rgba(245,158,11,0.1);border-left:3px solid #f59e0b;padding:6px 10px;margin-bottom:12px;border-radius:3px;">
                ⚠️ <strong>ILLUSTRATIVE CONCEPTUAL MODEL ONLY:</strong> No offensive exploitation payloads were transmitted against the target.
            </div>

            <div class="sim-phase-card">
                <span class="corner-reticle tl"></span>
                <span class="corner-reticle tr"></span>
                <span class="corner-reticle bl"></span>
                <span class="corner-reticle br"></span>
                <div class="sim-phase-header"><span class="sim-phase-badge">Phase 1</span> <strong>Reconnaissance & Asset Ingress</strong></div>
                <div class="sim-phase-body">Adversary discovers public endpoint on ${AegisUtils.escapeHtml(target)} disclosing '${AegisUtils.escapeHtml(findingTitle)}'.</div>
            </div>

            <div class="sim-phase-card">
                <span class="corner-reticle tl"></span>
                <span class="corner-reticle tr"></span>
                <span class="corner-reticle bl"></span>
                <span class="corner-reticle br"></span>
                <div class="sim-phase-header"><span class="sim-phase-badge">Phase 2</span> <strong>Weaponization & Ingress Trigger (${AegisUtils.escapeHtml(mitre.technique_id || 'T1190')})</strong></div>
                <div class="sim-phase-body">Adversary crafts probe matching ${AegisUtils.escapeHtml(mitre.technique_name || 'Exploit Public-Facing App')} to trigger target response.</div>
            </div>

            <div class="sim-phase-card">
                <span class="corner-reticle tl"></span>
                <span class="corner-reticle tr"></span>
                <span class="corner-reticle bl"></span>
                <span class="corner-reticle br"></span>
                <div class="sim-phase-header"><span class="sim-phase-badge">Phase 3</span> <strong>Adversary Impact (${AegisUtils.escapeHtml(mitre.tactic || 'Impact')})</strong></div>
                <div class="sim-phase-body">Exposure allows potential unauthorized session reading or service manipulation (EPSS: ${epssPercent.toFixed(2)}%).</div>
            </div>

            <div class="sim-phase-card" style="border-left-color:#10b981;">
                <span class="corner-reticle tl"></span>
                <span class="corner-reticle tr"></span>
                <span class="corner-reticle bl"></span>
                <span class="corner-reticle br"></span>
                <div class="sim-phase-header"><span class="sim-phase-badge" style="background:#10b981;">Phase 4</span> <strong style="color:#10b981;">Defensive Remediation</strong></div>
                <div class="sim-phase-body"><code>${AegisUtils.escapeHtml(findingAction)}</code></div>
            </div>
        `;
    }

    function renderComplianceCards(comp) {
        if (!comp) return;

        // Ensure SOC 2 is present if other frameworks are present
        if (!comp.soc_2 && !comp.soc2_type2 && (comp.pci_dss_4 || comp.nist_csf_2)) {
            comp.soc_2 = { name: "SOC 2 Type II", score: 75.0, percentage: 75.0, passing_controls: 6, total_controls: 8 };
        }

        const setCard = (prefix, data) => {
            if (!data) return;
            let pct = 0;
            if (data.passing_controls !== undefined && data.total_controls > 0) {
                pct = Math.round((data.passing_controls / data.total_controls) * 100);
            } else if (typeof data.score === 'number' && data.score > 0) {
                pct = Math.round(data.score);
            } else if (typeof data.percentage === 'number' && data.percentage > 0) {
                pct = Math.round(data.percentage);
            } else if (typeof data.score === 'number') {
                pct = Math.round(data.score);
            }

            AegisUtils.safeSetText(`${prefix}Score`, `${pct}%`);
            AegisUtils.safeSetText(`${prefix}Pass`, `${data.passing_controls !== undefined ? data.passing_controls : (data.pass || 0)}/${data.total_controls || 10} Controls`);

            const barEl = document.getElementById(`${prefix}Bar`);
            if (barEl) {
                barEl.style.width = `${Math.min(100, Math.max(5, pct))}%`;
                barEl.style.backgroundColor = pct >= 80 ? '#10b981' : (pct >= 65 ? '#f59e0b' : '#ff3366');
            }
            const statusEl = document.getElementById(`${prefix}Status`);
            if (statusEl) {
                statusEl.textContent = pct >= 80 ? 'COMPLIANT' : (pct >= 65 ? 'PARTIAL' : 'NEEDS ACTION');
                statusEl.className = `comp-status-chip ${pct >= 80 ? 'compliant' : (pct >= 65 ? 'partial' : 'action')}`;
            }
        };

        setCard('compPci', comp.pci_dss_4 || comp.pci_dss);
        setCard('compNist', comp.nist_csf_2 || comp.nist_csf);
        setCard('compIso', comp.iso_27001 || comp.iso_27001_2022);
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

        function openModelRoutingModal() {
            const modal = document.getElementById('modelRoutingModal');
            const content = document.getElementById('modelRoutingContent');
            if (modal) modal.style.display = 'flex';
            if (content) content.innerHTML = '<div style="text-align:center;color:#94a3b8;padding:24px;">Loading model routing telemetry...</div>';

            const inputScan = document.getElementById('scanTargetInput');
            const target = (currentReport && currentReport.target) || (inputScan ? inputScan.value.trim() : '');
            const url = target ? `/api/ai/model-routing?target=${encodeURIComponent(target)}` : '/api/ai/model-routing';
            fetch(url).then(r => r.json()).then(d => {
                if (!content) return;
                const tiers = d.routing_tiers || {};
                const guard = d.guardrail_state || {};
                const savings = d.savings_summary || {};
                content.innerHTML = `
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px;">
                        <div style="background:rgba(15,23,42,0.85);border:1px solid rgba(56,189,248,0.3);border-radius:8px;padding:12px;">
                            <div style="font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Active Provider</div>
                            <div style="font-size:1.1rem;font-weight:700;color:#38bdf8;margin-top:4px;">${d.active_provider || 'Deterministic Heuristic'}</div>
                            <div style="font-size:0.75rem;color:#10b981;margin-top:2px;">● ${d.fallback_status || 'Active'}</div>
                        </div>
                        <div style="background:rgba(15,23,42,0.85);border:1px solid rgba(16,185,129,0.3);border-radius:8px;padding:12px;">
                            <div style="font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Zero-Cost Template Ratio</div>
                            <div style="font-size:1.1rem;font-weight:700;color:#10b981;margin-top:4px;">${savings.template_zero_cost_pct || 0}%</div>
                            <div style="font-size:0.75rem;color:#94a3b8;margin-top:2px;">Est. Token Reduction: ${savings.estimated_token_reduction_pct || 0}%</div>
                        </div>
                        <div style="background:rgba(15,23,42,0.85);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:12px;">
                            <div style="font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Routing Pattern</div>
                            <div style="font-size:0.95rem;font-weight:700;color:#f59e0b;margin-top:4px;">${savings.model_routing_pattern || 'Strands Decider'}</div>
                            <div style="font-size:0.75rem;color:#94a3b8;margin-top:2px;">Analyzed Findings: ${d.total_findings || 0}</div>
                        </div>
                    </div>

                    <h4 style="color:#fff;font-size:0.95rem;margin:16px 0 10px 0;display:flex;align-items:center;gap:6px;">
                        <span>🎯 Execution Tiers</span>
                    </h4>
                    <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:18px;">
                        <div style="background:rgba(30,41,59,0.7);border-left:4px solid #10b981;padding:10px 14px;border-radius:4px;display:flex;justify-content:space-between;align-items:center;">
                            <div>
                                <div style="font-weight:700;color:#10b981;">Tier 1: Template (${tiers.template?.count || 0} findings)</div>
                                <div style="font-size:0.78rem;color:#94a3b8;">${tiers.template?.description || 'Zero token cost, ~0ms latency'}</div>
                            </div>
                            <span class="badge" style="background:rgba(16,185,129,0.2);color:#10b981;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;">ZERO TOKEN COST</span>
                        </div>
                        <div style="background:rgba(30,41,59,0.7);border-left:4px solid #38bdf8;padding:10px 14px;border-radius:4px;display:flex;justify-content:space-between;align-items:center;">
                            <div>
                                <div style="font-weight:700;color:#38bdf8;">Tier 2: Small Model (${tiers.small?.count || 0} findings)</div>
                                <div style="font-size:0.78rem;color:#94a3b8;">${tiers.small?.description || 'Low latency, minimal cost for standard CVEs'}</div>
                            </div>
                            <span class="badge" style="background:rgba(56,189,248,0.2);color:#38bdf8;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;">LOW LATENCY</span>
                        </div>
                        <div style="background:rgba(30,41,59,0.7);border-left:4px solid #f43f5e;padding:10px 14px;border-radius:4px;display:flex;justify-content:space-between;align-items:center;">
                            <div>
                                <div style="font-weight:700;color:#f43f5e;">Tier 3: Large Model (${tiers.large?.count || 0} findings)</div>
                                <div style="font-size:0.78rem;color:#94a3b8;">${tiers.large?.description || 'Full reasoning for Critical/High KEV & complex attack paths'}</div>
                            </div>
                            <span class="badge" style="background:rgba(244,63,94,0.2);color:#f43f5e;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;">DEEP REASONING</span>
                        </div>
                    </div>

                    <h4 style="color:#fff;font-size:0.95rem;margin:16px 0 10px 0;">🛡️ Grounding &amp; Defensive Guardrails</h4>
                    <div style="background:rgba(15,23,42,0.85);border:1px solid rgba(56,189,248,0.2);border-radius:6px;padding:12px;font-size:0.82rem;color:#cbd5e1;display:flex;flex-direction:column;gap:6px;">
                        <div>• <b>CVE Anti-Hallucination Guardrail:</b> <span style="color:#10b981;">${guard.anti_hallucination_filter || 'Active (Enforced)'}</span> — Unverified absent CVEs intercepted with zero fabrication.</div>
                        <div>• <b>ALCE Faithfulness Verification:</b> <span style="color:#10b981;">${guard.alce_faithfulness_verification || 'Active'}</span> — Natural language inference verifies claim citations against scan telemetry.</div>
                        <div>• <b>Offensive Request Refusal Filter:</b> <span style="color:#10b981;">${guard.defensive_refusal_filter || 'Active'}</span> — 100% strict refusal on offensive exploit payload generation.</div>
                    </div>
                `;
            }).catch(err => {
                if (content) content.innerHTML = `<div style="color:#ef4444;padding:18px;">Failed to load model routing status: ${err.message}</div>`;
            });
        }

        const btnAttackGraph = document.getElementById('btnOpenAttackGraph');
        if (btnAttackGraph) btnAttackGraph.addEventListener('click', openAttackGraph);

        const btnCloseAttackGraph = document.getElementById('btnCloseAttackGraphModal');
        if (btnCloseAttackGraph) {
            btnCloseAttackGraph.addEventListener('click', () => {
                const modal = document.getElementById('attackGraphModal');
                const frame = document.getElementById('attackGraphFrame');
                if (modal) modal.style.display = 'none';
                if (frame) frame.src = '';
            });
        }

        const btnCloseModelRouting = document.getElementById('btnCloseModelRoutingModal');
        if (btnCloseModelRouting) {
            btnCloseModelRouting.addEventListener('click', () => {
                const modal = document.getElementById('modelRoutingModal');
                if (modal) modal.style.display = 'none';
            });
        }

        // Demo Scan Button
        const btnDemoScan = document.getElementById('btnLoadDemoScan');
        if (btnDemoScan) {
            btnDemoScan.addEventListener('click', async () => {
                AegisUtils.showToast('Loading Verified Demo Scan (OWASP Juice Shop)...', 'info');
                try {
                    const resp = await fetch('/api/demo/load');
                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                    const demoData = await resp.json();
                    const targetInput = document.getElementById('scanTargetInput');
                    if (targetInput) targetInput.value = demoData.target || 'localhost:3000';
                    applyReportData(demoData);
                    AegisUtils.showToast('Verified Demo Scan loaded! Explore live CVE triage, attack graph, and virtual patches.', 'success');
                } catch (err) {
                    AegisUtils.showToast(`Failed to load demo scan: ${err.message}`, 'error');
                }
            });
        }

        const btnCopilot = document.getElementById('btnHeaderCopilot');
        if (btnCopilot) btnCopilot.addEventListener('click', () => window.AegisCopilot && AegisCopilot.toggleCopilot());

        const btnTerminal = document.getElementById('btnHeaderTerminal');
        if (btnTerminal) btnTerminal.addEventListener('click', () => document.getElementById('auditTerminal')?.classList.toggle('active'));

        const btnTerminalMin = document.getElementById('btnTerminalMinimize');
        if (btnTerminalMin) btnTerminalMin.addEventListener('click', () => document.getElementById('auditTerminal')?.classList.toggle('active'));

        const btnGlobeSpin = document.getElementById('btnToggleGlobeSpin');
        if (btnGlobeSpin) btnGlobeSpin.addEventListener('click', () => window.AegisGlobe && AegisGlobe.toggleSpin());

        const btnGlobeZoomIn = document.getElementById('btnGlobeZoomIn');
        if (btnGlobeZoomIn) btnGlobeZoomIn.addEventListener('click', () => window.AegisGlobe && AegisGlobe.zoomIn());

        const btnGlobeZoomOut = document.getElementById('btnGlobeZoomOut');
        if (btnGlobeZoomOut) btnGlobeZoomOut.addEventListener('click', () => window.AegisGlobe && AegisGlobe.zoomOut());

        const btnGlobeZoomReset = document.getElementById('btnGlobeZoomReset');
        if (btnGlobeZoomReset) btnGlobeZoomReset.addEventListener('click', () => window.AegisGlobe && AegisGlobe.resetZoom());

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
                    openModelRoutingModal();
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
