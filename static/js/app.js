/**
 * AEGIS-AI: Main Frontend Application Controller
 * Coordinates telemetry streams, 3D cyber globe, exposure charts, triage lists,
 * attack walkthroughs, command palette, and multi-format exports.
 */

window.AegisApp = (function () {
    'use strict';

    let currentReport = null;
    let selectedFindingIndex = 0;

    async function initDashboard() {
        // 1. Initialize 3D Globe
        AegisGlobe.initGlobe('globe-container');

        // 2. Setup Navigation and Modals
        setupEventListeners();

        // 3. Load initial report or demo data
        await loadInitialData();
    }

    async function loadInitialData() {
        try {
            const resp = await fetch('/api/report');
            if (resp.ok) {
                const data = await resp.json();
                applyReportData(data);
            } else {
                // Fallback to latest online
                const onlineResp = await fetch('/api/latest-online');
                if (onlineResp.ok) {
                    const onlineData = await onlineResp.json();
                    applyReportData(onlineData);
                }
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
        const critCount = findings.filter(f => (f.priority_level || '').includes('P1') || f.severity === 'Critical').length;
        const highCount = findings.filter(f => (f.priority_level || '').includes('P2') || f.severity === 'High').length;
        const medCount = findings.filter(f => (f.priority_level || '').includes('P3') || f.severity === 'Medium').length;
        const lowCount = findings.filter(f => (f.priority_level || '').includes('P4') || f.severity === 'Low').length;

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

        // Plot 3D Globe Pins from real geo data
        const geo = data.geo_telemetry || (data.report && data.report.geo_telemetry);
        AegisGlobe.plotRealTargetPins(target, geo);

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
                <tr class="finding-row ${idx === selectedFindingIndex ? 'row-selected' : ''}" onclick="AegisApp.selectFinding(${idx})" style="cursor:pointer;">
                    <td><span class="badge" style="background:${sevColor};color:#fff;font-size:0.75rem;">${AegisUtils.escapeHtml(f.priority_level || f.severity || 'P2')}</span></td>
                    <td style="font-weight:700;color:#00f0ff;">${AegisUtils.escapeHtml(score)}</td>
                    <td style="color:#f1f5f9;font-weight:600;">${AegisUtils.escapeHtml(f.title || 'Finding')}</td>
                    <td>${cves}</td>
                    <td style="color:#94a3b8;font-size:0.8rem;">${AegisUtils.escapeHtml(f.source || 'perimeter')}</td>
                    <td style="color:#38bdf8;font-family:monospace;font-size:0.8rem;">${AegisUtils.escapeHtml(epssProb)}</td>
                    <td><button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();AegisApp.viewRemediation(${idx})">Remediate</button></td>
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
        AegisUtils.safeSetText('selectedFindingTitle', f.title || 'Finding');
        AegisUtils.safeSetText('selectedFindingDesc', f.description || f.why_it_matters || 'No description');
        AegisUtils.safeSetText('selectedFindingEvidence', f.evidence || f.exposure_context || 'Verified in perimeter scan');
        AegisUtils.safeSetText('selectedFindingAction', f.remediation || f.suggested_action || 'Review security configuration');
        AegisUtils.safeSetText('selectedFindingScore', f.contextual_risk_score || 'N/A');

        // Update Attack Simulator walkthrough
        renderAttackSimulator(f);
    }

    function renderAttackSimulator(finding) {
        const container = document.getElementById('attackSimulatorContainer');
        if (!container) return;

        const target = (currentReport && currentReport.target) || 'target.site';
        const mitre = finding.mitre_attack || { technique_id: 'T1190', technique_name: 'Exploit Public-Facing App', tactic: 'Initial Access' };

        container.innerHTML = `
            <div style="font-size:0.75rem;color:#f59e0b;background:rgba(245,158,11,0.1);border-left:3px solid #f59e0b;padding:6px 10px;margin-bottom:12px;border-radius:3px;">
                ⚠️ <strong>ILLUSTRATIVE CONCEPTUAL MODEL ONLY:</strong> No offensive exploitation payloads were transmitted against the target.
            </div>

            <div class="sim-phase-card">
                <div class="sim-phase-header"><span class="sim-phase-badge">Phase 1</span> <strong>Reconnaissance & Asset Ingress</strong></div>
                <div class="sim-phase-body">Adversary discovers public endpoint on ${AegisUtils.escapeHtml(target)} disclosing '${AegisUtils.escapeHtml(finding.title)}'.</div>
            </div>

            <div class="sim-phase-card">
                <div class="sim-phase-header"><span class="sim-phase-badge">Phase 2</span> <strong>Weaponization & Ingress Trigger (${AegisUtils.escapeHtml(mitre.technique_id || 'T1190')})</strong></div>
                <div class="sim-phase-body">Adversary crafts probe matching ${AegisUtils.escapeHtml(mitre.technique_name || 'Exploit Public-Facing App')} to trigger target response.</div>
            </div>

            <div class="sim-phase-card">
                <div class="sim-phase-header"><span class="sim-phase-badge">Phase 3</span> <strong>Adversary Impact (${AegisUtils.escapeHtml(mitre.tactic || 'Impact')})</strong></div>
                <div class="sim-phase-body">Exposure allows potential unauthorized session reading or service manipulation (EPSS: ${(finding.epss_probability * 100 || 0.5).toFixed(2)}%).</div>
            </div>

            <div class="sim-phase-card" style="border-left-color:#10b981;">
                <div class="sim-phase-header"><span class="sim-phase-badge" style="background:#10b981;">Phase 4</span> <strong style="color:#10b981;">Defensive Remediation</strong></div>
                <div class="sim-phase-body"><code>${AegisUtils.escapeHtml(finding.remediation || 'Enforce WAF virtual patch.')}</code></div>
            </div>
        `;
    }

    function renderComplianceCards(comp) {
        if (!comp) return;
        const setCard = (prefix, data) => {
            if (!data) return;
            AegisUtils.safeSetText(`${prefix}Score`, `${data.score || 0}%`);
            AegisUtils.safeSetText(`${prefix}Pass`, `${data.passing_controls || 0}/${data.total_controls || 4} Controls`);
        };

        setCard('compPci', comp.pci_dss_4);
        setCard('compNist', comp.nist_csf_2);
        setCard('compIso', comp.iso_27001);
        setCard('compSoc2', comp.soc_2);
    }

    async function triggerScan(targetInput) {
        const target = targetInput || (document.getElementById('scanTargetInput') ? document.getElementById('scanTargetInput').value.trim() : '');
        if (!target) {
            AegisUtils.showToast('Please enter a target domain or IP.', 'warning');
            return;
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
        }

        // Domain Verification Modal Trigger
        const btnVerify = document.getElementById('btnOpenVerification');
        if (btnVerify) {
            btnVerify.onclick = () => {
                const target = (currentReport && currentReport.target) || (inputScan ? inputScan.value.trim() : '');
                AegisVerification.startVerification(target);
            };
        }

        // Command Palette (Ctrl+K / Cmd+K)
        window.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                toggleCommandPalette();
            }
        });

        // Export Dropdowns
        setupExportHandlers();
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

    function viewRemediation(idx) {
        selectFinding(idx);
        const modal = document.getElementById('remediationModal');
        if (modal) modal.style.display = 'flex';
    }

    return {
        initDashboard,
        triggerScan,
        selectFinding,
        viewRemediation,
        toggleCommandPalette
    };
})();

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    AegisApp.initDashboard();
});
