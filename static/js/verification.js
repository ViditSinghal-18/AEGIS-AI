/**
 * AEGIS-AI: Domain Ownership Verification UI Component
 * Provides guided DNS TXT and HTTP token challenge flows.
 */

window.AegisVerification = (function () {
    'use strict';

    let currentDomain = '';

    async function startVerification(domain) {
        if (!domain) {
            AegisUtils.showToast('Please specify a domain to verify.', 'warning');
            return;
        }
        currentDomain = domain;

        try {
            const resp = await fetch('/api/verify/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domain })
            });
            const data = await resp.json();

            if (data.success && data.instructions) {
                renderModalContent(data.instructions);
                const modal = document.getElementById('verificationModal');
                if (modal) modal.style.display = 'flex';
            } else {
                AegisUtils.showToast(data.error || 'Failed to start domain verification.', 'error');
            }
        } catch (e) {
            AegisUtils.showToast(`Verification error: ${e.message}`, 'error');
        }
    }

    function renderModalContent(instructions) {
        const body = document.getElementById('verificationModalBody');
        if (!body) return;

        body.innerHTML = `
            <div style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 16px;">
                To enable <strong>VERIFIED ACTIVE</strong> port scanning against <code>${AegisUtils.escapeHtml(instructions.domain)}</code>, 
                prove ownership via either DNS TXT record or HTTP challenge file:
            </div>

            <div style="background: rgba(5,8,17,0.7); border: 1px solid rgba(0,240,255,0.2); border-radius: 6px; padding: 14px; margin-bottom: 14px;">
                <h4 style="color:#00f0ff;margin-bottom:6px;font-size:0.9rem;">Option 1: DNS TXT Record (Recommended)</h4>
                <div style="font-size:0.8rem;color:#cbd5e1;margin-bottom:6px;">Add this TXT record at your DNS registrar:</div>
                <div style="display:flex;align-items:center;background:#030712;padding:6px 10px;border-radius:4px;font-family:monospace;font-size:0.8rem;">
                    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;">${AegisUtils.escapeHtml(instructions.dns_txt_record.host)} TXT "${AegisUtils.escapeHtml(instructions.dns_txt_record.value)}"</span>
                    <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${instructions.dns_txt_record.value}');AegisUtils.showToast('Token copied!','success');" style="margin-left:8px;padding:3px 8px;">Copy</button>
                </div>
            </div>

            <div style="background: rgba(5,8,17,0.7); border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 14px; margin-bottom: 18px;">
                <h4 style="color:#f1f5f9;margin-bottom:6px;font-size:0.9rem;">Option 2: HTTP Token File</h4>
                <div style="font-size:0.8rem;color:#cbd5e1;margin-bottom:6px;">Host this file on your web server:</div>
                <div style="background:#030712;padding:6px 10px;border-radius:4px;font-family:monospace;font-size:0.8rem;">
                    <code>${AegisUtils.escapeHtml(instructions.http_challenge.url)}</code>
                </div>
            </div>

            <div style="display:flex;justify-content:flex-end;gap:10px;">
                <button class="btn btn-secondary" onclick="document.getElementById('verificationModal').style.display='none';">Cancel</button>
                <button class="btn btn-primary" id="btnVerifyCheck">Verify Ownership Now</button>
            </div>
        `;

        document.getElementById('btnVerifyCheck').addEventListener('click', checkVerification);
    }

    async function checkVerification() {
        if (!currentDomain) return;
        const btn = document.getElementById('btnVerifyCheck');
        if (btn) btn.textContent = 'Checking DNS/HTTP...';

        try {
            const resp = await fetch('/api/verify/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: currentDomain })
            });
            const data = await resp.json();

            if (data.verified) {
                AegisUtils.showToast(`Domain ${currentDomain} successfully verified! Active scan unlocked.`, 'success');
                const modal = document.getElementById('verificationModal');
                if (modal) modal.style.display = 'none';

                // Update UI badge
                const badge = document.getElementById('operationalModeBadge');
                if (badge) {
                    badge.textContent = 'VERIFIED ACTIVE';
                    badge.style.background = 'rgba(16, 185, 129, 0.2)';
                    badge.style.borderColor = '#10b981';
                }
            } else {
                AegisUtils.showToast(data.message || 'Verification token not found yet. DNS may take up to 2 minutes to propagate.', 'warning');
            }
        } catch (e) {
            AegisUtils.showToast(`Check failed: ${e.message}`, 'error');
        } finally {
            if (btn) btn.textContent = 'Verify Ownership Now';
        }
    }

    return {
        startVerification,
        checkVerification
    };
})();
