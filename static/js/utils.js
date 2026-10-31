/**
 * AEGIS-AI: Frontend Utility & Safe DOM Manipulation Functions
 * Strictly prevents Cross-Site Scripting (XSS) by escaping all dynamic scan data.
 */

window.AegisUtils = (function () {
    'use strict';

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function safeSetText(elementOrId, text) {
        const el = typeof elementOrId === 'string' ? document.getElementById(elementOrId) : elementOrId;
        if (el) {
            el.textContent = text !== null && text !== undefined ? String(text) : '';
        }
    }

    function safeSetHtml(elementOrId, sanitizedHtml) {
        const el = typeof elementOrId === 'string' ? document.getElementById(elementOrId) : elementOrId;
        if (el) {
            el.innerHTML = sanitizedHtml;
        }
    }

    function showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `aegis-toast toast-${type}`;
        toast.style.cssText = `
            background: rgba(11, 18, 33, 0.95);
            border-left: 4px solid ${type === 'error' ? '#ef4444' : type === 'success' ? '#10b981' : '#00f0ff'};
            color: #f1f5f9;
            padding: 12px 18px;
            margin-bottom: 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            display: flex;
            align-items: center;
            justify-content: space-between;
            min-width: 280px;
            animation: fadeIn 0.3s ease;
        `;
        toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    function formatTimestamp(isoStr) {
        if (!isoStr) return 'Unknown';
        try {
            const d = new Date(isoStr);
            return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
        } catch (e) {
            return String(isoStr);
        }
    }

    function getSeverityColor(sev) {
        const s = String(sev || '').toLowerCase();
        if (s === 'critical' || s.includes('p1')) return '#ef4444';
        if (s === 'high' || s.includes('p2')) return '#f97316';
        if (s === 'medium' || s.includes('p3')) return '#f59e0b';
        if (s === 'low' || s.includes('p4')) return '#3b82f6';
        return '#64748b';
    }

    return {
        escapeHtml,
        safeSetText,
        safeSetHtml,
        showToast,
        formatTimestamp,
        getSeverityColor
    };
})();
