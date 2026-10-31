/**
 * AEGIS-AI: Grounded Security Operations Copilot UI Component
 * Strictly displays the active LLM provider (Anthropic, Gemini, Bedrock, Ollama, or Rule-based)
 * and verifies grounding against report telemetry.
 */

window.AegisCopilot = (function () {
    'use strict';

    let currentTarget = '';

    function initCopilot(target = '') {
        currentTarget = target;
        const sendBtn = document.getElementById('btnCopilotSend');
        const inputEl = document.getElementById('copilotInput');

        if (sendBtn && inputEl) {
            sendBtn.onclick = () => sendMessage();
            inputEl.onkeydown = (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            };
        }

        // Add welcome message if container is empty
        const container = document.getElementById('copilotMessages');
        if (container && container.children.length === 0) {
            appendChatMessage(
                'ai',
                `👋 Greetings! I am **Aegis Copilot**, your autonomous defensive SOC assistant. Monitoring target \`${target || 'active asset'}\`.\n\nAsk me to summarize findings, verify compliance posture, provide Nginx virtual patches, or explain specific CVE risks.`,
                'rule-based',
                'SOC Telemetry Engine'
            );
        }
    }

    function toggleCopilot() {
        const drawer = document.getElementById('copilotDrawer');
        const fab = document.getElementById('copilotFab');
        if (drawer) {
            if (drawer.style.display === 'none') {
                drawer.style.display = 'flex';
                if (fab) fab.style.display = 'none';
            } else {
                drawer.style.display = 'none';
                if (fab) fab.style.display = 'flex';
            }
        }
    }

    function minimizeCopilot() {
        const drawer = document.getElementById('copilotDrawer');
        if (drawer) {
            drawer.classList.toggle('minimized');
        }
    }

    async function sendMessage(customText = null) {
        const inputEl = document.getElementById('copilotInput');
        const text = customText || (inputEl ? inputEl.value.trim() : '');
        if (!text) return;

        // Ensure drawer is open and not minimized if user clicked a chip
        const drawer = document.getElementById('copilotDrawer');
        if (drawer) {
            drawer.style.display = 'flex';
            drawer.classList.remove('minimized');
        }

        if (inputEl) inputEl.value = '';
        appendChatMessage('user', text);

        // Show thinking indicator
        const thinkingId = appendChatMessage('ai', 'Thinking with grounded telemetry...', 'thinking');

        try {
            const resp = await fetch('/api/agent-chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, target: currentTarget })
            });

            const data = await resp.json();
            const thinkingEl = document.getElementById(thinkingId);
            if (thinkingEl) thinkingEl.remove();

            if (resp.ok) {
                appendChatMessage('ai', data.reply, data.provider, data.model, data.grounded);
            } else {
                appendChatMessage('ai', `Error: ${data.error || 'Failed to query Copilot.'}`, 'error');
            }
        } catch (e) {
            const thinkingEl = document.getElementById(thinkingId);
            if (thinkingEl) thinkingEl.remove();
            appendChatMessage('ai', `Connection error: ${e.message}`, 'error');
        }
    }

    function appendChatMessage(role, content, provider = 'system', model = '', isGrounded = true) {
        const container = document.getElementById('copilotMessages');
        if (!container) return null;

        const msgId = 'msg_' + Math.random().toString(36).substring(2, 9);
        const msgDiv = document.createElement('div');
        msgDiv.id = msgId;
        msgDiv.className = `copilot-msg msg-${role}`;
        msgDiv.style.cssText = `
            margin-bottom: 8px;
            display: flex;
            flex-direction: column;
            align-items: ${role === 'user' ? 'flex-end' : 'flex-start'};
            width: 100%;
        `;

        let providerBadge = '';
        if (role === 'ai') {
            const badgeColor = provider === 'anthropic' ? '#a855f7' : provider === 'gemini' ? '#38bdf8' : provider === 'bedrock' ? '#f59e0b' : '#10b981';
            const providerLabel = provider === 'rule-based' ? 'Rule-based Heuristic' : `LLM: ${model || provider}`;
            const groundBadge = isGrounded ? '<span style="color:#10b981;font-size:0.7rem;margin-left:6px;">[Grounded]</span>' : '<span style="color:#ef4444;font-size:0.7rem;margin-left:6px;">[Unverified Cited CVE]</span>';

            providerBadge = `
                <div style="font-size:0.7rem;color:#64748b;margin-bottom:4px;display:flex;align-items:center;">
                    <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:${badgeColor};margin-right:6px;"></span>
                    <strong style="color:#94a3b8;">${AegisUtils.escapeHtml(providerLabel)}</strong>
                    ${groundBadge}
                </div>
            `;
        }

        // Parse basic markdown: bold, code blocks, headers
        let parsedContent = AegisUtils.escapeHtml(content)
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/`([^`]+)`/g, '<code style="background:#0f172a;padding:2px 4px;border-radius:3px;color:#38bdf8;font-size:0.85em;">$1</code>')
            .replace(/### (.*?)\n/g, '<h4 style="color:#00f0ff;margin:8px 0 4px 0;font-size:0.92rem;">$1</h4>')
            .replace(/\n\n/g, '<br><br>')
            .replace(/\n/g, '<br>');

        msgDiv.innerHTML = `
            ${providerBadge}
            <div style="
                background: ${role === 'user' ? 'rgba(0, 240, 255, 0.12)' : 'rgba(11, 18, 33, 0.95)'};
                border: 1px solid ${role === 'user' ? 'rgba(0, 240, 255, 0.3)' : 'rgba(255, 255, 255, 0.08)'};
                border-left: 3px solid ${role === 'user' ? '#00f0ff' : '#38bdf8'};
                color: #f1f5f9;
                padding: 10px 14px;
                border-radius: 8px;
                font-size: 0.82rem;
                max-width: 90%;
                line-height: 1.5;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            ">
                ${parsedContent}
            </div>
        `;

        container.appendChild(msgDiv);
        container.scrollTop = container.scrollHeight;
        return msgId;
    }

    return {
        initCopilot,
        sendMessage,
        toggleCopilot,
        minimizeCopilot
    };
})();
