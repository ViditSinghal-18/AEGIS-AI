"""
Streamlit dashboard for the prioritized report and scan history diffs.
Run from repo root: py -m streamlit run dashboard/app.py
"""

from __future__ import annotations

import html
import io
import json
import os
import sys
import time as _time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
import streamlit.components.v1 as components

from backend.service import build_scan_request, run_scan
from config import DATA_DIR, DEFAULT_PORTS, DEFAULT_TARGET, get_target_allowlist, is_target_allowed
from storage import diff_reports, generate_csv_report, generate_html_report, list_run_history, read_json, target_data_dir
from verification.verify import (
    check_domain_verification,
    generate_verification_token,
    is_domain_verified,
    load_verified_targets,
)
from correlation.mitre_attack import map_findings_to_mitre
from correlation.compliance import OWASP_CATEGORIES, map_compliance
from correlation.siem_export import generate_cef_export, generate_ecs_export, send_webhook_alert
from remediation.code_gen import (
    generate_nginx_hardening,
    generate_apache_hardening,
    generate_caddy_hardening,
    generate_cloudflare_rules,
    generate_node_helmet,
    generate_dns_hardening,
    generate_firewall_rules,
)
from remediation.waf_rules import (
    generate_aws_waf_json,
    generate_cloudflare_waf_rules,
    generate_modsecurity_rules,
)
from ai.copilot import query_copilot
from dashboard.attack_graph import render_attack_surface_graph_html

# --- Page Setup & Cyber Dark SOC Theme ---
st.set_page_config(
    page_title="AI Attack Surface Correlation & SOC Defense Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    code, pre, [class*="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 3.5rem;
        max-width: 1600px;
    }

    /* Top Futuristic HUD Header */
    .cyber-hud-header {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.92) 0%, rgba(6, 11, 25, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.35);
        border-radius: 16px;
        padding: 1.4rem 1.8rem;
        margin-bottom: 1.4rem;
        backdrop-filter: blur(16px);
        box-shadow: 0 10px 35px -5px rgba(0, 242, 254, 0.12), 0 0 20px rgba(0, 0, 0, 0.6);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
        position: relative;
        overflow: hidden;
    }

    .cyber-hud-header::before {
        content: '';
        position: absolute;
        top: 0; left: 0; width: 100%; height: 2px;
        background: linear-gradient(90deg, transparent 0%, #38bdf8 50%, transparent 100%);
    }

    .cyber-title h1 {
        font-size: 2rem;
        font-weight: 900;
        margin: 0;
        background: linear-gradient(90deg, #f8fafc 0%, #38bdf8 60%, #818cf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: flex;
        align-items: center;
        gap: 0.6rem;
        letter-spacing: -0.02em;
    }

    .cyber-title p {
        color: #94a3b8;
        font-size: 0.95rem;
        margin: 0.3rem 0 0 0;
        font-weight: 500;
    }

    .pulse-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 10px #10b981;
        animation: pulse 1.8s infinite;
        margin-right: 6px;
    }

    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* High-Tech Cyber KPI Cards */
    .cyber-card {
        background: linear-gradient(145deg, rgba(30, 41, 59, 0.75) 0%, rgba(15, 23, 42, 0.85) 100%);
        border: 1px solid rgba(148, 163, 184, 0.16);
        border-radius: 14px;
        padding: 1.15rem 1.3rem;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 6px 24px -2px rgba(0, 0, 0, 0.4);
        position: relative;
        overflow: hidden;
        height: 100%;
    }
    .cyber-card:hover {
        transform: translateY(-3px);
        border-color: rgba(56, 189, 248, 0.5);
        box-shadow: 0 12px 30px -4px rgba(56, 189, 248, 0.2);
    }
    .cyber-label {
        font-size: 0.76rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 800;
        color: #94a3b8;
        margin-bottom: 0.4rem;
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }
    .cyber-value {
        font-size: 1.85rem;
        font-weight: 900;
        color: #f8fafc;
        line-height: 1.15;
    }
    .cyber-sub {
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 0.35rem;
        font-weight: 500;
    }

    /* Grade Badge Circle */
    .grade-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 44px;
        height: 44px;
        border-radius: 50%;
        font-size: 1.4rem;
        font-weight: 900;
        box-shadow: 0 0 15px currentColor;
    }

    /* Risk Score Gauge Pill */
    .risk-pill-crit { background: rgba(220, 38, 38, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
    .risk-pill-high { background: rgba(234, 88, 12, 0.2); border: 1px solid #f97316; color: #fdba74; }
    .risk-pill-med { background: rgba(217, 119, 6, 0.2); border: 1px solid #eab308; color: #fde047; }
    .risk-pill-low { background: rgba(37, 99, 235, 0.2); border: 1px solid #3b82f6; color: #93c5fd; }
    .risk-pill-info { background: rgba(75, 85, 99, 0.2); border: 1px solid #64748b; color: #cbd5e1; }

    /* Severity Badges & Chips */
    .risk-strip {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin: 0.75rem 0 1.25rem 0;
    }
    .risk-chip {
        border-radius: 9999px;
        padding: 6px 14px;
        font-size: 0.84rem;
        font-weight: 700;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.2s ease;
    }
    .risk-chip:hover {
        filter: brightness(1.2);
    }
    .risk-critical { background: #450a0a; color: #fecaca; border: 1px solid #b91c1c; }
    .risk-high { background: #431407; color: #fed7aa; border: 1px solid #c2410c; }
    .risk-medium { background: #451a03; color: #fde68a; border: 1px solid #b45309; }
    .risk-low { background: #172554; color: #bfdbfe; border: 1px solid #1d4ed8; }
    .risk-info { background: #1e293b; color: #cbd5e1; border: 1px solid #475569; }

    /* Interactive Banner Box */
    .feature-banner {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.85) 0%, rgba(15, 23, 42, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.28);
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
    }

    /* Glassmorphism for expanders and tabs */
    [data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(148, 163, 184, 0.16) !important;
        border-radius: 12px !important;
        margin-bottom: 0.75rem !important;
    }

    /* Mode Pill Badge */
    .mode-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 15px;
        border-radius: 9999px;
        font-size: 0.84rem;
        font-weight: 700;
        letter-spacing: 0.03em;
    }

    /* --- Cyber SOC Selectbox & Dropdown Popover Theme --- */
    /* Selectbox Input Box (Closed State) */
    div[data-testid="stSelectbox"] label {
        font-weight: 700 !important;
        color: #f8fafc !important;
        font-size: 0.95rem !important;
        margin-bottom: 0.35rem !important;
    }
    div[data-baseweb="select"] > div {
        background-color: #0f172a !important;
        border: 1px solid rgba(56, 189, 248, 0.35) !important;
        border-radius: 10px !important;
        color: #f8fafc !important;
        transition: all 0.2s ease-in-out !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
    }
    div[data-baseweb="select"] > div:hover {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.25) !important;
    }
    div[data-baseweb="select"] > div:focus-within {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 14px rgba(56, 189, 248, 0.4) !important;
    }
    div[data-baseweb="select"] span,
    div[data-baseweb="select"] div {
        color: #f8fafc !important;
    }
    div[data-baseweb="select"] svg {
        fill: #38bdf8 !important;
    }

    /* Floating Dropdown Popover Container (Opened State) */
    div[data-baseweb="popover"] {
        z-index: 9999999 !important;
        background: transparent !important;
    }
    div[data-baseweb="popover"] > div,
    div[data-baseweb="popover"] [role="listbox"],
    div[data-baseweb="popover"] [data-baseweb="menu"],
    ul[data-baseweb="menu"] {
        background-color: #0b1329 !important;
        background: linear-gradient(160deg, #0f172a 0%, #070d1e 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.45) !important;
        border-radius: 12px !important;
        box-shadow: 0 12px 35px rgba(0, 0, 0, 0.85), 0 0 20px rgba(56, 189, 248, 0.2) !important;
        backdrop-filter: blur(16px) !important;
        padding: 6px !important;
        overflow: hidden !important;
    }

    /* Individual Dropdown Menu Options */
    div[data-baseweb="popover"] li[role="option"],
    div[data-baseweb="popover"] [data-baseweb="menu-item"],
    ul[data-baseweb="menu"] li {
        background-color: transparent !important;
        color: #e2e8f0 !important;
        font-family: 'Outfit', sans-serif !important;
        font-size: 0.92rem !important;
        font-weight: 500 !important;
        border-radius: 8px !important;
        margin: 2px 0 !important;
        padding: 8px 14px !important;
        cursor: pointer !important;
        transition: all 0.15s ease-in-out !important;
    }

    /* Option Hover State */
    div[data-baseweb="popover"] li[role="option"]:hover,
    div[data-baseweb="popover"] [data-baseweb="menu-item"]:hover,
    div[data-baseweb="popover"] li[aria-selected="false"]:hover {
        background: rgba(56, 189, 248, 0.16) !important;
        color: #38bdf8 !important;
        font-weight: 700 !important;
        padding-left: 18px !important;
    }

    /* Selected Option State */
    div[data-baseweb="popover"] li[aria-selected="true"],
    div[data-baseweb="popover"] [data-baseweb="menu-item"][aria-selected="true"],
    div[data-baseweb="popover"] li[role="option"][aria-selected="true"] {
        background: linear-gradient(90deg, rgba(56, 189, 248, 0.25) 0%, rgba(30, 58, 138, 0.35) 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.45) !important;
        color: #38bdf8 !important;
        font-weight: 700 !important;
    }

    /* Scrollbar for long list of targets */
    div[data-baseweb="popover"] ::-webkit-scrollbar {
        width: 6px;
    }
    div[data-baseweb="popover"] ::-webkit-scrollbar-track {
        background: rgba(15, 23, 42, 0.5);
        border-radius: 4px;
    }
    div[data-baseweb="popover"] ::-webkit-scrollbar-thumb {
        background: rgba(56, 189, 248, 0.4);
        border-radius: 4px;
    }
    div[data-baseweb="popover"] ::-webkit-scrollbar-thumb:hover {
        background: #38bdf8;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

import hmac

# 1. Authentication & Security Guard
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()
ALLOW_ANONYMOUS_DASHBOARD = os.getenv("ALLOW_ANONYMOUS_DASHBOARD", "true").strip().lower() in {
    "1",
    "true",
    "yes",
}
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 30

if not DASHBOARD_PASSWORD and not ALLOW_ANONYMOUS_DASHBOARD:
    st.markdown(
        """
        <div class="cyber-hud-header">
            <div class="cyber-title">
                <h1>🔒 Security Assessment Portal</h1>
                <p>Private defensive reporting workspace</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.error("🛡️ **Dashboard access is currently locked.**")
    st.info("Set `DASHBOARD_PASSWORD` in your deployment environment or set `ALLOW_ANONYMOUS_DASHBOARD=true` in `.env` to enable access.")
    st.stop()

if DASHBOARD_PASSWORD:
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = 0
    if "lockout_until" not in st.session_state:
        st.session_state.lockout_until = 0.0

    if not st.session_state.authenticated:
        st.markdown(
            """
            <div class="cyber-hud-header">
                <div class="cyber-title">
                    <h1>🔒 Security Assessment Portal</h1>
                    <p>Enter your authorized access token to view defensive reports</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        now = _time.monotonic()
        locked = now < st.session_state.lockout_until
        if locked:
            remaining = int(st.session_state.lockout_until - now)
            st.error(f"⛔ Too many failed attempts. Locked out for {remaining} seconds.")
        else:
            col_l1, col_l2, _ = st.columns([2, 1, 1])
            with col_l1:
                pwd = st.text_input("Dashboard Access Password", type="password", key="login_pwd_input")
                if st.button("🔑 Authenticate & Enter", key="login_btn", use_container_width=True):
                    if hmac.compare_digest(pwd.encode("utf-8"), DASHBOARD_PASSWORD.encode("utf-8")):
                        st.session_state.authenticated = True
                        st.session_state.login_attempts = 0
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        if st.session_state.login_attempts >= _MAX_LOGIN_ATTEMPTS:
                            st.session_state.lockout_until = _time.monotonic() + _LOCKOUT_SECONDS
                            st.error(f"⛔ Maximum attempts reached. Locked for {_LOCKOUT_SECONDS}s.")
                        else:
                            rem = _MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                            st.error(f"❌ Invalid credentials. {rem} attempt(s) remaining.")
        st.stop()


# --- Target & Report Discovery ---
def _discover_available_targets() -> list[str]:
    """Find all targets across per-target subdirectories, report files, and legacy storage."""
    targets: set[str] = set()
    if DATA_DIR.exists():
        for item in DATA_DIR.iterdir():
            if item.is_dir() and item.name not in {"cache", "history", "scratch"}:
                if (item / "prioritized_report.json").exists() or (item / "history").exists():
                    targets.add(item.name)
            elif item.is_file() and item.name.startswith("report_") and item.name.endswith(".json"):
                name = item.name[len("report_"):-len(".json")]
                if name:
                    targets.add(name)
        # Check flat prioritized report
        flat_report = DATA_DIR / "prioritized_report.json"
        if flat_report.exists():
            try:
                d = json.loads(flat_report.read_text(encoding="utf-8"))
                if d.get("target"):
                    targets.add(d["target"])
            except Exception:
                pass
    return sorted(list(targets))


available_targets = _discover_available_targets()

# Sidebar: Controls & Quick Scans
st.sidebar.markdown(
    """
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:1.1rem;padding-bottom:0.8rem;border-bottom:1px solid rgba(148,163,184,0.15);">
        <span style="font-size:1.8rem;">🛡️</span>
        <div>
            <h3 style="margin:0;font-size:1.15rem;font-weight:800;color:#f8fafc;letter-spacing:-0.02em;">Command Center</h3>
            <span style="font-size:0.75rem;color:#38bdf8;font-weight:600;"><span class="pulse-dot"></span>AI SOC Defense Engine</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Target Selector with Dynamic Workspace Sync

if "active_target" not in st.session_state:
    st.session_state["active_target"] = (
        "localhost" if "localhost" in available_targets
        else (available_targets[0] if available_targets else None)
    )

# Consume any pending workspace switch set by scan callbacks on the previous run.
# This block MUST run before the selectbox is instantiated so that writing
# st.session_state["target_workspace_select"] is legal (widget not yet drawn).
pending = st.session_state.pop("pending_target", None)
if pending:
    st.session_state["active_target"] = pending
    if pending in available_targets:
        st.session_state["target_workspace_select"] = pending

selected_target: str | None = None
if available_targets:
    if st.session_state.get("active_target") not in available_targets:
        st.session_state["active_target"] = available_targets[0]
    if "target_workspace_select" not in st.session_state or \
            st.session_state["target_workspace_select"] not in available_targets:
        st.session_state["target_workspace_select"] = st.session_state["active_target"]
    selected_target = st.sidebar.selectbox(
        "🎯 Target Workspace", available_targets, key="target_workspace_select")
    st.session_state["active_target"] = selected_target
else:
    st.sidebar.caption("No target reports detected yet.")

# Quick Scan Launcher in Sidebar
with st.sidebar.expander("🚀 Run New Scan / Assessment", expanded=False):
    st.caption("Trigger an authorized active probe or passive OSINT scan directly:")
    scan_input_target = st.text_input("Target Host/Domain", value=selected_target or "localhost", key="scan_input_target")
    scan_ports_input = st.text_input("Ports (Active scan)", value=",".join(str(p) for p in DEFAULT_PORTS), key="scan_ports")
    force_passive = st.checkbox("Force Passive OSINT only", value=False, key="scan_passive_cb")

    if st.button("⚡ Start Assessment Pipeline", use_container_width=True, type="primary"):
        target_name = scan_input_target.strip()
        if not target_name:
            st.error("Please specify a target domain or IP.")
        else:
            with st.spinner(f"Running defensive pipeline against {target_name}..."):
                scan_ok = False
                try:
                    scan_request = build_scan_request(
                        target_name,
                        scan_ports_input,
                        force_passive=force_passive,
                        requested_by="streamlit-dashboard",
                    )
                    scan_result = run_scan(scan_request)
                    st.session_state["pending_target"] = scan_result.target
                    st.success(
                        f"Assessment completed for {scan_result.target} "
                        f"({scan_result.mode}, {scan_result.finding_count} finding(s))."
                    )
                    scan_ok = True
                except Exception as ex:
                    st.error(f"Scan failed: {ex}")
            if scan_ok:
                _time.sleep(1)
                st.rerun()


def _load_report(target: str | None = None) -> dict[str, Any]:
    """Load the prioritized security report safely."""
    if target:
        try:
            return read_json("prioritized_report.json", target=target)
        except Exception:
            pass
        target_file = DATA_DIR / f"report_{target}.json"
        if target_file.exists():
            try:
                return json.loads(target_file.read_text(encoding="utf-8"))
            except Exception:
                pass
    try:
        return read_json("prioritized_report.json")
    except Exception:
        return {}


report = _load_report(selected_target)

# History Selector
history_files = list_run_history(target=selected_target)
selected_history: Path | None = None

if history_files:
    st.sidebar.markdown("---")
    st.sidebar.markdown("**📜 Scan History Timeline**")
    history_options = ["Latest Scan (Current)"] + [f.name for f in history_files]
    choice = st.sidebar.selectbox("Select Snapshot", history_options, label_visibility="collapsed")
    if choice != "Latest Scan (Current)":
        target_path = next((f for f in history_files if f.name == choice), None)
        if target_path:
            try:
                report = json.loads(target_path.read_text(encoding="utf-8"))
                selected_history = target_path
            except Exception:
                pass

# Domain Verification Panel in Sidebar
with st.sidebar.expander("🔑 Domain Ownership Verification", expanded=False):
    st.markdown("<small style='color:#94a3b8;'>Prove administrative control over a domain to authorize active scans:</small>", unsafe_allow_html=True)
    v_domain = st.text_input("Target Domain", placeholder="example.com", key="v_dom_input")
    
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        if st.button("1. Get Token", use_container_width=True):
            if v_domain:
                tok = generate_verification_token(v_domain.strip())
                st.session_state["v_token"] = tok
                st.session_state["v_domain_curr"] = v_domain.strip()
            else:
                st.error("Enter a domain.")
    with col_v2:
        if st.button("2. Verify", use_container_width=True):
            if v_domain:
                with st.spinner("Checking DNS TXT & HTTP challenge..."):
                    ok, msg = check_domain_verification(v_domain.strip())
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
            else:
                st.error("Enter a domain.")

    if "v_token" in st.session_state and st.session_state.get("v_domain_curr") == v_domain:
        st.markdown(
            f"""
            <div style="background:rgba(15,23,42,0.9);border:1px solid rgba(56,189,248,0.3);border-radius:8px;padding:10px;margin-top:8px;">
                <div style="font-size:0.75rem;color:#38bdf8;font-weight:700;">CHALLENGE TOKEN</div>
                <code style="font-size:0.85rem;color:#f8fafc;word-break:break-all;">{st.session_state['v_token']}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(f"**Method A (DNS TXT):**\n`_attacksurface-verify.{v_domain}`")
        st.markdown(f"**Method B (HTTP):**\n`https://{v_domain}/.well-known/attacksurface-verify.txt`")

    active_verified = load_verified_targets()
    if active_verified:
        st.markdown("---")
        st.caption("✅ Currently Verified Domains (30-Day TTL):")
        for dom, info in active_verified.items():
            st.code(f"{dom} [{info.get('method')}]", language="text")

# Sidebar footer status
st.sidebar.markdown("---")
auth_status_text = "🔒 Password Protected" if DASHBOARD_PASSWORD else "🟢 Public Demo Mode"
st.sidebar.caption(f"Status: {auth_status_text} | Engine: Amazon Bedrock AI & Heuristic SOC")


# --- Main Dashboard Header ---
target_display = report.get("target") or (selected_target or "No Target Selected")
mode = report.get("mode") or ("active" if is_target_allowed(target_display) or is_domain_verified(target_display) else "passive")

if is_target_allowed(target_display):
    mode_pill = '<span class="mode-pill" style="background:#1e3a8a;border:1px solid #3b82f6;color:#bfdbfe;">🧪 Local Lab (Active Probing)</span>'
elif is_domain_verified(target_display) or mode == "active":
    mode_pill = '<span class="mode-pill" style="background:#064e3b;border:1px solid #10b981;color:#a7f3d0;">🛡️ Verified Active (Authorized)</span>'
else:
    mode_pill = '<span class="mode-pill" style="background:#4c1d95;border:1px solid #8b5cf6;color:#ddd6fe;">🌐 Passive OSINT (Zero Probing)</span>'

st.markdown(
    f"""
    <div class="cyber-hud-header">
        <div class="cyber-title">
            <h1>🛡️ AI Attack Surface & Defense SOC</h1>
            <p><span class="pulse-dot"></span>Automated defensive intelligence, CVE/KEV correlation, and AI-prioritized remediation</p>
        </div>
        <div>
            {mode_pill}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# --- Empty State Handler ---
if not report or not report.get("findings"):
    st.markdown(
        """
        <div style="background:radial-gradient(circle at center, rgba(30,41,59,0.8) 0%, rgba(15,23,42,0.9) 100%);border:1px solid rgba(56,189,248,0.25);border-radius:16px;padding:3rem 2rem;text-align:center;margin:2rem 0;box-shadow:0 10px 40px rgba(0,0,0,0.5);">
            <div style="font-size:3.5rem;margin-bottom:1rem;">🎯</div>
            <h2 style="color:#f8fafc;font-weight:800;margin:0 0 0.5rem 0;">No Assessment Report Loaded</h2>
            <p style="color:#94a3b8;max-width:600px;margin:0 auto 1.8rem auto;font-size:1.05rem;">
                Select an existing target from the sidebar, launch an instant scan, or load sample lab data to evaluate the defensive intelligence engine.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        if st.button("⚡ Run Instant Localhost Scan", use_container_width=True, type="primary"):
            with st.spinner("Executing defensive pipeline for localhost..."):
                scan_result = run_scan(build_scan_request("localhost", DEFAULT_PORTS, force_passive=False))
                st.session_state["pending_target"] = scan_result.target
                st.success("Localhost scan complete!")
                _time.sleep(1)
                st.rerun()
    with col_e2:
        if st.button("🌐 Run Passive OSINT on example.com", use_container_width=True):
            with st.spinner("Gathering passive intelligence for example.com..."):
                scan_result = run_scan(build_scan_request("example.com", DEFAULT_PORTS, force_passive=True))
                st.session_state["pending_target"] = scan_result.target
                st.success("Passive OSINT scan complete!")
                _time.sleep(1)
                st.rerun()
    st.stop()


findings = report.get("findings") or []
target = report.get("target") or "Unknown"

# Compute Severity Analytics
severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
for finding in findings:
    sev = str(finding.get("severity") or "Info").title()
    severity_counts[sev if sev in severity_counts else "Info"] += 1

high_risk_count = severity_counts["Critical"] + severity_counts["High"]
related_cves = {cve for finding in findings for cve in (finding.get("related_cves") or [])}
cve_count = len(related_cves)

# Composite Risk Score Calculation (0-100)
raw_score = (
    severity_counts["Critical"] * 30
    + severity_counts["High"] * 18
    + severity_counts["Medium"] * 8
    + severity_counts["Low"] * 3
    + severity_counts["Info"] * 1
)
risk_score = min(100, raw_score)

if risk_score >= 70:
    score_pill_class = "risk-pill-crit"
    score_label = "HIGH THREAT"
elif risk_score >= 40:
    score_pill_class = "risk-pill-high"
    score_label = "ELEVATED"
elif risk_score >= 20:
    score_pill_class = "risk-pill-med"
    score_label = "MODERATE"
else:
    score_pill_class = "risk-pill-low"
    score_label = "SECURE / LOW"

# Calculate Compliance & Security Grade
comp_data = map_compliance(findings)
grade = comp_data["grade"]
grade_color = comp_data["grade_color"]

# Load asset metadata for visual graph & OSINT
assets_data = {}
try:
    assets_data = read_json("discovered_assets.json", target=selected_target)
except Exception:
    try:
        assets_data = read_json("discovered_assets.json")
    except Exception:
        assets_data = {}

passive_meta = assets_data.get("passive_meta") or {}
discovered_ports = assets_data.get("ports", [])
discovered_subdomains = passive_meta.get("certificate_transparency", [])
discovered_ips = passive_meta.get("dns", {}).get("A", [])


# --- Executive KPI Grid ---
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

with kpi1:
    st.markdown(
        f"""
        <div class="cyber-card">
            <div class="cyber-label">🎯 Assessed Target</div>
            <div class="cyber-value" style="font-size:1.35rem;word-break:break-all;">{target}</div>
            <div class="cyber-sub">Mode: {mode.upper()}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi2:
    st.markdown(
        f"""
        <div class="cyber-card">
            <div class="cyber-label">🚨 Total Findings</div>
            <div class="cyber-value">{len(findings)}</div>
            <div class="cyber-sub">{high_risk_count} Critical / High</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi3:
    st.markdown(
        f"""
        <div class="cyber-card">
            <div class="cyber-label">⚡ Threat Index</div>
            <div class="cyber-value">
                <span class="risk-chip {score_pill_class}" style="padding:4px 12px;font-size:1.2rem;">
                    {risk_score}/100
                </span>
            </div>
            <div class="cyber-sub">{score_label} POSTURE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi4:
    st.markdown(
        f"""
        <div class="cyber-card">
            <div class="cyber-label">🛡️ Security Grade</div>
            <div class="cyber-value" style="display:flex;align-items:center;gap:10px;">
                <span class="grade-badge" style="color:{grade_color};border:2px solid {grade_color};">
                    {grade}
                </span>
                <span style="font-size:1rem;font-weight:700;color:{grade_color};">
                    {comp_data['score']}%
                </span>
            </div>
            <div class="cyber-sub">{comp_data['posture']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi5:
    engine_name = "Amazon Bedrock AI" if report.get("used_llm") else "Heuristic Engine"
    model_str = report.get("model_id") or "CVSS 3.1 Fallback"
    st.markdown(
        f"""
        <div class="cyber-card">
            <div class="cyber-label">🧠 Prioritization Engine</div>
            <div class="cyber-value" style="font-size:1.2rem;color:#38bdf8;">{engine_name}</div>
            <div class="cyber-sub" style="font-size:0.75rem;overflow:hidden;text-overflow:ellipsis;">{model_str}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Severity Chip Summary Bar
chips = []
for severity, css_name in (
    ("Critical", "critical"),
    ("High", "high"),
    ("Medium", "medium"),
    ("Low", "low"),
    ("Info", "info"),
):
    count = severity_counts[severity]
    chips.append(f"<span class='risk-chip risk-{css_name}'>● {severity}: {count}</span>")

st.markdown("<div class='risk-strip'>" + "".join(chips) + "</div>", unsafe_allow_html=True)


# --- Streamlined Cyber Dashboard Tabs (6 Focused Panels) ---
tab_graph, tab_findings, tab_remediation, tab_compliance, tab_osint, tab_copilot = st.tabs(
    [
        "🕸️ Attack Surface Graph",
        "📋 Findings & Insights",
        "🛠️ Remediation & WAF",
        "🛡️ Threat & Compliance",
        "🌐 OSINT Recon & Diff",
        "🤖 AI Copilot & SIEM Export",
    ]
)


# ==========================================
# TAB 1: Interactive Visual Attack Graph (D3.js)
# ==========================================
with tab_graph:
    st.markdown("### 🕸️ Interactive Attack Surface Network Topology")
    st.caption("Dynamic force-directed cyber graph illustrating the target, IP endpoints, public subdomains, open ports, and correlated risk nodes.")

    graph_html = render_attack_surface_graph_html(
        target=target,
        findings=findings,
        ports=discovered_ports,
        subdomains=discovered_subdomains,
        ips=discovered_ips,
    )
    components.html(graph_html, height=510, scrolling=False)


# ==========================================
# TAB 2: Findings & Strategic Risk Insights
# ==========================================
with tab_findings:
    # 1. Executive Summary & Attack Surface Vector Breakdown
    col_s1, col_s2 = st.columns([1.8, 1.2])
    with col_s1:
        st.markdown("**Executive Summary**")
        st.info(report.get("summary") or "No executive summary available.")
        
        top_risks = report.get("top_risks") or []
        if top_risks:
            st.markdown("**🎯 Top Strategic Threats to Mitigate First:**")
            for idx, r in enumerate(top_risks, 1):
                st.markdown(f"**{idx}.** {r}")

    with col_s2:
        st.markdown("**📈 Severity Distribution**")
        chart_data = {
            "Severity": list(severity_counts.keys()),
            "Findings": list(severity_counts.values()),
        }
        st.bar_chart(chart_data, x="Severity", y="Findings", color="Severity")

    st.markdown("---")
    st.markdown("#### 🔬 Attack Surface Vector Breakdown")
    v_c1, v_c2, v_c3 = st.columns(3)
    
    config_issues = sum(1 for f in findings if f.get("source") in ["config_issues", "headers", "http_headers"])
    net_issues = sum(1 for f in findings if f.get("source") in ["port_scan", "services", "open_ports"])
    cve_findings = sum(1 for f in findings if f.get("related_cves"))

    with v_c1:
        st.markdown(
            f"""
            <div class="cyber-card">
                <div class="cyber-label">⚙️ Configuration & Headers</div>
                <div class="cyber-value">{config_issues}</div>
                <div class="cyber-sub">Missing CSP, HSTS, X-Frame, Info Leaks</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with v_c2:
        st.markdown(
            f"""
            <div class="cyber-card">
                <div class="cyber-label">🔌 Open Ports & Services</div>
                <div class="cyber-value">{net_issues}</div>
                <div class="cyber-sub">Exposed network service banners</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with v_c3:
        st.markdown(
            f"""
            <div class="cyber-card">
                <div class="cyber-label">⚠️ Known CVE Vulnerabilities</div>
                <div class="cyber-value">{cve_findings}</div>
                <div class="cyber-sub">Correlated against NVD database</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("### 📋 Prioritized Vulnerabilities & Actionable Fixes")
    st.caption("Issues are ranked in order of defensive urgency using CVSS, exploit probability (EPSS), and active KEV threats.")

    f_col1, f_col2, f_col3 = st.columns([2.5, 1.2, 1])
    with f_col1:
        search_query = st.text_input("🔍 Filter findings", placeholder="Search title, CVE, description, or action...", label_visibility="collapsed")
    with f_col2:
        selected_sev = st.selectbox("Severity Filter", ["All Severities", "Critical", "High", "Medium", "Low", "Info"], label_visibility="collapsed")
    with f_col3:
        sort_by = st.selectbox("Sort", ["Rank (Urgency)", "Severity (High→Low)"], label_visibility="collapsed")

    filtered_findings = []
    q = search_query.strip().lower()
    for f in findings:
        f_sev = str(f.get("severity") or "Info").title()
        if selected_sev != "All Severities" and f_sev != selected_sev:
            continue
        searchable_text = " ".join([
            str(f.get("title") or ""),
            str(f.get("why_it_matters") or ""),
            str(f.get("exploitability") or ""),
            str(f.get("suggested_action") or ""),
            " ".join(f.get("related_cves") or []),
        ]).lower()
        if q and q not in searchable_text:
            continue
        filtered_findings.append(f)

    if sort_by == "Severity (High→Low)":
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        filtered_findings.sort(key=lambda x: sev_order.get(str(x.get("severity") or "Info").title(), 5))
    else:
        filtered_findings.sort(key=lambda x: int(x.get("rank") or 999))

    # Findings Table Overview
    if filtered_findings:
        table_data = []
        for item in filtered_findings:
            table_data.append({
                "Rank": f"#{item.get('rank', '-')}",
                "Severity": str(item.get("severity", "Info")).upper(),
                "Title": item.get("title", "Untitled"),
                "Exploitability / Threat Context": item.get("exploitability", "-"),
                "CVEs": ", ".join(item.get("related_cves") or []) or "None",
                "Source": item.get("source", "configuration"),
            })
        st.dataframe(
            table_data,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Rank": st.column_config.TextColumn(width="small"),
                "Severity": st.column_config.TextColumn(width="small"),
                "Title": st.column_config.TextColumn(width="medium"),
                "Exploitability / Threat Context": st.column_config.TextColumn(width="large"),
                "CVEs": st.column_config.TextColumn(width="small"),
            },
        )
    else:
        st.info("No vulnerabilities match your search query.")

    st.markdown("---")
    st.subheader("🛡️ Detailed Remediation Cards")

    for item in filtered_findings:
        sev = str(item.get("severity") or "Info").title()
        rank = item.get("rank", "?")
        title = item.get("title", "Finding")
        
        with st.expander(f"#{rank} • [{sev.upper()}] {title}", expanded=(sev in ["Critical", "High"] and rank == 1)):
            c_info1, c_info2 = st.columns([2, 1])
            with c_info1:
                st.markdown(f"**⚡ Exploitability & Threat:** `{item.get('exploitability', 'Standard exposure')}`")
                st.markdown(f"**🔍 Why It Matters:**\n\n{item.get('why_it_matters', 'No description provided.')}")
            with c_info2:
                st.markdown(f"**🏷️ Discovery Vector:** `{item.get('source', 'config')}`")
                cves = item.get("related_cves") or []
                if cves:
                    st.markdown("**Public CVEs:**")
                    for cve in cves:
                        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
                        st.markdown(f"- [`{cve}`]({nvd_url})")
                else:
                    st.caption("No linked CVE identifiers.")

            action = item.get("suggested_action", "")
            if action:
                st.markdown(
                    f"""
                    <div style="background:rgba(6,78,59,0.25);border:1px solid #10b981;border-radius:8px;padding:12px 16px;margin-top:10px;">
                        <div style="color:#6ee7b7;font-weight:700;font-size:0.9rem;margin-bottom:6px;">
                            🛡️ Recommended Defensive Fix & Configuration
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.markdown(action)


# ==========================================
# TAB 3: Remediation Engineering & WAF Protection
# ==========================================
with tab_remediation:
    st.markdown("### 🛠️ Remediation Engineering & WAF Protection")
    st.caption("Interactive patch simulation, production server hardening scripts, and edge WAF rules.")

    sub_rem_code, sub_rem_waf, sub_rem_sim = st.tabs(
        ["🚀 Server Hardening", "🧱 WAF Shield Rules", "⚡ 'What-If' Patch Simulator"]
    )

    with sub_rem_code:
        st.markdown(
            """
            <div class="feature-banner">
                <div style="font-weight:700;color:#38bdf8;font-size:1.05rem;margin-bottom:4px;">
                    🚀 Instant Infrastructure Hardening
                </div>
                <div style="color:#94a3b8;font-size:0.88rem;">
                    Select your web server, edge proxy, or cloud environment below to generate copy-paste configuration snippets that address missing headers, weak TLS, email spoofing, and port exposure.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        rem_choice = st.radio(
            "Select Target Environment:",
            [
                "Nginx Web Server (`nginx.conf`)",
                "Apache HTTP Server (`.htaccess` / `httpd.conf`)",
                "Caddy Server (`Caddyfile`)",
                "Cloudflare Edge (Workers / Transform Rules)",
                "Node.js / Express (`helmet` Middleware)",
                "DNS Email Security Records (SPF & DMARC TXT)",
                "Linux Firewall (`ufw` & `iptables`)",
            ],
            horizontal=True,
        )

        exposed_ports: list[int] = []
        for p in discovered_ports:
            if isinstance(p, dict) and str(p.get("port", "")).isdigit():
                exposed_ports.append(int(p["port"]))
            elif isinstance(p, int):
                exposed_ports.append(p)

        if "Nginx" in rem_choice:
            code_text = generate_nginx_hardening(findings, target=target)
            lang = "nginx"
            filename = f"nginx_hardening_{target}.conf"
        elif "Apache" in rem_choice:
            code_text = generate_apache_hardening(findings, target=target)
            lang = "apacheconf"
            filename = f"apache_hardening_{target}.conf"
        elif "Caddy" in rem_choice:
            code_text = generate_caddy_hardening(findings, target=target)
            lang = "caddyfile"
            filename = "Caddyfile"
        elif "Cloudflare" in rem_choice:
            code_text = generate_cloudflare_rules(findings, target=target)
            lang = "javascript"
            filename = f"cloudflare_headers_{target}.js"
        elif "Node" in rem_choice:
            code_text = generate_node_helmet(findings)
            lang = "javascript"
            filename = "security-middleware.js"
        elif "DNS" in rem_choice:
            code_text = generate_dns_hardening(target=target)
            lang = "dns"
            filename = f"dns_security_{target}.zone"
        else:
            code_text = generate_firewall_rules(exposed_ports or None)
            lang = "bash"
            filename = f"firewall_rules_{target}.sh"

        st.code(code_text, language=lang)
        
        col_dl1, col_dl2 = st.columns([1, 4])
        with col_dl1:
            st.download_button(
                label=f"💾 Download `{filename}`",
                data=code_text,
                file_name=filename,
                mime="text/plain",
                use_container_width=True,
                type="primary",
            )

    with sub_rem_waf:
        st.caption("Export ready-to-import firewall rules to block exploit scanners and enforce header protections directly at the network edge.")

        waf_env = st.radio(
            "Select WAF Platform:",
            ["AWS WAF (WebACL JSON)", "Cloudflare WAF (Custom Rules Expression)", "ModSecurity / Coraza (.conf)"],
            horizontal=True,
        )

        if "AWS" in waf_env:
            waf_code = generate_aws_waf_json(findings, target=target)
            waf_lang = "json"
            waf_file = f"aws_waf_shield_{target}.json"
        elif "Cloudflare" in waf_env:
            waf_code = generate_cloudflare_waf_rules(findings, target=target)
            waf_lang = "bash"
            waf_file = f"cloudflare_waf_{target}.txt"
        else:
            waf_code = generate_modsecurity_rules(findings, target=target)
            waf_lang = "apacheconf"
            waf_file = f"modsecurity_{target}.conf"

        st.code(waf_code, language=waf_lang)
        st.download_button(
            label=f"💾 Download `{waf_file}`",
            data=waf_code,
            file_name=waf_file,
            mime="text/plain",
            type="primary",
        )

    with sub_rem_sim:
        st.caption("Select the findings you plan to remediate to see how your defensive Threat Score and exposure posture immediately improves.")

        if "simulated_patches" not in st.session_state:
            st.session_state.simulated_patches = set()

        sim_col1, sim_col2 = st.columns([1.6, 1.2])

        with sim_col1:
            st.markdown("#### 🛠️ Check Remediated / Mitigated Items:")
            for idx, f in enumerate(findings):
                title = f.get("title", f"Finding #{idx+1}")
                sev = str(f.get("severity", "Info")).title()
                rank = f.get("rank", idx+1)
                key = f"sim_cb_{rank}_{idx}"
                
                is_patched = st.checkbox(
                    f"#{rank} [{sev.upper()}] {title}",
                    key=key,
                    value=(key in st.session_state.simulated_patches),
                )
                if is_patched:
                    st.session_state.simulated_patches.add(key)
                else:
                    st.session_state.simulated_patches.discard(key)

        with sim_col2:
            sim_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for idx, f in enumerate(findings):
                key = f"sim_cb_{f.get('rank', idx+1)}_{idx}"
                if key not in st.session_state.simulated_patches:
                    sev = str(f.get("severity", "Info")).title()
                    sim_counts[sev if sev in sim_counts else "Info"] += 1

            sim_raw = (
                sim_counts["Critical"] * 30
                + sim_counts["High"] * 18
                + sim_counts["Medium"] * 8
                + sim_counts["Low"] * 3
                + sim_counts["Info"] * 1
            )
            sim_risk = min(100, sim_raw)
            score_diff = risk_score - sim_risk

            st.markdown(
                f"""
                <div class="cyber-card" style="text-align:center;padding:1.5rem;">
                    <div style="font-size:0.85rem;color:#94a3b8;font-weight:700;text-transform:uppercase;">Simulated Threat Posture</div>
                    <div style="font-size:3rem;font-weight:900;color:{'#10b981' if sim_risk < 20 else '#38bdf8' if sim_risk < 50 else '#ef4444'};margin:0.5rem 0;">
                        {sim_risk}/100
                    </div>
                    <div style="font-size:0.95rem;color:#34d399;font-weight:700;">
                        🔻 Risk Reduced by {score_diff} points ({round((score_diff/max(1, risk_score))*100)}% drop)
                    </div>
                    <div style="font-size:0.8rem;color:#94a3b8;margin-top:8px;">
                        Baseline: {risk_score}/100 ➔ Simulated: {sim_risk}/100
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("---")
            st.markdown("**Simulated Remaining Severity Breakdown:**")
            chart_data = {
                "Severity": list(sim_counts.keys()),
                "Remaining Findings": list(sim_counts.values()),
            }
            st.bar_chart(chart_data, x="Severity", y="Remaining Findings")


# ==========================================
# TAB 4: Threat Frameworks & Regulatory Compliance
# ==========================================
with tab_compliance:
    st.markdown("### 🛡️ Threat Frameworks & Regulatory Compliance")
    st.caption("Adversary tactics mapping against MITRE ATT&CK and compliance posture against OWASP Top 10 & NIST CSF.")

    sub_comp_mitre, sub_comp_standards = st.tabs(["🎯 MITRE ATT&CK Matrix", "📜 OWASP Top 10 & NIST CSF"])

    with sub_comp_mitre:
        mitre_data = map_findings_to_mitre(findings)
        kill_chain = mitre_data.get("kill_chain", [])

        # Tactic Progression Pipeline
        kc_cols = st.columns(len(kill_chain))
        for idx, stage in enumerate(kill_chain):
            with kc_cols[idx]:
                count = stage["count"]
                badge_bg = stage["color"] if count > 0 else "rgba(148,163,184,0.15)"
                st.markdown(
                    f"""
                    <div style="background:rgba(15,23,42,0.8);border:1px solid {stage['color']}44;border-top:3px solid {stage['color']};border-radius:8px;padding:10px;text-align:center;">
                        <div style="font-size:1.3rem;">{stage['icon']}</div>
                        <div style="font-weight:700;font-size:0.82rem;color:#f8fafc;margin-top:2px;">{stage['name']}</div>
                        <div style="font-size:0.75rem;color:#94a3b8;margin-top:4px;">
                            <span style="background:{badge_bg}33;color:{stage['color']};padding:2px 8px;border-radius:12px;font-weight:700;">
                                {count} Flags
                            </span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("---")
        st.subheader("🎯 Flagged MITRE ATT&CK Techniques & Defenses")

        flagged_any = False
        for stage in kill_chain:
            if stage["techniques"]:
                flagged_any = True
                st.markdown(f"#### {stage['icon']} {stage['name']} (`{stage['tactic_id']}`)")
                for tech in stage["techniques"]:
                    with st.expander(f"📌 {tech['id']}: {tech['name']} [{tech['relevance']} Priority]"):
                        st.markdown(f"**MITRE Reference:** [{tech['id']} — {tech['name']}]({tech['url']})")
                        st.markdown(f"**🛡️ Defensive Mitigation Strategy:**\n{tech['mitigation']}")
                        
                        matched_f = mitre_data["technique_findings"].get(tech["id"], [])
                        if matched_f:
                            st.markdown("**Correlated Target Findings:**")
                            for mf in matched_f:
                                st.markdown(f"- `[{mf.get('severity', 'Info')}]` {mf.get('title')}")

        if not flagged_any:
            st.info("No active MITRE ATT&CK attack vectors identified.")

    with sub_comp_standards:
        cmp_c1, cmp_c2 = st.columns([1.5, 1.5])
        with cmp_c1:
            st.markdown("#### 🌐 OWASP Top 10 (2021) Breakdown")
            for cat_id, items in comp_data["owasp_categories"].items():
                cat_info = OWASP_CATEGORIES.get(cat_id, {})
                violation_count = len(items)
                status_label = f"❌ {violation_count} Violation(s)" if violation_count else "✅ Compliant"
                with st.expander(f"{cat_info.get('icon', '📌')} {cat_id}: {cat_info.get('title')} — {status_label}"):
                    st.markdown(f"**Standard Risk Level:** `{cat_info.get('risk', 'Medium')}`")
                    if items:
                        st.markdown("**Correlated Target Exposures:**")
                        for it in items:
                            st.markdown(f"- `[{it.get('severity', 'Info')}]` {it.get('title')}")
                    else:
                        st.success("No active findings in this category.")

        with cmp_c2:
            st.markdown("#### 🏛️ NIST Cybersecurity Framework (CSF v2.0)")
            for nist in comp_data["nist_functions"]:
                st.markdown(
                    f"""
                    <div style="background:rgba(15,23,42,0.7);border:1px solid {nist['color']}44;border-left:4px solid {nist['color']};border-radius:8px;padding:10px 14px;margin-bottom:8px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-weight:700;color:#f8fafc;font-size:0.9rem;">[{nist['id']}] {nist['name']}</span>
                            <span style="color:{nist['color']};font-weight:800;font-size:0.85rem;">{nist['status']}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


# ==========================================
# TAB 5: OSINT Reconnaissance & Historical Drift
# ==========================================
with tab_osint:
    st.markdown("### 🌐 Passive Intelligence & Attack Surface Recon")
    st.caption("Non-intrusive metadata gathered from public DNS, TLS certificates, Certificate Transparency, and historical baseline drift.")

    sub_osint_telemetry, sub_osint_diff = st.tabs(
        [
            "🔍 Surface Telemetry & Ports",
            "🔄 Drift & Regression Tracking",
        ]
    )

    with sub_osint_telemetry:
        if assets_data:
            o_tab1, o_tab2, o_tab3, o_tab4 = st.tabs(["📧 DNS & Email Security", "🔒 TLS/SSL Certificate", "📜 CT Subdomains", "🔌 Open Ports"])
            
            with o_tab1:
                dns_data = passive_meta.get("dns", {})
                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    st.markdown("**IP Address Records**")
                    st.write(f"- **A Records:** `{', '.join(dns_data.get('A', [])) or 'None'}`")
                    st.write(f"- **AAAA (IPv6):** `{', '.join(dns_data.get('AAAA', [])) or 'None'}`")
                    st.write(f"- **MX (Mail Servers):** `{', '.join(dns_data.get('MX', [])) or 'None'}`")
                with col_d2:
                    st.markdown("**Email Spoofing Defenses**")
                    spf = dns_data.get("SPF")
                    dmarc = dns_data.get("DMARC")
                    st.markdown(f"- **SPF Record:** {'`' + spf + '`' if spf else '❌ **Missing SPF Record (High Spoofing Risk)**'}")
                    st.markdown(f"- **DMARC Record:** {'`' + dmarc + '`' if dmarc else '❌ **Missing DMARC Policy (High Phishing Risk)**'}")

            with o_tab2:
                tls_data = passive_meta.get("tls", {})
                if tls_data.get("available"):
                    t_col1, t_col2 = st.columns(2)
                    with t_col1:
                        st.write(f"**Subject Common Name:** `{tls_data.get('subject')}`")
                        st.write(f"**Certificate Authority:** `{tls_data.get('issuer')}`")
                        st.write(f"**TLS Protocol:** `{tls_data.get('version')}`")
                    with t_col2:
                        days = tls_data.get("days_remaining", 0)
                        exp_badge = "🟢 Valid" if days > 30 else "⚠️ Expiring Soon"
                        st.write(f"**Valid Until:** `{tls_data.get('notAfter')}` ({days} days remaining — {exp_badge})")
                        st.write(f"**Self-Signed Certificate:** `{'❌ Yes (Untrusted)' if tls_data.get('self_signed') else '✅ No (Signed CA)'}`")
                else:
                    st.info(f"TLS info: {tls_data.get('error', 'Not available for this target or port 443 closed.')}")

            with o_tab3:
                ct_subdomains = passive_meta.get("certificate_transparency", [])
                st.markdown(f"Found **{len(ct_subdomains)}** public subdomains in Certificate Transparency logs (`crt.sh`):")
                if ct_subdomains:
                    st.code("\n".join(ct_subdomains), language="text")
                    st.caption("ℹ️ Note: Subdomains from public CT logs are mapped for reconnaissance awareness only. Active port scanning requires domain verification.")
                else:
                    st.info("No subdomains found in CT logs.")

            with o_tab4:
                ports = assets_data.get("ports", [])
                if ports:
                    st.markdown(f"**Discovered Open TCP Ports ({len(ports)}):**")
                    port_rows = []
                    for p in ports:
                        if isinstance(p, dict):
                            port_rows.append({
                                "Port": p.get("port"),
                                "Service": p.get("service", "unknown"),
                                "Product": p.get("product", "-"),
                                "Version": p.get("version", "-"),
                            })
                        else:
                            port_rows.append({"Port": p, "Service": "open", "Product": "-", "Version": "-"})
                    st.dataframe(port_rows, use_container_width=True)
                else:
                    st.info("No active open ports logged (or scan run in passive mode).")
        else:
            st.info("Run an active or passive scan to populate deep OSINT asset telemetry.")

    with sub_osint_diff:
        st.markdown("### 🔄 Historical Remediation & Regression Analysis")
        st.caption("Compare security reports over time to verify whether fixes took effect and catch newly introduced risks.")

        if len(history_files) > 1:
            prev_options = [f.name for f in history_files if not (selected_history and f.name == selected_history.name)]
            comp_file = st.selectbox("Select Baseline Comparison Scan:", prev_options, key="baseline_diff_sel")
            
            if comp_file:
                comp_path = next((f for f in history_files if f.name == comp_file), None)
                if comp_path:
                    try:
                        baseline_report = json.loads(comp_path.read_text(encoding="utf-8"))
                        diff = diff_reports(report, baseline_report)
                        
                        d_c1, d_c2, d_c3 = st.columns(3)
                        d_c1.metric("🆕 New Vulnerabilities", len(diff["new"]), delta=f"+{len(diff['new'])}" if diff["new"] else "0", delta_color="inverse")
                        d_c2.metric("✅ Remediated Issues", len(diff["resolved"]), delta=f"-{len(diff['resolved'])}" if diff["resolved"] else "0", delta_color="normal")
                        d_c3.metric("🔄 Persisting Issues", len(diff["unchanged"]))

                        dt_new, dt_res, dt_unc = st.tabs(["🆕 New Issues", "✅ Remediated Issues", "🔄 Persisting Issues"])
                        with dt_new:
                            if diff["new"]:
                                for item in diff["new"]:
                                    st.error(f"**[NEW]** {item.get('title')} ({item.get('severity')}) — {item.get('exploitability')}")
                            else:
                                st.success("No new vulnerabilities detected since baseline!")
                        with dt_res:
                            if diff["resolved"]:
                                for item in diff["resolved"]:
                                    st.success(f"**[RESOLVED]** {item.get('title')} ({item.get('severity')})")
                            else:
                                st.info("No previously open vulnerabilities were resolved in this run.")
                        with dt_unc:
                            if diff["unchanged"]:
                                for item in diff["unchanged"]:
                                    st.warning(f"**[PERSISTING]** {item.get('title')} ({item.get('severity')})")
                            else:
                                st.info("No overlapping findings.")
                    except Exception as ex:
                        st.error(f"Failed to diff reports: {ex}")
        else:
            st.info("Run multiple assessments over time to generate historical diffs and remediation metrics.")


# ==========================================
# TAB 6: AI SOC Intelligence & SIEM Exports
# ==========================================
with tab_copilot:
    sub_copilot_chat, sub_copilot_export = st.tabs(
        [
            "🧠 AI SOC Copilot",
            "📥 Reports & SIEM Export",
        ]
    )

    with sub_copilot_chat:
        st.markdown("### 🤖 Interactive AI SOC Security Copilot")
        st.caption("Ask our AI security intelligence engine questions about findings, attack vectors, or custom remediation strategies.")

        st.markdown(
            """
            <div class="feature-banner">
                <div style="font-weight:700;color:#38bdf8;font-size:1.05rem;margin-bottom:4px;">
                    🧠 Instant Security Analyst Q&A
                </div>
                <div style="color:#94a3b8;font-size:0.88rem;">
                    Choose a pre-baked one-click prompt or type any custom security question below to receive context-aware blue-team advice.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if "copilot_answer" not in st.session_state:
            st.session_state.copilot_answer = ""

        q_col1, q_col2, q_col3, q_col4 = st.columns(4)
        with q_col1:
            if st.button("📊 CISO Executive Brief", use_container_width=True):
                st.session_state.copilot_user_input = "Generate an executive cyber risk briefing for CISO and senior management."
        with q_col2:
            if st.button("⚡ Top 3 Quick Wins", use_container_width=True):
                st.session_state.copilot_user_input = "What are the top 3 quick-win fixes that provide the highest immediate security impact & risk reduction?"
        with q_col3:
            if st.button("🧪 Bash Verification Script", use_container_width=True):
                st.session_state.copilot_user_input = "Generate a comprehensive bash script to test and verify these fixes."
        with q_col4:
            if st.button("🎭 Simulate Attack Path", use_container_width=True):
                st.session_state.copilot_user_input = "Simulate how a threat actor might attempt to chain these attack surface exposures."

        st.text_area(
            "Ask AI SOC Copilot a custom question:",
            placeholder="e.g. How do I harden my reverse proxy against clickjacking and MIME sniffing?",
            key="copilot_user_input",
            height=90,
        )
        MAX_BEDROCK_QUERIES_PER_SESSION = int(os.getenv("MAX_BEDROCK_QUERIES_PER_SESSION", "20"))
        current_calls = st.session_state.get("bedrock_query_count", 0)
        remaining_calls = max(0, MAX_BEDROCK_QUERIES_PER_SESSION - current_calls)

        st.caption(f"🛡️ Demo Safety Guardrail: {remaining_calls}/{MAX_BEDROCK_QUERIES_PER_SESSION} Bedrock queries remaining in this session.")

        if st.button("🚀 Ask SOC Copilot", type="primary"):
            copilot_query = str(st.session_state.get("copilot_user_input") or "").strip()
            if not copilot_query:
                st.warning("Enter a question or choose a one-click prompt first.")
            elif current_calls >= MAX_BEDROCK_QUERIES_PER_SESSION:
                st.error(
                    f"🛑 Demo Rate Limit Reached: Maximum of {MAX_BEDROCK_QUERIES_PER_SESSION} Bedrock queries "
                    "allowed per session to prevent runaway API spend. Please refresh your session or log in as administrator."
                )
            else:
                st.session_state.bedrock_query_count = current_calls + 1
                with st.spinner("AI SOC Analyst reasoning with report telemetry..."):
                    st.session_state.copilot_answer = query_copilot(copilot_query, report)

        if st.session_state.copilot_answer:
            st.markdown(st.session_state.copilot_answer)

    with sub_copilot_export:
        st.markdown("### 📥 Executive Reports & SIEM Integration")
        st.caption("Download formatted reports for technical stakeholders or export directly to SIEM pipelines (Splunk / Elastic) and Webhooks.")

        exp_col1, exp_col2, exp_col3 = st.columns(3)
        
        with exp_col1:
            st.markdown(
                """
                <div class="cyber-card" style="text-align:center;">
                    <div style="font-size:2rem;margin-bottom:0.5rem;">📄</div>
                    <div style="font-weight:700;color:#f8fafc;margin-bottom:0.5rem;">HTML Executive Report</div>
                    <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:1rem;">Standalone interactive HTML briefing with full finding breakdown</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            html_bytes = generate_html_report(report)
            st.download_button(
                label="Download HTML Briefing",
                data=html_bytes,
                file_name=f"security_assessment_{target}.html",
                mime="text/html",
                use_container_width=True,
                type="primary",
            )

        with exp_col2:
            st.markdown(
                """
                <div class="cyber-card" style="text-align:center;">
                    <div style="font-size:2rem;margin-bottom:0.5rem;">📊</div>
                    <div style="font-weight:700;color:#f8fafc;margin-bottom:0.5rem;">CSV Findings Matrix</div>
                    <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:1rem;">Spreadsheet-ready findings with formula injection protection</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            csv_bytes = generate_csv_report(report)
            st.download_button(
                label="Download CSV Matrix",
                data=csv_bytes,
                file_name=f"security_findings_{target}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        with exp_col3:
            st.markdown(
                """
                <div class="cyber-card" style="text-align:center;">
                    <div style="font-size:2rem;margin-bottom:0.5rem;">💾</div>
                    <div style="font-weight:700;color:#f8fafc;margin-bottom:0.5rem;">Raw JSON Schema</div>
                    <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:1rem;">Direct machine-readable JSON for SIEM / CI/CD integration</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            raw_json_str = json.dumps(report, indent=2)
            st.download_button(
                label="Download Raw JSON",
                data=raw_json_str,
                file_name=f"report_{target}.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("---")
        st.markdown("### 🔌 SIEM Ingestion & Live Webhook Alerting")
        
        siem_col1, siem_col2 = st.columns(2)
        
        with siem_col1:
            st.markdown("**ArcSight / Splunk Common Event Format (CEF)**")
            cef_data = generate_cef_export(report)
            st.download_button(
                "Download CEF Syslog Format",
                data=cef_data,
                file_name=f"findings_{target}.cef",
                mime="text/plain",
                use_container_width=True,
            )
            st.markdown("**Elastic Common Schema (ECS JSON-Lines)**")
            ecs_data = generate_ecs_export(report)
            st.download_button(
                "Download ECS JSONL Format",
                data=ecs_data,
                file_name=f"findings_{target}.ecs.jsonl",
                mime="application/x-ndjson",
                use_container_width=True,
            )

        with siem_col2:
            st.markdown("**🚨 Webhook Alert Dispatcher (Slack / Discord / Teams)**")
            webhook_input = st.text_input("Webhook URL", placeholder="https://hooks.slack.com/services/...", key="wh_url_input")
            if st.button("📤 Send Test SOC Alert to Webhook", use_container_width=True):
                if webhook_input:
                    with st.spinner("Dispatching webhook payload..."):
                        ok, msg = send_webhook_alert(webhook_input.strip(), report)
                        if ok:
                            st.success(msg)
                        else:
                            st.error(msg)
                else:
                    st.error("Please provide a webhook URL.")

