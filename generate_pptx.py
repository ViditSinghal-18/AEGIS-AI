"""
AEGIS-AI: Automated PowerPoint Presentation Generator
Generates a professional 10-slide PowerPoint (.pptx) presentation for AEGIS-AI.
Requires: pip install python-pptx
"""

import sys

try:
    from pptx import Presentation
    from pptx.util import Inches, Pt
    from pptx.enum.text import PP_ALIGN
    from pptx.dml.color import RGBColor
    from pptx.enum.shapes import MSO_SHAPE
except ImportError:
    print("[!] python-pptx is not installed.")
    print("[*] Install it with: pip install python-pptx")
    sys.exit(1)

def build_presentation(filename="AEGIS_AI_Presentation.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Theme Colors
    BG_COLOR = RGBColor(5, 8, 17)        # Dark #050811
    CYAN = RGBColor(0, 240, 255)         # Neon Cyan #00f0ff
    ROSE = RGBColor(255, 51, 102)        # Rose Red #ff3366
    WHITE = RGBColor(248, 250, 252)      # Off-white
    MUTED = RGBColor(148, 163, 184)      # Muted slate
    CARD_BG = RGBColor(15, 23, 42)       # Card #0f172a
    EMERALD = RGBColor(16, 185, 129)     # Green

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.fill.background()
        return bg

    def add_header(slide, tag_text, title_text):
        # Tag
        tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.5), Inches(0.4))
        tf = tag_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"● {tag_text.upper()}"
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = CYAN

        # Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.9), Inches(11.5), Inches(0.8))
        tf2 = title_box.text_frame
        tf2.word_wrap = True
        p2 = tf2.paragraphs[0]
        p2.text = title_text
        p2.font.size = Pt(26)
        p2.font.bold = True
        p2.font.color.rgb = WHITE

    # -------------------------------------------------------------
    # SLIDE 1: Title Slide
    # -------------------------------------------------------------
    blank_layout = prs.slide_layouts[6]
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    tbox = s1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(3.5))
    tf = tbox.text_frame
    p = tf.paragraphs[0]
    p.text = "● AUTONOMOUS EXPOSURE MANAGEMENT PLATFORM"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = CYAN

    p2 = tf.add_paragraph()
    p2.text = "AEGIS-AI"
    p2.font.size = Pt(48)
    p2.font.bold = True
    p2.font.color.rgb = WHITE

    p3 = tf.add_paragraph()
    p3.text = "Continuous Threat Exposure Management (CTEM) & Explainable RBVM"
    p3.font.size = Pt(18)
    p3.font.color.rgb = CYAN

    p4 = tf.add_paragraph()
    p4.text = "\nPresenter: Vidit Singhal | Cluster: Cloud Security & Ethical AI"
    p4.font.size = Pt(13)
    p4.font.color.rgb = MUTED

    p5 = tf.add_paragraph()
    p5.text = "Live Demo: https://aegis-ai-khaki-eight.vercel.app  |  GitHub: ViditSinghal-18/AEGIS-AI"
    p5.font.size = Pt(12)
    p5.font.color.rgb = EMERALD

    # -------------------------------------------------------------
    # SLIDE 2: The Alert Fatigue Crisis
    # -------------------------------------------------------------
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Industry Challenge", "The Alert Fatigue Crisis in Modern SecOps")

    cards_s2 = [
        ("10,000+ Theoretical Alerts", "Average enterprise receives thousands of CVE alerts monthly. Teams waste weeks triaging harmless issues.", ROSE),
        ("85%+ Unreachable Flaws", "Over 85% of reported dependencies sit in dead internal code that external attackers cannot trigger.", ROSE),
        ("Blind CVSS Reliance", "CVSS 9.8 treated as crisis-level critical even when completely unexposed and lacking wild exploits.", ROSE)
    ]
    for idx, (title, desc, col) in enumerate(cards_s2):
        card = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.9), Inches(2.2), Inches(3.6), Inches(3.8))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = col
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(18)
        p.font.bold = True
        p.font.color.rgb = col

        p2 = tf.add_paragraph()
        p2.text = f"\n{desc}"
        p2.font.size = Pt(13)
        p2.font.color.rgb = WHITE

    # -------------------------------------------------------------
    # SLIDE 3: The Smart Hospital Analogy
    # -------------------------------------------------------------
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Conceptual Framing", "The Clueless Guard vs. The Context-Aware Sentinel")

    # Clueless Guard
    c1 = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.0), Inches(5.6), Inches(4.5))
    c1.fill.solid()
    c1.fill.fore_color.rgb = CARD_BG
    c1.line.color.rgb = ROSE
    c1.line.width = Pt(1.5)
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "❌ Traditional Scanner (The Clueless Guard)\n"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = ROSE
    p2 = tf1.add_paragraph()
    p2.text = (
        "• Walks into a hospital with a generic handbook of product recalls.\n\n"
        "• Dumps a 400-page binder of 5,000 alerts on the Doctor's desk:\n"
        "  'A filing cabinet lock on floor 4 has a 1998 flaw, and the basement microwave has a loose pin!'\n\n"
        "• Overwhelmed, staff ignores the binder, leaving the emergency street exit door wide open."
    )
    p2.font.size = Pt(13)
    p2.font.color.rgb = WHITE

    # Context Sentinel
    c2 = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(2.0), Inches(5.6), Inches(4.5))
    c2.fill.solid()
    c2.fill.fore_color.rgb = CARD_BG
    c2.line.color.rgb = CYAN
    c2.line.width = Pt(1.5)
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "✅ AEGIS-AI (The Context-Aware Sentinel)\n"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p2 = tf2.add_paragraph()
    p2.text = (
        "• Inspects what is actually exposed to the public highway (Port 3000 running Express.js).\n\n"
        "• Traces code execution paths and tells the team:\n"
        "  'Out of 5,000 theoretical bugs, only ONE is reachable from the public internet with active weaponization (CVE-2024-29041). Fix this today, ignore the microwave!'\n\n"
        "• Result: 60.0% Alert Noise Reduction & ~14.5 Hours Saved per sprint."
    )
    p2.font.size = Pt(13)
    p2.font.color.rgb = WHITE

    # -------------------------------------------------------------
    # SLIDE 4: 4-Stage Intelligence Pipeline
    # -------------------------------------------------------------
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Technical Architecture", "The 4-Stage Automated Intelligence Pipeline")

    stages = [
        ("STAGE 1", "Perimeter Discovery", "discovery.py", "TCP SYN socket probes (80, 443, 3000) & HTTP service fingerprinting."),
        ("STAGE 2", "Threat Correlation", "correlate.py", "Queries Google OSV & NIST NVD for running dependencies, normalizing GHSA/CVE IDs."),
        ("STAGE 3", "Explainable RBVM", "prioritize.py", "Blends FIRST.org EPSS exploit likelihood, AST reachability, and CISA KEV directives."),
        ("STAGE 4", "Universal Auditor", "scanner_online.py", "External evaluation of live websites (TLS 1.3, HSTS, CSP, WAF detection, A+ to F).")
    ]
    for idx, (stg, name, file, desc) in enumerate(stages):
        card = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 2.95), Inches(2.2), Inches(2.75), Inches(4.2))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = CYAN if idx == 2 else MUTED
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = stg
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = CYAN

        p2 = tf.add_paragraph()
        p2.text = name
        p2.font.size = Pt(15)
        p2.font.bold = True
        p2.font.color.rgb = WHITE

        p3 = tf.add_paragraph()
        p3.text = f"{file}\n"
        p3.font.size = Pt(11)
        p3.font.color.rgb = CYAN

        p4 = tf.add_paragraph()
        p4.text = desc
        p4.font.size = Pt(12)
        p4.font.color.rgb = MUTED

    # -------------------------------------------------------------
    # SLIDE 5: Mathematical Explainability Formula
    # -------------------------------------------------------------
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Mathematical Explainability", "The Multi-Factor Risk Formulation")

    # Formula Box
    fbox = s5.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(2.0), Inches(11.7), Inches(1.3))
    fbox.fill.solid()
    fbox.fill.fore_color.rgb = RGBColor(2, 4, 8)
    fbox.line.color.rgb = CYAN
    fbox.line.width = Pt(1.5)
    tf = fbox.text_frame
    p = tf.paragraphs[0]
    p.text = "Risk Score = (0.35 × CVSS) + (0.30 × Reachability) + (0.25 × EPSS) + (0.10 × Criticality)"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.alignment = PP_ALIGN.CENTER

    weights = [
        ("Base CVSS (35%)", "Theoretical vulnerability severity from NIST NVD."),
        ("Reachability (30%)", "AST execution trace from open ingress socket to vulnerable sink."),
        ("FIRST.org EPSS (25%)", "Live daily weaponization probability in the wild (API v1.0)."),
        ("Asset Criticality (10%)", "Business sensitivity: Customer database vs. sandbox environment.")
    ]
    for idx, (w_name, w_desc) in enumerate(weights):
        card = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 2.95), Inches(3.7), Inches(2.75), Inches(2.8))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = CYAN
        card.line.width = Pt(1)

        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = w_name
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = WHITE

        p2 = tf.add_paragraph()
        p2.text = f"\n{w_desc}"
        p2.font.size = Pt(12)
        p2.font.color.rgb = MUTED

    # -------------------------------------------------------------
    # SLIDE 6: 3D Threat Globe & Live Reconnaissance
    # -------------------------------------------------------------
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Interactive Visualization", "Luminescent 3D Cyber Threat Globe & Telemetry Stream")

    g1 = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.0), Inches(5.6), Inches(4.5))
    g1.fill.solid()
    g1.fill.fore_color.rgb = CARD_BG
    g1.line.color.rgb = CYAN
    g1.line.width = Pt(1.5)
    tf1 = g1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "🌍 Three.js WebGL Cyber Globe\n"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p2 = tf1.add_paragraph()
    p2.text = (
        "• Emissive Inner Core with 1,800 coordinate particle points.\n\n"
        "• Global Threat Origin Vectors:\n"
        "  - Moscow (APT28 / Fancy Bear)\n"
        "  - Beijing (Volt Typhoon Ingress)\n"
        "  - London (External C2 Relay)\n"
        "  - Tokyo (Mirai Botnet Swarm)\n\n"
        "• Interactive Raycasting HUD: Hover or click any node to pin live telemetry (IP, ASN, MITRE TTP, Payload).\n\n"
        "• 2D Canvas Fail-Safe Fallback: Guarantees 60 FPS on any device."
    )
    p2.font.size = Pt(12)
    p2.font.color.rgb = WHITE

    g2 = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(2.0), Inches(5.6), Inches(4.5))
    g2.fill.solid()
    g2.fill.fore_color.rgb = CARD_BG
    g2.line.color.rgb = CYAN
    g2.line.width = Pt(1.5)
    tf2 = g2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "💻 Live CTEM Telemetry Stream\n"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p2 = tf2.add_paragraph()
    p2.text = (
        "• Expandable Recon Console: Streams real-time progress.\n\n"
        "• Phase 1: Ingress Discovery (TCP Port 3000 Open [2ms]).\n"
        "• Phase 2: Perimeter Fingerprint (Express 4.17.1 identified).\n"
        "• Phase 3: FIRST.org EPSS Sync (CVE-2024-29041 54.6th %ile).\n"
        "• Phase 4: AST Semantic Trace (GET /redirect ➔ res.location).\n"
        "• Phase 5: False-Positive Filter (3 unreachable suppressed).\n\n"
        "• Result: Exposure 72.5/100 · DEFCON 4 · 1 P1 Action Required."
    )
    p2.font.size = Pt(12)
    p2.font.color.rgb = WHITE

    # -------------------------------------------------------------
    # SLIDE 7: Threat Matrix & Attack Radar
    # -------------------------------------------------------------
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Visual Analytics", "4-Quadrant Threat Exposure Matrix & 5-Axis Attack Radar")

    t1 = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.0), Inches(5.6), Inches(4.5))
    t1.fill.solid()
    t1.fill.fore_color.rgb = CARD_BG
    t1.line.color.rgb = CYAN
    t1.line.width = Pt(1.5)
    tf1 = t1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "📊 4-Quadrant Threat Exposure Matrix\n"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p2 = tf1.add_paragraph()
    p2.text = (
        "• Scatter Bubble Plot: Plots EPSS Percentile (X) vs. CVSS Severity (Y).\n\n"
        "• Top-Right Quadrant: Urgent Action Zone (flaws that are both high-severity AND actively exploited).\n\n"
        "• Bubble Radius: Scaled dynamically based on network reachability.\n\n"
        "• Interactive Focus: Clicking any bubble synchronizes the 5-axis attack radar immediately."
    )
    p2.font.size = Pt(13)
    p2.font.color.rgb = WHITE

    t2 = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(2.0), Inches(5.6), Inches(4.5))
    t2.fill.solid()
    t2.fill.fore_color.rgb = CARD_BG
    t2.line.color.rgb = CYAN
    t2.line.width = Pt(1.5)
    tf2 = t2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "🎯 5-Axis Exploitability Radar\n"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p2 = tf2.add_paragraph()
    p2.text = (
        "• Multi-Vector Polygon Spider Chart comparing 5 axes:\n"
        "  1. Base CVSS Severity (Theoretical flaw impact)\n"
        "  2. FIRST.org EPSS (Wild weaponization proof)\n"
        "  3. Environmental Reachability (AST socket trace)\n"
        "  4. Asset Criticality (Production vs sandbox)\n"
        "  5. CISA KEV Urgency (Federal BOD 22-01 directives)\n\n"
        "• Plain-English explanations generated for executive review."
    )
    p2.font.size = Pt(13)
    p2.font.color.rgb = WHITE

    # -------------------------------------------------------------
    # SLIDE 8: Enterprise Governance & SBOM
    # -------------------------------------------------------------
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Enterprise Compliance", "Regulatory Scorecards & CycloneDX v1.5 SBOM")

    comps = [
        ("PCI-DSS 4.0", "100% (Grade A)", "Req 6.2.4 (30-day patch SLA) & Req 1.3.1 (Perimeter Protocol Isolation)."),
        ("NIST CSF 2.0", "100% (Grade B)", "PR.PS-01 (Configuration management) & DE.CM-01 (Network monitoring)."),
        ("ISO 27001", "75% (Grade B+)", "Controls A.8.8 (Vulnerability management) & A.8.20 (Network security)."),
        ("SOC 2 Type II", "100% (Grade B-)", "Criteria CC6.6 & CC7.1 (Logical boundary perimeter defense).")
    ]
    for idx, (std, score, desc) in enumerate(comps):
        card = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 2.95), Inches(2.2), Inches(2.75), Inches(2.8))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = EMERALD
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = std
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = WHITE

        p2 = tf.add_paragraph()
        p2.text = score
        p2.font.size = Pt(16)
        p2.font.bold = True
        p2.font.color.rgb = EMERALD

        p3 = tf.add_paragraph()
        p3.text = f"\n{desc}"
        p3.font.size = Pt(11)
        p3.font.color.rgb = MUTED

    s_box = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(5.3), Inches(11.7), Inches(1.5))
    s_box.fill.solid()
    s_box.fill.fore_color.rgb = CARD_BG
    s_box.line.color.rgb = CYAN
    s_box.line.width = Pt(1)
    tf = s_box.text_frame
    p = tf.paragraphs[0]
    p.text = "📦 CycloneDX v1.5 Software Bill of Materials (SBOM) Integration"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p2 = tf.add_paragraph()
    p2.text = "Exports standardized machine-readable JSON SBOMs including cryptographic SHA hashes, dependency licensing, and component lineage to satisfy Executive Order 14028 supply chain requirements."
    p2.font.size = Pt(12)
    p2.font.color.rgb = WHITE

    # -------------------------------------------------------------
    # SLIDE 9: Quantitative Benchmark Results
    # -------------------------------------------------------------
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Measurable Outcomes", "Quantitative Security & Efficiency Results")

    res_cards = [
        ("60.0%", "Noise Suppression", "Of theoretical vulnerability alerts safely filtered via AST reachability proofs.", EMERALD),
        ("~14.5 hrs", "Sprint Time Saved", "Developer and SecOps hours saved per two-week engineering sprint.", CYAN),
        ("< 24 hrs", "MTTR for Weaponized Flaws", "Mean Time to Remediate high-exposure CISA KEV vulnerabilities.", RGBColor(59, 130, 246))
    ]
    for idx, (num, label, desc, col) in enumerate(res_cards):
        card = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.9), Inches(2.2), Inches(3.6), Inches(4.0))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = col
        card.line.width = Pt(2)

        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = num
        p.font.size = Pt(36)
        p.font.bold = True
        p.font.color.rgb = col

        p2 = tf.add_paragraph()
        p2.text = label.upper()
        p2.font.size = Pt(12)
        p2.font.bold = True
        p2.font.color.rgb = WHITE

        p3 = tf.add_paragraph()
        p3.text = f"\n{desc}"
        p3.font.size = Pt(13)
        p3.font.color.rgb = MUTED

    # -------------------------------------------------------------
    # SLIDE 10: Conclusion & Live Demonstration
    # -------------------------------------------------------------
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Summary & Live Demonstration", "Experience AEGIS-AI in Production")

    c_box = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.0), Inches(11.7), Inches(4.5))
    c_box.fill.solid()
    c_box.fill.fore_color.rgb = CARD_BG
    c_box.line.color.rgb = CYAN
    c_box.line.width = Pt(2)

    tf = c_box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "🌐 Live Cloud Platform: https://aegis-ai-khaki-eight.vercel.app\n"
    p.font.size = Pt(20)
    p.font.bold = True
    p.font.color.rgb = CYAN

    p2 = tf.add_paragraph()
    p2.text = (
        "• Global Production Deployment: Hosted serverless on Vercel with zero cold-start delay.\n\n"
        "• Interactive 3D Cyber Threat Globe with spatial raycast HUD overlays.\n\n"
        "• Live Universal Web Security Assessor (Audit any public domain: owasp.org, google.com).\n\n"
        "• Open Source GitHub Repository: https://github.com/ViditSinghal-18/AEGIS-AI\n\n"
        "Thank you! We are now open for questions and interactive evaluation."
    )
    p2.font.size = Pt(14)
    p2.font.color.rgb = WHITE

    prs.save(filename)
    print(f"[+] Successfully generated PowerPoint presentation: {filename}")

if __name__ == "__main__":
    build_presentation()
