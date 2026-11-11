import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

class TestUIAndStaticAssets:
    def test_index_page_loads_and_has_security_headers(self, client):
        res = client.get("/")
        assert res.status_code == 200
        html = res.data.decode("utf-8")
        assert "AEGIS-AI" in html
        assert "/static/css/styles.css" in html
        assert "/static/js/app.js" in html
        assert "/static/js/globe.js" in html
        assert "remediationModal" in html
        assert "chkActiveScan" in html
        
        # Verify Security Headers
        assert "Content-Security-Policy" in res.headers
        assert "default-src 'self'" in res.headers["Content-Security-Policy"]
        assert res.headers["X-Content-Type-Options"] == "nosniff"
        assert res.headers["X-Frame-Options"] == "DENY"
        assert res.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_css_stylesheet_serves_valid_css(self, client):
        res = client.get("/static/css/styles.css")
        assert res.status_code == 200
        css = res.data.decode("utf-8")
        assert ":root" in css
        assert ".dark-dashboard" in css or ".brand-box" in css
        assert "@media (prefers-reduced-motion" in css

    def test_modular_js_modules_serve_successfully(self, client):
        modules = [
            ("utils.js", "escapeHtml"),
            ("globe.js", "AegisGlobe"),
            ("charts.js", "AegisCharts"),
            ("telemetry.js", "AegisTelemetry"),
            ("verification.js", "AegisVerification"),
            ("copilot.js", "AegisCopilot"),
            ("app.js", "AegisApp"),
        ]
        for filename, expected_token in modules:
            res = client.get(f"/static/js/{filename}")
            assert res.status_code == 200, f"Failed to serve /static/js/{filename}"
            content = res.data.decode("utf-8")
            assert expected_token in content, f"Token '{expected_token}' missing from {filename}"
