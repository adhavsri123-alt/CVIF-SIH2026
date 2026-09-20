"""Targeted Phase 11 Regression Tests: Frontend Serving & Security Headers.

Verifies:
1. test_frontend_dist_exists_or_fails_cleanly
2. test_root_serves_react_app
3. test_spa_route_fallback
4. test_api_routes_not_swallowed_by_spa
5. test_static_path_traversal_blocked
6. test_frontend_security_headers
7. test_csp_present
8. test_backend_source_not_exposed
9. test_evidence_store_not_exposed
10. test_sqlite_not_exposed
11. test_missing_frontend_dist_behavior
12. test_typescript_build

All tests are strictly deterministic, isolated, and offline.
"""

from pathlib import Path
import re
import pytest
from fastapi.testclient import TestClient

from cvif.api.frontend import (
    CSP_POLICY,
    FRONTEND_SECURITY_HEADERS,
    SPA_ROUTES,
    get_frontend_dist_dir,
)
from cvif.api.main import create_app
from cvif.core.config import AppConfig


@pytest.fixture
def app_with_dist(tmp_path):
    """Create a FastAPI instance wired to the actual frontend/dist."""
    cfg = AppConfig()
    cfg.storage.data_dir = tmp_path / "data"
    cfg.storage.catalog_db_path = tmp_path / "data" / "db" / "catalogue.db"
    cfg.audit.audit_dir = tmp_path / "data" / "audit"
    cfg.audit.audit_log_path = tmp_path / "data" / "audit" / "audit.jsonl"
    cfg.audit.index_db_path = tmp_path / "data" / "db" / "audit_index.db"
    cfg.keystore.keystore_dir = tmp_path / "data" / "keys"
    cfg.keystore.keystore_db_path = tmp_path / "data" / "db" / "keystore.db"
    cfg.evidence.evidence_dir = tmp_path / "data" / "evidence_store"
    cfg.evidence.metadata_db_path = tmp_path / "data" / "evidence_store" / "metadata.db"
    cfg.evidence.sessions_dir = tmp_path / "data" / "evidence_store" / "sessions"

    application = create_app(config=cfg)
    return application


@pytest.fixture
def client(app_with_dist):
    with TestClient(app_with_dist) as test_client:
        yield test_client


# 1. test_frontend_dist_exists_or_fails_cleanly
def test_frontend_dist_exists_or_fails_cleanly():
    """Verify that frontend/dist exists with index.html in the repository."""
    dist_dir = get_frontend_dist_dir()
    assert dist_dir.is_dir(), f"Frontend dist directory not found at {dist_dir}"
    index_html = dist_dir / "index.html"
    assert index_html.is_file(), f"index.html not found in {dist_dir}"

    content = index_html.read_text(encoding="utf-8")
    assert "<div id=\"root\"></div>" in content or 'id="root"' in content
    assert "CVIF" in content


# 2. test_root_serves_react_app
def test_root_serves_react_app(client):
    """Verify GET / serves the compiled React application index.html."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert '<div id="root"></div>' in resp.text
    assert "CVIF" in resp.text


# 3. test_spa_route_fallback
def test_spa_route_fallback(client):
    """Verify that all client-side SPA routes serve index.html for direct navigation."""
    test_routes = [
        "/dashboard",
        "/overview",
        "/dataset",
        "/model",
        "/provenance",
        "/shift",
        "/assurance",
        "/evidence",
        "/audit",
    ]
    for route in test_routes:
        resp = client.get(route)
        assert resp.status_code == 200, f"SPA route {route} failed with {resp.status_code}"
        assert "text/html" in resp.headers.get("content-type", "")
        assert '<div id="root"></div>' in resp.text


# 4. test_api_routes_not_swallowed_by_spa
def test_api_routes_not_swallowed_by_spa(client):
    """CRITICAL: Verify API routes are NEVER swallowed by SPA fallback.

    - Valid API route returns JSON 200
    - Non-existent API route returns 404 JSON, NOT index.html
    """
    # Valid API route
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    assert health_resp.json().get("status") in ("HEALTHY", "DEGRADED")

    # Non-existent API route must NOT return index.html
    missing_api = client.get("/api/v1/does-not-exist")
    assert missing_api.status_code == 404
    assert '<div id="root"></div>' not in missing_api.text
    assert "<!DOCTYPE html>" not in missing_api.text
    # Must be JSON response
    body = missing_api.json()
    assert "detail" in body or "error_code" in body

    # Unknown prefix under /api
    unknown_api = client.get("/api/unknown")
    assert unknown_api.status_code == 404
    assert '<div id="root"></div>' not in unknown_api.text


# 5. test_static_path_traversal_blocked
def test_static_path_traversal_blocked(client):
    """Verify path traversal attacks cannot escape frontend/dist."""
    traversal_paths = [
        "/assets/../../src/cvif/core/config.py",
        "/assets/%2e%2e/%2e%2e/src/cvif/core/config.py",
        "/assets/..%2f..%2fsrc/cvif/core/config.py",
        "/..%2f..%2fetc/passwd",
        "/assets/../../data/db/catalogue.db",
    ]
    for path in traversal_paths:
        resp = client.get(path)
        assert resp.status_code in (400, 404), (
            f"Traversal path {path} returned unexpected status {resp.status_code}"
        )
        assert "class AppConfig" not in resp.text
        assert "SQLite format 3" not in resp.text


# 6. test_frontend_security_headers
def test_frontend_security_headers(client):
    """Verify defensive browser headers are present on frontend responses."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers.get("permissions-policy", "")


# 7. test_csp_present
def test_csp_present(client):
    """Verify Content-Security-Policy header restricts external script/network execution."""
    resp = client.get("/")
    assert resp.status_code == 200
    csp = resp.headers.get("content-security-policy", "")
    assert csp, "Content-Security-Policy header is missing"

    # Verify strict policies
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "font-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp

    # Ensure no external domains are whitelisted
    assert "http://" not in csp
    assert "https://" not in csp
    assert "googleapis" not in csp
    assert "cloudflare" not in csp
    assert "unpkg" not in csp


# 8. test_backend_source_not_exposed
def test_backend_source_not_exposed(client):
    """Verify backend Python source files cannot be read via static serving."""
    targets = [
        "/src/cvif/core/config.py",
        "/src/cvif/api/main.py",
        "/src/cvif/api/frontend.py",
    ]
    for target in targets:
        resp = client.get(target)
        assert resp.status_code == 404, f"Source path {target} returned {resp.status_code}"
        assert "import" not in resp.text
        assert "def create_app" not in resp.text


# 9. test_evidence_store_not_exposed
def test_evidence_store_not_exposed(client):
    """Verify evidence store files and metadata databases cannot be accessed via static routes."""
    targets = [
        "/data/evidence_store/metadata.db",
        "/data/evidence_store/sessions",
    ]
    for target in targets:
        resp = client.get(target)
        assert resp.status_code == 404
        assert "SQLite format 3" not in resp.text


# 10. test_sqlite_not_exposed
def test_sqlite_not_exposed(client):
    """Verify SQLite database files cannot be downloaded via static routes."""
    targets = [
        "/data/db/catalogue.db",
        "/data/db/keystore.db",
        "/data/db/audit_index.db",
    ]
    for target in targets:
        resp = client.get(target)
        assert resp.status_code == 404
        assert "SQLite format 3" not in resp.text


# 11. test_missing_frontend_dist_behavior
def test_missing_frontend_dist_behavior(tmp_path):
    """Verify clear and safe failure when frontend/dist is missing or unbuilt."""
    non_existent = tmp_path / "non_existent_dist"
    app_missing = create_app(frontend_dist=non_existent)

    with TestClient(app_missing) as client_missing:
        # GET / must fail clearly with 404
        resp = client_missing.get("/")
        assert resp.status_code == 404
        assert "not found" in resp.json().get("detail", "").lower()

        # GET /dashboard must fail clearly with 404
        resp_dash = client_missing.get("/dashboard")
        assert resp_dash.status_code == 404

        # CRITICAL: API routes must still function even when frontend is missing
        health = client_missing.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json().get("status") == "HEALTHY"


# 12. test_typescript_build
def test_typescript_build():
    """Verify frontend build integrity, strict tsconfig, and air-gap compliance."""
    repo_root = Path(__file__).resolve().parents[2]
    frontend_dir = repo_root / "frontend"
    src_dir = frontend_dir / "src"

    # Verify tsconfig strict settings
    tsconfig_path = frontend_dir / "tsconfig.json"
    assert tsconfig_path.is_file(), "frontend/tsconfig.json missing"
    tsconfig_content = tsconfig_path.read_text(encoding="utf-8")
    assert '"noUnusedLocals": true' in tsconfig_content
    assert '"noUnusedParameters": true' in tsconfig_content

    # Scan all frontend source files for external references (air-gap)
    src_forbidden = [
        r"https?://",
        r"fonts\.googleapis\.com",
        r"cdn\.",
        r"eval\(",
        r"dangerouslySetInnerHTML",
    ]
    for ext in ("*.ts", "*.tsx", "*.css", "*.html"):
        for src_file in src_dir.rglob(ext):
            content = src_file.read_text(encoding="utf-8")
            for pattern in src_forbidden:
                matches = re.findall(pattern, content, re.IGNORECASE)
                assert not matches, f"Forbidden pattern '{pattern}' found in source {src_file.name}: {matches}"

    # Verify production build artifacts in frontend/dist
    dist_dir = get_frontend_dist_dir()
    assert dist_dir.is_dir(), f"Frontend dist directory missing at {dist_dir}"
    assert (dist_dir / "index.html").is_file(), "dist/index.html missing"

    assets_dir = dist_dir / "assets"
    assert assets_dir.is_dir()
    js_files = list(assets_dir.glob("*.js"))
    assert len(js_files) > 0, "No compiled JS bundle found in frontend/dist/assets"
    css_files = list(assets_dir.glob("*.css"))
    assert len(css_files) > 0, "No compiled CSS bundle found in frontend/dist/assets"

    # Verify dist does not contain external CDNs, fonts, or third-party trackers
    dist_forbidden = [
        r"fonts\.googleapis\.com",
        r"google-analytics",
        r"googletagmanager",
        r"sentry\.io",
        r"mixpanel",
        r"segment\.io",
        r"cloudflare\.com",
        r"unpkg\.com",
        r"jsdelivr\.net",
    ]
    for js_file in js_files:
        content = js_file.read_text(encoding="utf-8")
        for pattern in dist_forbidden:
            matches = re.findall(pattern, content, re.IGNORECASE)
            assert not matches, f"Forbidden pattern '{pattern}' matched in {js_file.name}: {matches}"
