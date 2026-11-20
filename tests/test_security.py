import subprocess
import sys

import config
from tests.conftest import account_token

CREATE = {"cp_id": "CP1", "connector_id": 1, "phone": "+31600000000"}


def _create(client):
    r = client.post("/api/sessions/create", json=CREATE)
    assert r.status_code == 200, r.text
    return r


# ── X-Client-Cert-Serial ─────────────────────────────────────────────────

def test_cert_header_ignored_by_default(make_client):
    c = make_client()
    r = c.get("/", headers={"X-Client-Cert-Serial": "ABC123"})
    assert "device_auth" not in r.headers.get("set-cookie", "")
    r2 = c.get("/account/profile", headers={"X-Client-Cert-Serial": "ABC123"}, follow_redirects=False)
    assert "Victim Driver" not in r2.text


def test_cert_header_honoured_when_trusted_proxy_enabled(make_client, monkeypatch):
    monkeypatch.setattr(config, "TRUST_CLIENT_CERT_HEADER", True)
    c = make_client()
    r = c.get("/", headers={"X-Client-Cert-Serial": "ABC123"})
    assert "device_auth" in r.headers.get("set-cookie", "")


# ── session ownership ────────────────────────────────────────────────────

def test_creator_can_use_session(make_client):
    c = make_client()
    _create(c)
    assert c.get("/api/sessions/S-1/poll").status_code == 200
    assert c.get("/api/sessions/S-1/receipt").status_code == 200
    assert c.post("/api/sessions/S-1/stop").status_code == 200
    assert c.post("/api/sessions/S-1/cancel").status_code == 200


def test_stranger_cannot_touch_session(make_client, calls):
    _create(make_client())
    calls.clear()
    stranger = make_client()
    assert stranger.get("/api/sessions/S-1/poll").status_code == 403
    assert stranger.get("/api/sessions/S-1/receipt").status_code == 403
    assert stranger.get("/api/sessions/S-1/pdf", follow_redirects=False).status_code == 403
    assert stranger.post("/api/sessions/S-1/stop").status_code == 403
    assert stranger.post("/api/sessions/S-1/cancel").status_code == 403
    assert calls == [], "forbidden requests must not reach Core"


def test_forged_session_cookie_rejected(make_client):
    import jwt
    c = make_client()
    forged = jwt.encode({"typ": "session-access", "sids": ["S-1"]}, "wrong-secret", algorithm="HS256")
    c.cookies.set("session_access", forged)
    assert c.get("/api/sessions/S-1/poll").status_code == 403


def test_other_token_types_do_not_grant_access(make_client):
    """An account JWT (same signing key) must not double as a session grant."""
    c = make_client()
    c.cookies.set("session_access", account_token("drv-9"))
    assert c.get("/api/sessions/S-1/poll").status_code == 403


def test_account_owner_allowed_other_account_denied(make_client):
    owner = make_client()
    owner.cookies.set("auth_token", account_token("drv-1"))
    assert owner.get("/api/sessions/S-1/poll").status_code == 200
    other = make_client()
    other.cookies.set("auth_token", account_token("drv-2"))
    assert other.get("/api/sessions/S-1/poll").status_code == 403


# ── management key / error leaks ─────────────────────────────────────────

def test_management_key_not_sent_on_public_endpoints(make_client, calls):
    c = make_client()
    _create(c)
    c.get("/api/sessions/S-1/poll")
    public = [x for x in calls if x["path"].startswith("/api/v1/public/")]
    assert public and all(x["x_api_key"] is None for x in public)
    internal = [x for x in calls if x["path"].startswith("/api/v1/chargers/")]
    assert internal and all(x["x_api_key"] == "mgmt-test-key" for x in internal)


def test_core_errors_do_not_leak(make_client, state):
    c = make_client()
    _create(c)
    state["fail"] = True
    for r in (c.get("/api/sessions/S-1/poll"), c.get("/api/sessions/S-1/receipt")):
        assert r.status_code >= 500
        assert "SECRET" not in r.text and "127.0.0.1" not in r.text and "http" not in r.text


# ── headers, cookies, health, service worker ────────────────────────────

def test_security_headers_and_health(make_client):
    r = make_client().get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    for h in ("content-security-policy", "x-content-type-options", "x-frame-options",
              "referrer-policy", "permissions-policy"):
        assert h in r.headers, h
    assert r.headers["x-frame-options"] == "DENY"


def test_service_worker_scope_header(make_client):
    r = make_client().get("/sw.js")
    assert r.status_code == 200
    assert r.headers["service-worker-allowed"] == "/"
    assert "/sw.js" in make_client().get("/").text


def test_session_cookie_flags(make_client, monkeypatch):
    monkeypatch.setattr(config, "COOKIE_SECURE", True)
    r = _create(make_client())
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "secure" in sc and "samesite=lax" in sc


def test_cookie_secure_defaults_from_public_url():
    code = ("import os; os.environ['PUBLIC_URL']='https://cpo.example.com'; import config; print(config.COOKIE_SECURE)")
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip() == "True"
    code = code.replace("https://cpo.example.com", "http://localhost")
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip() == "False"


# ── no shared per-request state in templates ─────────────────────────────

def test_account_not_stored_in_shared_template_globals(make_client):
    from main import templates
    make_client().get("/")
    assert "account" not in templates.env.globals


# ── unknown skin ─────────────────────────────────────────────────────────

def test_unknown_skin_falls_back_to_default():
    code = (
        "import os; os.environ['SKIN']='does-not-exist'; os.environ['JWT_SECRET']='x';"
        "from fastapi.testclient import TestClient; from main import app;"
        "print(TestClient(app).get('/skin/style.css').status_code)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.strip().splitlines()[-1] == "200", out.stderr[-500:]
