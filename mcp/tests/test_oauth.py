import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client

from mcp.models import SCOPE_DESTRUCTIVE, OAuthClient, OAuthToken
from mcp.tests.conftest import make_token

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


def register(redirect=REDIRECT, **extra):
    return Client().post("/oauth/register", json.dumps({"redirect_uris": [redirect], "client_name": "Claude", **extra}),
                         content_type="application/json")


def pkce():
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def authorize(client, reg, challenge, decision="allow", destructive=True):
    data = {"client_id": reg["client_id"], "redirect_uri": REDIRECT, "state": "st", "response_type": "code",
            "code_challenge": challenge, "code_challenge_method": "S256", "decision": decision}
    if destructive:
        data["destructive"] = "on"
    response = client.post("/oauth/authorize", data)
    assert response.status_code == 302
    return parse_qs(urlsplit(response.url).query)


def exchange(reg, code, verifier, **extra):
    return Client().post("/oauth/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                          "client_id": reg["client_id"], "code_verifier": verifier, **extra})


@pytest.fixture
def browser(admin):
    client = Client()
    client.force_login(admin)
    return client


def test_metadata_is_built_from_public_base_url(db):
    meta = Client().get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == "https://mcp.example.com"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    resource = Client().get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource == {"resource": "https://mcp.example.com/mcp", "authorization_servers": ["https://mcp.example.com"],
                        "scopes_supported": ["dokploy", SCOPE_DESTRUCTIVE], "bearer_methods_supported": ["header"]}


@pytest.mark.parametrize("uri", ["https://evil.example/cb", "http://claude.ai/api/mcp/auth_callback", "javascript:alert(1)",
                                 "https://claude.ai.evil.com/cb", "https://claude.ai/login?returnTo=https://evil.example",
                                 "http://localhost@evil.example/cb", "http://localhost:9/cb?x=1", "http://evil.example/cb"])
def test_registration_rejects_redirects_off_the_allowlist(db, uri):
    assert register(uri).status_code == 400


@pytest.mark.parametrize("uri", [REDIRECT, "http://localhost:53682/callback", "http://127.0.0.1:9000/cb"])
def test_registration_accepts_claude_and_loopback(db, uri):
    body = register(uri).json()
    assert body["client_id"].startswith("mcp_") and "client_secret" not in body


def test_consent_requires_a_superuser(db, admin):
    reg = register().json()
    params = {"client_id": reg["client_id"], "redirect_uri": REDIRECT, "response_type": "code",
              "code_challenge": "x" * 43, "code_challenge_method": "S256"}
    assert Client().get("/oauth/authorize", params).url.startswith("/admin/login/")
    staff = Client()
    staff.force_login(get_user_model().objects.create_user("bob", password="another-long-passw0rd", is_staff=True))
    assert staff.get("/oauth/authorize", params).url.startswith("/admin/login/")


def test_consent_rejects_unregistered_redirect_and_missing_pkce(browser):
    reg = register().json()
    base = {"client_id": reg["client_id"], "response_type": "code", "code_challenge_method": "S256"}
    assert browser.get("/oauth/authorize", base | {"redirect_uri": "https://claude.ai/other", "code_challenge": "x"}).status_code == 400
    assert browser.get("/oauth/authorize", base | {"redirect_uri": REDIRECT}).status_code == 400
    page = browser.get("/oauth/authorize", base | {"redirect_uri": REDIRECT, "code_challenge": "x" * 43})
    assert page.status_code == 200 and b"csrfmiddlewaretoken" in page.content and b"claude.ai" in page.content


def test_consent_post_is_csrf_protected(admin):
    client = Client(enforce_csrf_checks=True)
    client.force_login(admin)
    reg = register().json()
    response = client.post("/oauth/authorize", {"client_id": reg["client_id"], "redirect_uri": REDIRECT, "response_type": "code",
                                                 "code_challenge": "x" * 43, "code_challenge_method": "S256", "decision": "allow"})
    assert response.status_code == 403


def test_full_flow_issues_a_token_that_opens_mcp(browser):
    reg = register().json()
    verifier, challenge = pkce()
    query = authorize(browser, reg, challenge)
    assert query["state"] == ["st"] and query["iss"] == ["https://mcp.example.com"]
    body = exchange(reg, query["code"][0], verifier).json()
    assert body["scope"] == f"dokploy {SCOPE_DESTRUCTIVE}"
    response = Client().post("/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}), content_type="application/json",
                             HTTP_AUTHORIZATION=f"Bearer {body['access_token']}")
    assert response.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_unticking_destructive_grants_the_base_scope_only(browser):
    reg = register().json()
    verifier, challenge = pkce()
    code = authorize(browser, reg, challenge, destructive=False)["code"][0]
    assert exchange(reg, code, verifier).json()["scope"] == "dokploy"


def test_denied_consent_returns_access_denied(browser):
    reg = register().json()
    assert authorize(browser, reg, "x" * 43, decision="deny")["error"] == ["access_denied"]


def test_codes_are_single_use_and_bound_to_pkce_and_client(browser):
    reg, other = register().json(), register().json()
    verifier, challenge = pkce()
    code = authorize(browser, reg, challenge)["code"][0]
    assert exchange(reg, code, "wrong-verifier").status_code == 400
    code = authorize(browser, reg, challenge)["code"][0]
    assert exchange(other, code, verifier).status_code == 401
    code = authorize(browser, reg, challenge)["code"][0]
    assert exchange(reg, code, verifier).status_code == 200
    assert exchange(reg, code, verifier).json()["error"] == "invalid_grant"


def test_confidential_clients_must_present_their_secret(browser):
    reg = register(token_endpoint_auth_method="client_secret_post").json()
    verifier, challenge = pkce()
    code = authorize(browser, reg, challenge)["code"][0]
    assert exchange(reg, code, verifier).status_code == 401
    code = authorize(browser, reg, challenge)["code"][0]
    basic = base64.b64encode(f"{reg['client_id']}:{reg['client_secret']}".encode()).decode()
    response = Client().post("/oauth/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                              "code_verifier": verifier}, HTTP_AUTHORIZATION=f"Basic {basic}")
    assert response.status_code == 200


def test_refresh_rotates_and_cannot_be_replayed(browser):
    reg = register().json()
    verifier, challenge = pkce()
    first = exchange(reg, authorize(browser, reg, challenge)["code"][0], verifier).json()
    refresh = {"grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": reg["client_id"]}
    second = Client().post("/oauth/token", refresh).json()
    assert second["access_token"] != first["access_token"] and second["scope"] == first["scope"]
    assert Client().post("/oauth/token", refresh).status_code == 400
    assert OAuthToken.objects.filter(revoked=False).count() == 0  # the replay revoked the connector's new token too


def test_a_registration_flood_evicts_old_unused_clients_instead_of_locking_out(db):
    OAuthClient.objects.bulk_create(OAuthClient(client_id=f"c{i}", redirect_uris=[REDIRECT]) for i in range(60))
    assert register().status_code == 201
    assert OAuthClient.objects.count() == 50


def test_login_is_throttled_per_client(admin):
    cache.clear()
    login = {"username": "admin", "password": "a-long-enough-passw0rd"}
    for _ in range(10):
        assert Client().post("/admin/login/", login | {"password": "wrong"}, HTTP_X_FORWARDED_FOR="203.0.113.9").status_code == 200
    assert Client().post("/admin/login/", login, HTTP_X_FORWARDED_FOR="203.0.113.9").status_code == 200  # locked out
    assert Client().post("/admin/login/", login, HTTP_X_FORWARDED_FOR="198.51.100.7").status_code == 302  # others are not
    cache.clear()
    for i in range(50):  # rotating a forged X-Forwarded-For still hits the global budget
        Client().post("/admin/login/", login | {"password": "wrong"}, HTTP_X_FORWARDED_FOR=f"10.9.0.{i}")
    assert Client().post("/admin/login/", login, HTTP_X_FORWARDED_FOR="198.51.100.8").status_code == 200
    cache.clear()


def test_ensure_admin_sets_password_and_revokes_tokens_on_change(db, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "first-long-passphrase")
    call_command("ensure_admin")
    user = get_user_model().objects.get(username="admin")
    assert user.is_superuser and user.check_password("first-long-passphrase")
    token = make_token(user)
    call_command("ensure_admin")  # unchanged password: tokens survive a restart
    token.refresh_from_db()
    assert not token.revoked
    other = get_user_model().objects.create_superuser("backdoor", password="another-long-passw0rd")
    other_token = make_token(other, raw="backdoor")
    monkeypatch.setenv("ADMIN_PASSWORD", "second-long-passphrase")
    call_command("ensure_admin")
    token.refresh_from_db()
    other_token.refresh_from_db()
    other.refresh_from_db()
    assert token.revoked and get_user_model().objects.get(username="admin").check_password("second-long-passphrase")
    assert other_token.revoked and not other.is_active and not other.is_superuser


@pytest.mark.parametrize("password", ["", "short", "password1234"])
def test_ensure_admin_refuses_weak_passwords(db, monkeypatch, password):
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    with pytest.raises(CommandError):
        call_command("ensure_admin")


def test_chunked_request_bodies_are_read(db):
    """claude.ai registers with a chunked body; Django alone would see it as empty."""
    import io

    from django.test import RequestFactory

    from project.wsgi import application
    body = json.dumps({"redirect_uris": [REDIRECT]}).encode()
    environ = RequestFactory().post("/oauth/register", content_type="application/json").environ
    environ.update({"wsgi.input": io.BytesIO(body), "HTTP_TRANSFER_ENCODING": "chunked", "HTTP_HOST": "mcp.example.com"})
    environ.pop("CONTENT_LENGTH", None)
    statuses = []
    response = application(environ, lambda status, headers: statuses.append(status))
    assert statuses == ["201 Created"], b"".join(response)
