"""OAuth 2.1 authorization server for /mcp: RFC 8414/9728 metadata, Dynamic Client Registration
(RFC 7591), a superuser-only consent screen, and the token endpoint (authorization code + PKCE
S256, rotating refresh tokens). Also the throttled login backend guarding the admin password."""
import base64
import hashlib
import json
import logging
import re
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import user_passes_test
from django.core.cache import cache
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from mcp.models import SCOPE_DESTRUCTIVE, OAuthClient, OAuthGrant, OAuthToken

logger = logging.getLogger(__name__)
ACCESS_TTL, REFRESH_TTL, CODE_TTL = timedelta(hours=1), timedelta(days=30), timedelta(minutes=2)
LOOPBACK_REDIRECT = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?/[A-Za-z0-9/_-]*$")  # native apps, RFC 8252


def sha256(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def client_ip(request):
    # Traefik overwrites X-Forwarded-For from untrusted clients; its last entry is the peer it saw.
    return request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[-1].strip() or request.META.get("REMOTE_ADDR", "")


class ThrottledBackend(ModelBackend):
    """ModelBackend that stops checking passwords after too many failures: per client IP, and in
    total, since any container on dokploy-network can reach us directly and forge X-Forwarded-For."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        limits = {f"login-failures:{client_ip(request) if request else ''}": settings.LOGIN_FAILURE_LIMIT,
                  "login-failures": settings.LOGIN_FAILURE_LIMIT * 5}
        if any(cache.get(key, 0) >= limit for key, limit in limits.items()):
            return None
        user = super().authenticate(request, username, password, **kwargs)
        if user is None:
            for key in limits:
                cache.add(key, 0, timeout=900)
                cache.incr(key)
        return user


def authenticate_bearer(request):
    """The active token behind ``Authorization: Bearer``, if it belongs to an active superuser
    (re-checked on every call, so demoting the user cuts off their connectors at once)."""
    scheme, _, raw = request.headers.get("Authorization", "").partition(" ")
    return scheme.lower() == "bearer" and OAuthToken.objects.select_related("client").filter(
        access_token_hash=sha256(raw.strip()), revoked=False, expires_at__gt=timezone.now(),
        user__is_active=True, user__is_superuser=True).first() or None


def authorization_server_metadata(request):
    base = settings.PUBLIC_BASE_URL
    return JsonResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": ["dokploy", SCOPE_DESTRUCTIVE],
        "authorization_response_iss_parameter_supported": True,
    })


def protected_resource_metadata(request):
    base = settings.PUBLIC_BASE_URL
    return JsonResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "scopes_supported": ["dokploy", SCOPE_DESTRUCTIVE],
        "bearer_methods_supported": ["header"],
    })


def _redirect_allowed(uri):
    return isinstance(uri, str) and (uri in settings.OAUTH_REDIRECT_URIS or bool(LOOPBACK_REDIRECT.match(uri)))


@csrf_exempt
@require_POST
def register(request):
    """Dynamic Client Registration, limited to OAUTH_REDIRECT_URIS and loopback redirects so a
    consent link can never hand a code to anyone but Claude or a local app."""
    try:
        data = json.loads(request.body)
        uris = data["redirect_uris"]
        if not (isinstance(uris, list) and 0 < len(uris) <= 5 and all(map(_redirect_allowed, uris))):
            raise ValueError
    except Exception:
        logger.warning("Rejected client registration: %s", request.body[:1000])
        return JsonResponse({"error": "invalid_redirect_uri", "error_description": "redirect_uris must be one of "
                             f"{', '.join(settings.OAUTH_REDIRECT_URIS)} or http://localhost:<port>/<path>"}, status=400)
    # Only the newest 50 registrations that never led to a token are kept, so the open endpoint can
    # neither fill the database nor be jammed to lock out a real connector.
    OAuthClient.objects.filter(pk__in=OAuthClient.objects.filter(oauthtoken__isnull=True).order_by("-created_at")
                               .values_list("pk", flat=True)[49:]).delete()
    method = data.get("token_endpoint_auth_method", "none")
    if method not in ("none", "client_secret_post", "client_secret_basic"):
        return JsonResponse({"error": "invalid_client_metadata"}, status=400)
    secret = secrets.token_urlsafe(32) if method != "none" else ""
    client = OAuthClient.objects.create(
        client_id="mcp_" + secrets.token_urlsafe(16),
        client_secret_hash=sha256(secret) if secret else "",
        client_name=str(data.get("client_name") or "")[:100],
        redirect_uris=uris,
    )
    body = {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": uris,
        "token_endpoint_auth_method": method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_id_issued_at": int(client.created_at.timestamp()),
    }
    if secret:
        body.update(client_secret=secret, client_secret_expires_at=0)
    return JsonResponse(body, status=201)


@user_passes_test(lambda u: u.is_active and u.is_superuser, login_url="admin:login")
def authorize(request):
    """GET shows the consent screen; POST (CSRF-protected) records the decision."""
    params = request.POST if request.method == "POST" else request.GET
    client = OAuthClient.objects.filter(client_id=params.get("client_id", "")).first()
    redirect_uri = params.get("redirect_uri", "")
    if not client or redirect_uri not in client.redirect_uris:
        return HttpResponseBadRequest("Unknown client_id or unregistered redirect_uri.")
    if params.get("response_type") != "code" or params.get("code_challenge_method") != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", params.get("code_challenge", "")):
        return HttpResponseBadRequest("Only response_type=code with PKCE (S256) is supported.")
    reply = {"state": params.get("state", ""), "iss": settings.PUBLIC_BASE_URL}  # RFC 9207: tells the client who answered
    sep = "&" if "?" in redirect_uri else "?"
    if request.method != "POST":
        return render(request, "mcp/consent.html", {
            "client": client, "redirect_host": urlsplit(redirect_uri).hostname, "params": {
                k: params.get(k, "") for k in ("client_id", "redirect_uri", "state", "response_type", "code_challenge", "code_challenge_method")},
        })
    if params.get("decision") != "allow":
        return redirect(f"{redirect_uri}{sep}{urlencode({'error': 'access_denied', **reply})}")
    code = secrets.token_urlsafe(32)
    OAuthGrant.objects.create(
        code_hash=sha256(code), client=client, user=request.user, redirect_uri=redirect_uri,
        code_challenge=params["code_challenge"], expires_at=timezone.now() + CODE_TTL,
        scope="dokploy" + (f" {SCOPE_DESTRUCTIVE}" if params.get("destructive") == "on" else ""),
    )
    return redirect(f"{redirect_uri}{sep}{urlencode({'code': code, **reply})}")


def _error(error, description="", status=400):
    return JsonResponse({"error": error, "error_description": description}, status=status)


def _client_authenticated(request, client):
    """Public clients prove themselves with PKCE; confidential ones also need their secret
    (client_secret_post or client_secret_basic)."""
    client_id, secret = request.POST.get("client_id", ""), request.POST.get("client_secret", "")
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            client_id, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
        except ValueError:
            return False
    if not secrets.compare_digest(client_id.encode(), client.client_id.encode()):
        return False
    return not client.client_secret_hash or secrets.compare_digest(sha256(secret), client.client_secret_hash)


def _issue(client, user, scope):
    access, refresh, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), timezone.now()
    OAuthToken.objects.create(
        access_token_hash=sha256(access), refresh_token_hash=sha256(refresh), client=client, user=user,
        scope=scope, expires_at=now + ACCESS_TTL, refresh_expires_at=now + REFRESH_TTL,
    )
    return JsonResponse({"access_token": access, "token_type": "Bearer", "expires_in": int(ACCESS_TTL.total_seconds()),
                         "refresh_token": refresh, "scope": scope}, headers={"Cache-Control": "no-store"})


@csrf_exempt
@require_POST
def token(request):
    grant_type = request.POST.get("grant_type")
    if grant_type == "authorization_code":
        grant = OAuthGrant.objects.select_related("client", "user").filter(code_hash=sha256(request.POST.get("code", ""))).first()
        # Deleting the row is what spends the code, so two racing redemptions cannot both win.
        if not grant or not OAuthGrant.objects.filter(pk=grant.pk).delete()[0] or timezone.now() >= grant.expires_at:
            return _error("invalid_grant", "Invalid or expired authorization code")
        if not _client_authenticated(request, grant.client):
            return _error("invalid_client", status=401)
        verifier = request.POST.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if request.POST.get("redirect_uri") != grant.redirect_uri or not secrets.compare_digest(challenge, grant.code_challenge):
            return _error("invalid_grant", "redirect_uri or PKCE verifier mismatch")
        return _issue(grant.client, grant.user, grant.scope)
    if grant_type == "refresh_token":
        presented = sha256(request.POST.get("refresh_token", ""))
        reused = OAuthToken.objects.filter(refresh_token_hash=presented, revoked=True).first()
        if reused:  # a replayed, already-rotated token means it leaked: cut off that whole connector
            OAuthToken.objects.filter(client=reused.client).update(revoked=True)
        old = OAuthToken.objects.select_related("client", "user").filter(
            refresh_token_hash=presented, revoked=False, user__is_active=True, user__is_superuser=True).first()
        if not old or timezone.now() >= old.refresh_expires_at or not _client_authenticated(request, old.client):
            return _error("invalid_grant", "Invalid or expired refresh token")
        if not OAuthToken.objects.filter(pk=old.pk, revoked=False).update(revoked=True):  # rotate exactly once
            return _error("invalid_grant", "Refresh token already used")
        return _issue(old.client, old.user, old.scope)
    return _error("unsupported_grant_type")
