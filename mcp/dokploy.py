"""Minimal client for Dokploy's REST API (tRPC procedures exposed as GET /api/<proc>?<query> for
queries and POST /api/<proc> with a JSON body for mutations, authenticated with x-api-key)."""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from django.conf import settings


class DokployError(Exception):
    pass


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None  # never replay the API key to wherever a redirect points


# No proxies either: the key only ever goes straight to DOKPLOY_URL.
_opener = build_opener(ProxyHandler({}), _NoRedirects)


def api(proc, body=None, **query):
    """GET ``proc`` with ``query`` when ``body`` is None, else POST ``body``; returns parsed JSON."""
    url = f"{settings.DOKPLOY_URL}/api/{proc}" + (f"?{urlencode(query)}" if query else "")
    data = None if body is None else json.dumps(body).encode()
    request = Request(url, data=data, method="GET" if body is None else "POST", headers={
        "x-api-key": settings.DOKPLOY_API_KEY, "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with _opener.open(request, timeout=180) as response:
            raw = response.read()
    except HTTPError as exc:
        try:
            message = json.loads(exc.read()).get("message", "")
        except Exception:
            message = ""
        hint = " (check DOKPLOY_API_KEY, and that the key was created without a rate limit)" if exc.code == 401 else ""
        raise DokployError(f"Dokploy {proc} failed with HTTP {exc.code}: {str(message)[:500]}{hint}") from None
    except (URLError, TimeoutError) as exc:
        raise DokployError(f"Cannot reach Dokploy at {settings.DOKPLOY_URL}: {exc}") from None
    return json.loads(raw) if raw else None
