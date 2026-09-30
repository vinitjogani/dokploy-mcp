"""The MCP endpoint: JSON-RPC 2.0 over a single POST (Streamable HTTP, stateless), no SDK.
Every request needs a bearer token from mcp.oauth; tool calls are dispatched by mcp.tools."""
import json

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from mcp.oauth import authenticate_bearer
from mcp.tools import call_tool, list_tools

VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")


def handle(msg, token):
    """The response for one JSON-RPC message, or None for a notification."""
    method, msg_id, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if "id" not in msg:
        return None  # notifications (notifications/initialized, cancelled, ...) and stray responses
    if not isinstance(method, str) or not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32600, "message": "Invalid request"}}
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {
            "protocolVersion": version if version in VERSIONS else VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "dokploy-mcp", "version": "1.0.0"},
            "instructions": "Manage Docker Compose services on the owner's Dokploy instance. Start with "
                            "list_services to find the service for a repository; changes to env vars or "
                            "domains take effect on the next deploy_service.",
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": list_tools(token)}
    elif method == "tools/call":
        result = call_tool(token, params.get("name"), params.get("arguments") or {})
    else:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


@csrf_exempt
@require_POST
def mcp(request):
    token = authenticate_bearer(request)
    if token is None:
        response = JsonResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Unauthorized"}}, status=401)
        response["WWW-Authenticate"] = f'Bearer resource_metadata="{settings.PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp"'
        return response
    try:
        msg = json.loads(request.body)
    except ValueError:
        return JsonResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status=400)
    if not isinstance(msg, dict):  # JSON-RPC batches were removed from MCP in 2025-06-18
        return JsonResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Expected one JSON-RPC message"}}, status=400)
    response = handle(msg, token)
    if response is None:
        return HttpResponse(status=202)
    if "text/event-stream" in request.headers.get("Accept", ""):  # some connectors insist on SSE framing
        return HttpResponse(f"event: message\ndata: {json.dumps(response)}\n\n", content_type="text/event-stream")
    return JsonResponse(response)
