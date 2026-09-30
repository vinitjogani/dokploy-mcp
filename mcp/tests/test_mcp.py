"""The /mcp endpoint and every tool, against an in-memory fake of the Dokploy API."""
import copy
import json

import pytest
from django.test import Client

from mcp import tools
from mcp.dokploy import DokployError
from mcp.models import AuditLog
from mcp.tests.conftest import make_token


class FakeDokploy:
    """Just enough of Dokploy's REST API, recording every call."""

    def __init__(self):
        self.calls, self.projects, self.composes, self.overview, self.containers = [], [], {}, [], []
        self.repos = [{"full_name": "acme/blog", "name": "blog", "owner": {"login": "acme"}, "default_branch": "main"}]
        self.branches, self.services, self.fetched = ["main", "dev"], ["web", "db"], []

    def __call__(self, proc, body=None, **query):
        self.calls.append((proc, copy.deepcopy(body), query))
        return getattr(self, proc.replace(".", "_"))(body, **query)

    def add_project(self, name):
        project = {"projectId": f"p{len(self.projects)}", "name": name,
                   "environments": [{"environmentId": f"e{len(self.projects)}", "name": "production", "isDefault": True, "compose": []}]}
        self.projects.append(project)
        return project

    def add_compose(self, name, project="apps", repo="acme/blog", env="", **extra):
        p = next((p for p in self.projects if p["name"] == project), None) or self.add_project(project)
        cid = f"c{len(self.composes)}"
        owner, repository = repo.split("/") if repo else (None, None)
        self.composes[cid] = {"composeId": cid, "name": name, "appName": f"{name}-abc123", "composeStatus": "idle",
                              "sourceType": "github", "owner": owner, "repository": repository, "branch": "main",
                              "composePath": "./docker-compose.yml", "autoDeploy": True, "watchPaths": None, "env": env,
                              "refreshToken": "SECRET-TOKEN", "domains": [], "deployments": [],
                              "environment": {"name": "production", "project": {"projectId": p["projectId"], "name": p["name"]}}, **extra}
        p["environments"][0]["compose"].append({"composeId": cid, "name": name, "composeStatus": "idle"})
        return cid

    def github_githubProviders(self, _):
        return [{"githubId": "gh1"}]

    def github_getGithubRepositories(self, _, githubId):
        return self.repos

    def github_getGithubBranches(self, _, **q):
        return [{"name": b} for b in self.branches]

    def project_all(self, _):
        return self.projects

    def project_one(self, _, projectId):
        return next(p for p in self.projects if p["projectId"] == projectId)

    def project_create(self, body):
        p = self.add_project(body["name"])
        return {"project": {"projectId": p["projectId"]}, "environment": p["environments"][0]}

    def project_remove(self, body):
        self.projects = [p for p in self.projects if p["projectId"] != body["projectId"]]

    def compose_create(self, body):
        project = next(p["name"] for p in self.projects if p["environments"][0]["environmentId"] == body["environmentId"])
        return self.composes[self.add_compose(body["name"], project, repo=None)]

    def compose_one(self, _, composeId):
        if composeId not in self.composes:
            raise DokployError("Dokploy compose.one failed with HTTP 404: Compose not found")
        return copy.deepcopy(self.composes[composeId])

    def compose_update(self, body):
        self.composes[body["composeId"]].update({k: v for k, v in body.items() if k != "composeId"})

    def compose_saveEnvironment(self, body):
        self.composes[body["composeId"]]["env"] = body["env"]
        return True

    def compose_loadServices(self, _, composeId, type):
        self.fetched.append(type)
        return self.services if type == "fetch" else self.services[:1]

    def compose_deploy(self, body):
        return {"success": True}

    def compose_stop(self, body):
        return True

    def compose_delete(self, body):
        del self.composes[body["composeId"]]

    def compose_readLogs(self, _, **q):
        return f"runtime logs of {q['containerId']}"

    def deployment_readLogs(self, _, **q):
        return f"build log of {q['deploymentId']}"

    def docker_getContainersByAppNameMatch(self, _, **q):
        return self.containers

    def settings_getWebServerSettings(self, _):
        return {"host": "panel.example.com", "sshPrivateKey": "SECRET-KEY"}

    def overview_domains(self, _):
        return self.overview

    def domain_one(self, _, domainId):
        return next(d for c in self.composes.values() for d in c["domains"] if d["domainId"] == domainId)

    def domain_create(self, body):
        domain = {"domainId": f"d{len(self.overview)}", **body}
        self.composes[body["composeId"]]["domains"].append(domain)
        self.overview.append({"host": body["host"], "serviceOwnerId": body["composeId"]})
        return domain

    def domain_delete(self, body):
        for c in self.composes.values():
            c["domains"] = [d for d in c["domains"] if d["domainId"] != body["domainId"]]


@pytest.fixture
def fake(monkeypatch):
    fake = FakeDokploy()
    monkeypatch.setattr(tools, "api", fake)
    return fake


def rpc(method, params=None, raw="raw-token", accept="application/json, text/event-stream"):
    body = {"jsonrpc": "2.0", "id": 7, "method": method, **({"params": params} if params is not None else {})}
    return Client().post("/mcp", json.dumps(body), content_type="application/json", HTTP_ACCEPT=accept,
                         HTTP_AUTHORIZATION=f"Bearer {raw}")


def parse(response):
    text = response.content.decode()
    return json.loads(text.removeprefix("event: message\ndata: ").strip()) if text.startswith("event:") else json.loads(text)


def call(tool, /, **arguments):
    result = parse(rpc("tools/call", {"name": tool, "arguments": arguments}))["result"]
    text = result["content"][0]["text"]
    if result["isError"]:
        raise tools.ToolError(text)
    try:
        return json.loads(text)
    except ValueError:
        return text


# ---------------------------------------------------------------------------- protocol


def test_requests_without_a_valid_token_get_the_oauth_challenge(token):
    for raw in ("", "wrong"):
        response = rpc("ping", raw=raw)
        assert response.status_code == 401
        assert response["WWW-Authenticate"] == 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'


def test_revoked_and_non_superuser_tokens_are_refused(token, admin):
    token.revoked = True
    token.save()
    assert rpc("ping").status_code == 401
    make_token(admin, raw="other")
    admin.is_superuser = False
    admin.save()
    assert rpc("ping", raw="other").status_code == 401


def test_initialize_negotiates_the_protocol_version(token):
    assert parse(rpc("initialize", {"protocolVersion": "2025-06-18"}))["result"]["protocolVersion"] == "2025-06-18"
    assert parse(rpc("initialize", {"protocolVersion": "1999-01-01"}))["result"]["protocolVersion"] == "2025-11-25"


def test_transport_edges(token):
    assert rpc("ping", accept="text/event-stream").content.startswith(b"event: message\ndata: ")
    assert parse(rpc("ping", accept="application/json")) == {"jsonrpc": "2.0", "id": 7, "result": {}}
    notification = Client().post("/mcp", json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                                 content_type="application/json", HTTP_AUTHORIZATION="Bearer raw-token")
    assert notification.status_code == 202
    batch = Client().post("/mcp", "[]", content_type="application/json", HTTP_AUTHORIZATION="Bearer raw-token")
    assert batch.status_code == 400
    assert Client().get("/mcp", HTTP_AUTHORIZATION="Bearer raw-token").status_code == 405
    assert parse(rpc("resources/list"))["error"]["code"] == -32601


def test_tools_are_annotated_and_destructive_ones_need_the_scope(admin, fake):
    make_token(admin)
    tools_ = parse(rpc("tools/list"))["result"]["tools"]
    listed = {t["name"]: t["annotations"] for t in tools_}
    assert len(listed) == 15 and all(t["title"] and t["description"] for t in tools_)
    forced = {t["name"] for t in tools_ if t.get("_meta", {}).get("anthropic/requiresUserInteraction") is True}
    assert forced == {n for n, a in listed.items() if a["destructiveHint"]} == {
        "rename_service", "remove_env_vars", "remove_domain", "stop_service", "delete_service", "delete_project"}
    assert listed["get_service"]["readOnlyHint"] and not listed["get_service"]["destructiveHint"]
    assert not listed["create_service"]["readOnlyHint"] and not listed["create_service"]["destructiveHint"]
    assert listed["delete_service"]["destructiveHint"]
    make_token(admin, scope="dokploy", raw="limited")
    limited = {t["name"] for t in parse(rpc("tools/list", raw="limited"))["result"]["tools"]}
    assert "delete_service" not in limited and "deploy_service" in limited
    cid = fake.add_compose("blog")
    result = parse(rpc("tools/call", {"name": "delete_service", "arguments": {"compose_id": cid}}, raw="limited"))["result"]
    assert result["isError"] and cid in fake.composes


# ---------------------------------------------------------------------------- validation


@pytest.mark.parametrize("name,arguments", [
    ("create_service", {"project": "p", "name": "Bad Name", "repo": "acme/blog"}),
    ("create_service", {"project": "p", "name": "blog", "repo": "acme/blog", "compose_path": "../../../etc/traefik/x.yml"}),
    ("create_service", {"project": "p", "name": "blog", "repo": "acme/blog", "compose_path": "x$(id).yml"}),
    ("create_service", {"project": "p", "name": "blog", "repo": "acme/blog", "branch": "--upload-pack=x"}),
    ("create_service", {"project": "p", "name": "blog", "repo": "acme/blog", "command": "run --privileged"}),
    ("add_domain", {"compose_id": "c0", "host": "a.example.com", "service": "web", "port": 80, "path": "/x`) || Host(`evil"}),
    ("add_domain", {"compose_id": "c0", "host": "a.example.com`)", "service": "web", "port": 80}),
    ("add_domain", {"compose_id": "c0", "host": "a.example.com", "service": "__proto__", "port": 80}),
    ("add_domain", {"compose_id": "c0", "host": "a.example.com", "service": "web", "port": 0}),
    ("set_env_vars", {"compose_id": "c0", "env": {"A": "line\nB=injected"}}),
    ("set_env_vars", {"compose_id": "c0", "env": {"BAD-KEY": "x"}}),
    ("set_env_vars", {"compose_id": "c0", "env": {"COMPOSE_FILE": "/etc/x.yml"}}),
    ("set_env_vars", {"compose_id": "c0", "env": {"DOCKER_HOST": "tcp://evil:2375"}}),
    ("set_env_vars", {"compose_id": "c0", "env": {"LEAK": "${{project.DB_PASSWORD}}"}}),
    ("get_service", {"compose_id": "../etc"}),
    ("create_service", {"project": "p", "name": "blog\n", "repo": "acme/blog"}),
    ("create_service", {"project": "p", "name": "blog", "repo": "acme/blog", "compose_path": "x.yml\n"}),
    ("set_env_vars", {"compose_id": "c0", "env": {"A": "value\n"}}),
])
def test_unsafe_arguments_never_reach_dokploy(token, fake, name, arguments):
    with pytest.raises(tools.ToolError, match="Invalid arguments"):
        call(name, **arguments)
    assert fake.calls == []


# ---------------------------------------------------------------------------- reading


def test_list_and_get_never_show_secrets(token, fake):
    fake.add_compose("blog", env="DB_PASSWORD=hunter2\n# note\nexport API_KEY='x y'")
    fake.add_compose("other", repo="acme/other")
    listed = call("list_services", repo="blog")
    assert [s["name"] for p in listed for s in p["services"]] == ["blog"]
    service = call("get_service", compose_id="c0")
    assert service["env_keys"] == ["DB_PASSWORD", "API_KEY"] and service["compose_services"] == ["web"]
    dumped = json.dumps([listed, service])
    assert "hunter2" not in dumped and "SECRET" not in dumped


def test_logs_only_reads_this_services_containers_and_deployments(token, fake):
    cid = fake.add_compose("blog", deployments=[{"deploymentId": "old", "createdAt": "2026-01-01", "status": "done"},
                                                {"deploymentId": "new", "createdAt": "2026-02-01", "status": "error"}])
    fake.containers = [{"containerId": "abc", "name": "blog-abc123-web-1"}, {"containerId": "zzz", "name": "blog-abc123-webhook-1"},
                       {"containerId": "own", "name": "my-db"}]
    assert call("get_container_logs", compose_id=cid, service="my-db") == "runtime logs of own"
    assert call("get_deployment_logs", compose_id=cid).startswith("Deployment new (error):\nbuild log of new")
    assert "build log of old" in call("get_deployment_logs", compose_id=cid, deployment_id="old")
    with pytest.raises(tools.ToolError, match="No such deployment"):
        call("get_deployment_logs", compose_id=cid, deployment_id="someone-elses")
    assert call("get_container_logs", compose_id=cid, service="web") == "runtime logs of abc"
    with pytest.raises(tools.ToolError, match="No container"):
        call("get_container_logs", compose_id=cid, service="dokploy")


# ---------------------------------------------------------------------------- creating and configuring


def test_create_service_wires_only_allowlisted_fields(token, fake):
    service = call("create_service", project="Side projects", name="blog", repo="Acme/Blog", env={"SECRET": "p@ss word#1"})
    assert service["repo"] == "acme/blog" and service["branch"] == "main" and service["project"] == "Side projects"
    updates = [body for proc, body, _ in fake.calls if proc == "compose.update"]
    assert updates == [{"composeId": "c0", "sourceType": "github", "githubId": "gh1", "owner": "acme", "repository": "blog",
                        "branch": "main", "composePath": "docker-compose.yml", "autoDeploy": True, "triggerType": "push",
                        "watchPaths": [], "enableSubmodules": False}]
    assert ("compose.create", {"name": "blog", "appName": "blog", "environmentId": "e0", "composeType": "docker-compose"}, {}) in fake.calls
    assert fake.composes["c0"]["env"] == "SECRET='p@ss word#1'"
    assert AuditLog.objects.get(tool="create_service").arguments["env"] == {"SECRET": "<redacted>"}
    with pytest.raises(tools.ToolError, match="already has a service named 'blog'"):
        call("create_service", project="Side projects", name="blog", repo="acme/blog")
    assert len(fake.projects) == 1


def test_create_service_refuses_repos_and_branches_dokploy_cannot_see(token, fake):
    with pytest.raises(tools.ToolError, match="not accessible"):
        call("create_service", project="p", name="evil", repo="stranger/malicious")
    with pytest.raises(tools.ToolError, match="no branch 'nope'"):
        call("create_service", project="p", name="blog", repo="acme/blog", branch="nope")
    assert not any(proc.startswith(("compose.", "project.create")) for proc, _, _ in fake.calls)


def test_update_service_checks_branch_against_the_current_repo(token, fake):
    cid = fake.add_compose("blog")
    call("update_service", compose_id=cid, branch="dev", watch_paths=["src/**"], auto_deploy=False)
    assert fake.composes[cid]["branch"] == "dev" and fake.composes[cid]["watchPaths"] == ["src/**"]
    assert fake.composes[cid]["autoDeploy"] is False and fake.composes[cid]["composePath"] == "./docker-compose.yml"
    with pytest.raises(tools.ToolError, match="no branch"):
        call("update_service", compose_id=cid, branch="missing")


def test_env_edits_treat_multiline_values_as_one_variable(token, fake):
    cid = fake.add_compose("blog", env='KEY="-----BEGIN\nFAKE=1\n-----END"\nNEXT=2\nLAST=3')
    assert call("get_service", compose_id=cid)["env_keys"] == ["KEY", "NEXT", "LAST"]
    call("remove_env_vars", compose_id=cid, keys=["KEY"])
    call("set_env_vars", compose_id=cid, env={"LAST": "x"})
    assert fake.composes[cid]["env"] == "NEXT=2\nLAST=x"


def test_update_service_keeps_the_branch_and_skips_broken_providers(token, fake):
    cid = fake.add_compose("blog")
    fake.composes[cid]["branch"] = "dev"
    real = fake.github_getGithubRepositories
    fake.github_githubProviders = lambda _: [{"githubId": "broken"}, {"githubId": "gh1"}]
    fake.github_getGithubRepositories = lambda _, githubId: real(_, githubId) if githubId == "gh1" else (_ for _ in ()).throw(DokployError("500"))
    call("update_service", compose_id=cid, repo="ACME/blog", compose_path="deploy/compose.yml")
    assert fake.composes[cid]["branch"] == "dev" and fake.composes[cid]["composePath"] == "deploy/compose.yml"
    raw = fake.add_compose("raw", repo=None)
    with pytest.raises(tools.ToolError, match="not deployed from GitHub"):
        call("update_service", compose_id=raw, branch="main")


def test_env_vars_merge_and_quote_for_dotenv(token, fake):
    cid = fake.add_compose("blog", env="A=1\n# keep me\nB=2\nexport C=3")
    result = call("set_env_vars", compose_id=cid, env={"B": "has space", "D": "it's", "E": "a'b`c", "F": "plain-value_1.2"})
    assert fake.composes[cid]["env"] == "A=1\n# keep me\nB='has space'\nexport C=3\nD=`it's`\nE=\"a'b`c\"\nF=plain-value_1.2"
    assert result["env_keys"] == ["A", "B", "C", "D", "E", "F"]
    call("remove_env_vars", compose_id=cid, keys=["A", "C", "missing"])
    assert fake.composes[cid]["env"] == "# keep me\nB='has space'\nD=`it's`\nE=\"a'b`c\"\nF=plain-value_1.2"
    with pytest.raises(tools.ToolError, match="dotenv cannot store"):
        call("set_env_vars", compose_id=cid, env={"G": "'`\"\\"})


def test_add_domain_routes_new_hosts_only(token, fake):
    cid = fake.add_compose("blog")
    other = fake.add_compose("shop")
    fake.overview.append({"host": "shop.example.com", "serviceOwnerId": other})
    domain = call("add_domain", compose_id=cid, host="blog", service="web", port=8000)
    assert domain["url"] == "https://blog.example.com/"
    created = next(body for proc, body, _ in fake.calls if proc == "domain.create")
    assert created == {"host": "blog.example.com", "path": "/", "port": 8000, "https": True, "certificateType": "letsencrypt",
                       "composeId": cid, "serviceName": "web", "domainType": "compose", "stripPath": False,
                       "internalPath": "/", "middlewares": []}
    call("add_domain", compose_id=cid, host="blog", service="db", port=5432, path="/api")  # same host, own service
    assert fake.fetched[-2:] == ["cache", "fetch"]
    for host, reason in [("shop", "another service"), ("panel.example.com", "another service"),
                         ("mcp.example.com", "another service"), ("dokploy", "another service"),
                         ("blog", "already routed"), ("evil.com", "must be under")]:
        with pytest.raises(tools.ToolError, match=reason):
            call("add_domain", compose_id=cid, host=host, service="web", port=80)
    with pytest.raises(tools.ToolError, match="not a service"):
        call("add_domain", compose_id=cid, host="new", service="worker", port=80)


def test_add_domain_without_https_for_a_tls_proxy(token, fake):
    cid = fake.add_compose("blog")
    domain = call("add_domain", compose_id=cid, host="blog", service="web", port=8000, https=False)
    assert domain["url"] == "http://blog.example.com/"
    created = next(body for proc, body, _ in fake.calls if proc == "domain.create")
    assert created["https"] is False and created["certificateType"] == "none"


def test_protected_services_are_read_only(token, fake):
    cid = fake.add_compose("mcp-server", repo="acme/Dokploy-MCP")
    renamed = fake.add_compose("renamed", repo="acme/fork", domains=[{"domainId": "x", "host": "MCP.example.com"}])
    with pytest.raises(tools.ToolError, match="PROTECTED_SERVICES"):
        call("deploy_service", compose_id=renamed)
    assert call("get_service", compose_id=cid)["protected"] is True
    for name, arguments in [("set_env_vars", {"env": {"A": "1"}}), ("deploy_service", {}), ("delete_service", {}),
                            ("add_domain", {"host": "x", "service": "web", "port": 1}), ("rename_service", {"name": "x"})]:
        with pytest.raises(tools.ToolError, match="PROTECTED_SERVICES"):
            call(name, compose_id=cid, **arguments)
    assert not any(proc in ("compose.saveEnvironment", "compose.deploy", "compose.delete", "domain.create", "compose.update")
                   for proc, _, _ in fake.calls)


# ---------------------------------------------------------------------------- destructive


def test_destructive_tools(token, fake):
    cid = fake.add_compose("blog", project="old")
    call("add_domain", compose_id=cid, host="blog", service="web", port=80)
    assert call("rename_service", compose_id=cid, name="journal")["name"] == "journal"
    assert call("remove_domain", domain_id="d0")["compose_id"] == cid and fake.composes[cid]["domains"] == []
    assert call("stop_service", compose_id=cid) == {"stopped": cid}
    with pytest.raises(tools.ToolError, match="still has services"):
        call("delete_project", project_id="p0")
    assert call("delete_service", compose_id=cid) == {"deleted": "journal", "volumes_deleted": False}
    assert ("compose.delete", {"composeId": cid, "deleteVolumes": False}, {}) in fake.calls
    fake.projects[0]["environments"][0]["compose"] = []
    assert call("delete_project", project_id="p0") == {"deleted": "old"}


def test_long_output_keeps_its_tail(token, fake):
    cid = fake.add_compose("blog", deployments=[{"deploymentId": "d", "createdAt": "2026-01-01", "status": "done"}])
    fake.deployment_readLogs = lambda _, **q: "x" * 70_000 + "the end"
    text = call("get_deployment_logs", compose_id=cid)
    assert text.startswith("[first ") and text.endswith("the end") and len(text) < 61_000


def test_dokploy_errors_are_tool_errors_and_audited(token, fake):
    with pytest.raises(tools.ToolError, match="Compose not found"):
        call("get_service", compose_id="nope")
    entry = AuditLog.objects.get(tool="get_service")
    assert entry.ok is False and entry.token == token
