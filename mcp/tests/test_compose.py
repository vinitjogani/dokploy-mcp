"""Raw compose deploys: the image allowlists and the compose file checks."""
import pytest

from mcp import tools
from mcp.compose import ComposeError, image_allowed, parse_image, validate
from mcp.tests.conftest import make_token
from mcp.tests.test_mcp import call, fake, parse, rpc  # noqa: F401 (fixture)

WEB = "services:\n  web:\n    image: ghcr.io/acme/blog:1.2\n"


@pytest.fixture
def allow(settings):
    settings.ALLOWED_REGISTRIES = {"ghcr.io"}
    settings.ALLOWED_IMAGES = ["nginx", "redis:7", "quay.io/acme/*", "registry.example.com:5000/team/app@sha256:" + "a" * 64]
    return settings


@pytest.mark.parametrize("ref,expected", [
    ("nginx", ("docker.io", "library/nginx", None, None)),
    ("nginx:1.27", ("docker.io", "library/nginx", "1.27", None)),
    ("acme/app", ("docker.io", "acme/app", None, None)),
    ("index.docker.io/acme/app:v1", ("docker.io", "acme/app", "v1", None)),
    ("ghcr.io/acme/blog:1.2", ("ghcr.io", "acme/blog", "1.2", None)),
    ("localhost:5000/app", ("localhost:5000", "app", None, None)),
    ("ghcr.io/acme/blog@sha256:" + "b" * 64, ("ghcr.io", "acme/blog", None, "sha256:" + "b" * 64)),
])
def test_parse_image(ref, expected):
    assert parse_image(ref) == expected


@pytest.mark.parametrize("ref,ok", [
    ("ghcr.io/anyone/anything:latest", True),  # registry allowlisted
    ("nginx:1.27", True), ("docker.io/library/nginx", True),  # image allowlisted, any tag
    ("redis:7", True), ("redis:8", False), ("redis", False),  # pinned tag
    ("quay.io/acme/api:2", True), ("quay.io/acme-evil/api", False), ("quay.io/acme", False),  # namespace
    ("registry.example.com:5000/team/app@sha256:" + "a" * 64, True), ("registry.example.com:5000/team/app:latest", False),
    ("postgres", False), ("evil.com/nginx", False), ("ghcr.io.evil.com/acme/blog", False),
])
def test_image_allowlists(allow, ref, ok):
    assert image_allowed(ref) is ok


def test_wildcard_registry_allows_everything(settings):
    settings.ALLOWED_REGISTRIES, settings.ALLOWED_IMAGES = {"*"}, []
    assert image_allowed("anything.example/x/y:z")


def test_disabled_without_allowlists(settings):
    settings.ALLOWED_REGISTRIES, settings.ALLOWED_IMAGES = set(), []
    with pytest.raises(ComposeError, match="disabled"):
        validate(WEB)


def test_a_reasonable_compose_file_passes(allow):
    text = """
x-common: {restart: unless-stopped}
services:
  web:
    image: ghcr.io/acme/blog:1.2
    environment: {DATABASE_URL: "postgres://app:${DB_PASSWORD}@db/app"}
    env_file: .env
    expose: ["8000"]
    depends_on: [db]
    volumes: ["uploads:/app/uploads", "/tmp/cache", {type: tmpfs, target: /run}]
    labels: {app.tier: web}
    deploy: {resources: {limits: {memory: 512M}}}
    networks: [backend]
  db:
    image: postgres:16
    volumes: [{type: volume, source: pgdata, target: /var/lib/postgresql/data}]
    networks: {backend: {aliases: [database]}}
volumes:
  uploads:
  pgdata: {labels: {backup: daily}}
networks:
  backend: {internal: true}
"""
    allow.ALLOWED_IMAGES = ["postgres:16"]
    assert validate(text) == text


@pytest.mark.parametrize("text,reason", [
    ("services:\n  web:\n    image: postgres\n", "not in ALLOWED"),
    ("services:\n  web:\n    image: ${IMAGE}\n", "interpolation"),
    ("services:\n  web:\n    build: .\n", "build not allowed"),
    ("services:\n  web:\n    image: nginx\n    privileged: true\n", "privileged not allowed"),
    ("services:\n  web:\n    image: nginx\n    network_mode: host\n", "network_mode not allowed"),
    ("services:\n  web:\n    image: nginx\n    pid: host\n", "pid not allowed"),
    ("services:\n  web:\n    image: nginx\n    cap_add: [SYS_ADMIN]\n", "cap_add not allowed"),
    ("services:\n  web:\n    image: nginx\n    devices: [/dev/sda]\n", "devices not allowed"),
    ("services:\n  web:\n    image: nginx\n    security_opt: [seccomp=unconfined]\n", "security_opt not allowed"),
    ("services:\n  web:\n    image: nginx\n    ports: ['80:80']\n", "ports not allowed"),
    ("services:\n  web:\n    image: nginx\n    container_name: dokploy\n", "container_name not allowed"),
    ("services:\n  web:\n    image: nginx\n    volumes: ['/:/host']\n", "host paths"),
    ("services:\n  web:\n    image: nginx\n    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n", "host paths"),
    ("services:\n  web:\n    image: nginx\n    volumes: ['./data:/data']\n", "host paths"),
    ("services:\n  web:\n    image: nginx\n    volumes: ['${HOME}:/data']\n", "interpolation"),
    ("services:\n  web:\n    image: nginx\n    volumes: [{type: bind, source: /, target: /h}]\n", "type 'bind'"),
    ("services:\n  web:\n    image: nginx\n    volumes: [{type: volume, source: d, target: /d, volume: {subpath: ../..}}]\n"
     "volumes:\n  d:\n", "subpath not allowed"),
    ("services:\n  web:\n    image: nginx\n    volumes: ['data:/d']\nvolumes:\n  data: {driver_opts: {type: none, o: bind, device: /}}\n",
     "driver_opts not allowed"),
    ("services:\n  web:\n    image: nginx\n    volumes: ['data:/d']\nvolumes:\n  data: {external: true, name: dokploy-postgres}\n",
     "external, name not allowed"),
    ("services:\n  web:\n    image: nginx\n    networks: [dokploy-network]\n", "must be declared"),
    ("services:\n  web:\n    image: nginx\nnetworks:\n  dokploy-network: {external: true}\n", "external not allowed"),
    ("services:\n  web:\n    image: nginx\n    labels: ['traefik.http.routers.x.rule=Host(`mcp.example.com`)']\n", "reserved"),
    ("services:\n  web:\n    image: nginx\n    labels: {com.docker.compose.project: other}\n", "reserved"),
    ("services:\n  web:\n    image: nginx\n    env_file: /etc/dokploy/.env\n", "only .env"),
    ("services:\n  web:\n    image: nginx\n    env_file: [{path: ../../other/.env}]\n", "only .env"),
    ("services:\n  web:\n    image: nginx\n    deploy: {labels: {traefik.enable: 'true'}}\n", "labels not allowed"),
    ("services:\n  web:\n    image: nginx\n    extends: {file: /etc/x.yml, service: s}\n", "extends not allowed"),
    ("services:\n  dokploy:\n    image: nginx\n", "service name not allowed"),
    ("name: other-project\nservices:\n  web:\n    image: nginx\n", "name not allowed"),
    ("include: [/etc/x.yml]\nservices:\n  web:\n    image: nginx\n", "include not allowed"),
    ("services:\n  web:\n    image: nginx\nsecrets:\n  s: {file: /etc/shadow}\n", "secrets not allowed"),
    ("services:\n  web:\n    image: nginx\n    environment: {X: '${{project.SECRET}}'}\n", r"\$\{\{"),
    ("x: &a [1]\ny: *a\nservices: {}\n", "aliases"),
    ("services:\n  web: [\n", "Invalid YAML"),
    ("services: {}\n", "at least one service"),
    ("- a list\n", "must be a mapping"),
])
def test_unsafe_compose_files_are_refused(allow, text, reason):
    with pytest.raises(ComposeError, match=reason):
        validate(text)


def test_raw_compose_tools_are_hidden_until_an_allowlist_is_set(admin, settings, fake):
    make_token(admin)
    settings.ALLOWED_REGISTRIES, settings.ALLOWED_IMAGES = set(), []
    names = {t["name"] for t in parse(rpc("tools/list"))["result"]["tools"]}
    assert not names & tools.RAW_COMPOSE_TOOLS
    with pytest.raises(tools.ToolError, match="Unknown tool"):
        call("create_compose_service", project="p", name="web", compose_yaml=WEB)
    settings.ALLOWED_REGISTRIES = {"ghcr.io"}
    names = {t["name"] for t in parse(rpc("tools/list"))["result"]["tools"]}
    assert tools.RAW_COMPOSE_TOOLS <= names


def test_create_compose_service(token, allow, fake):
    service = call("create_compose_service", project="apps", name="web", compose_yaml=WEB, env={"A": "1"})
    assert service["source"] == "raw" and service["repo"] is None and service["compose_yaml"] == WEB
    assert ("compose.update", {"composeId": "c0", "sourceType": "raw", "composeFile": WEB, "autoDeploy": False}, {}) in fake.calls
    assert fake.composes["c0"]["env"] == "A=1"
    with pytest.raises(tools.ToolError, match="not in ALLOWED"):
        call("create_compose_service", project="apps", name="evil", compose_yaml="services:\n  x:\n    image: evil/miner\n")
    assert len(fake.composes) == 1  # refused before anything was created


def test_set_compose_file(token, allow, fake):
    cid = fake.add_compose("blog")
    call("set_compose_file", compose_id=cid, compose_yaml=WEB)
    assert fake.composes[cid]["sourceType"] == "raw" and fake.composes[cid]["composeFile"] == WEB
    with pytest.raises(tools.ToolError, match="privileged"):
        call("set_compose_file", compose_id=cid, compose_yaml=WEB + "    privileged: true\n")
    assert fake.composes[cid]["composeFile"] == WEB
    protected = fake.add_compose("dokploy-mcp")
    with pytest.raises(tools.ToolError, match="PROTECTED_SERVICES"):
        call("set_compose_file", compose_id=protected, compose_yaml=WEB)
