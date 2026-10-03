"""Validation of raw Docker Compose files that agents deploy without a GitHub repository.

A compose file is root on the host: privileged containers, bind mounts of ``/`` or the Docker
socket, host networking, a volume or project ``name`` that adopts another stack's data, Traefik
labels that steal another service's domain. So rather than blocking known-bad keys, only an
allowlisted subset of the compose spec is accepted, and every image must come from
ALLOWED_REGISTRIES or match ALLOWED_IMAGES. Errors name the offending path so an agent can fix it.
"""
import re

import yaml
from django.conf import settings

MAX_SIZE = 64 * 1024

TOP_LEVEL = {"services", "volumes", "networks"}
SERVICE_KEYS = {
    "image", "command", "entrypoint", "environment", "env_file", "expose", "volumes", "depends_on", "restart",
    "healthcheck", "working_dir", "user", "labels", "deploy", "hostname", "stop_grace_period", "stop_signal",
    "tmpfs", "read_only", "init", "shm_size", "ulimits", "networks", "mem_limit", "mem_reservation", "cpus",
    "cap_drop", "stdin_open", "tty", "platform", "pull_policy", "profiles", "extra_hosts", "dns",
}
DEPLOY_KEYS = {"resources", "restart_policy", "replicas"}
VOLUME_KEYS = {"labels"}  # no name/external (another stack's data) and no driver/driver_opts (host binds)
NETWORK_KEYS = {"labels", "internal"}  # no name/external: dokploy-network carries the panel's API
SERVICE_NETWORK_KEYS = {"aliases"}
LONG_VOLUME_KEYS = {"type", "source", "target", "read_only", "volume", "tmpfs"}
# Names Dokploy's own containers answer to on dokploy-network, which a domain attaches services to.
RESERVED_SERVICE_NAMES = {"dokploy", "dokploy-traefik", "dokploy-postgres", "dokploy-redis", "traefik"}
RESERVED_LABEL_PREFIXES = ("traefik", "com.docker.")
NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$")
DOCKER_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"}


class ComposeError(ValueError):
    """Why a compose file was refused."""


class NoAliasLoader(yaml.SafeLoader):
    """Anchors/aliases (and so ``<<`` merges) are refused: they allow exponential "billion laughs"
    documents and are not needed for a compose file an agent writes."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ComposeError("YAML anchors and aliases are not supported; write the values out.")
        return super().compose_node(parent, index)


def parse_image(ref, namespace=False):
    """``ref`` -> (registry, repository, tag, digest), normalized the way Docker resolves it:
    ``nginx`` is ``docker.io/library/nginx`` (unless ``ref`` names a namespace, as in ``acme/*``)."""
    if not IMAGE.match(ref):
        raise ComposeError(f"'{ref}' is not a valid image reference (no ${{...}} interpolation).")
    name, _, digest = ref.partition("@")
    tag = None
    if ":" in name.rpartition("/")[2]:
        name, _, tag = name.rpartition(":")
    first, sep, rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first, rest
    else:
        registry, repository = "docker.io", name
    if registry in DOCKER_HUB:
        registry = "docker.io"
        if "/" not in repository and not namespace:
            repository = f"library/{repository}"
    return registry, repository, tag, digest or None


def image_allowed(ref):
    registry, repository, tag, digest = parse_image(ref)
    if "*" in settings.ALLOWED_REGISTRIES or registry in settings.ALLOWED_REGISTRIES:
        return True
    for entry in settings.ALLOWED_IMAGES:
        prefix = entry.endswith("/*")
        e_registry, e_repository, e_tag, e_digest = parse_image(entry[:-2] if prefix else entry, namespace=prefix)
        if e_registry != registry:
            continue
        if prefix:
            if repository.startswith(f"{e_repository}/"):
                return True
        elif e_repository == repository and e_tag in (None, tag) and e_digest in (None, digest):
            return True
    return False


def raw_compose_enabled():
    return bool(settings.ALLOWED_REGISTRIES or settings.ALLOWED_IMAGES)


def check_keys(where, mapping, allowed):
    if not isinstance(mapping, dict):
        raise ComposeError(f"{where} must be a mapping.")
    extra = sorted(str(k) for k in mapping if k not in allowed and not str(k).startswith("x-"))
    if extra:
        raise ComposeError(f"{where}: {', '.join(extra)} not allowed. Allowed: {', '.join(sorted(allowed))}.")


def no_interpolation(where, value):
    if not isinstance(value, str) or "$" in value:
        raise ComposeError(f"{where} must be a plain string without $ interpolation.")
    return value


def check_labels(where, labels):
    keys = labels if isinstance(labels, list) else list(labels or {})
    for item in keys:
        key = str(item).partition("=")[0].strip().lower()
        if key.startswith(RESERVED_LABEL_PREFIXES):
            raise ComposeError(f"{where}: label '{key}' is reserved (routing is done with add_domain).")


def check_volume(where, spec, declared):
    if isinstance(spec, str):
        no_interpolation(where, spec)
        source, sep, _ = spec.partition(":")
        if sep and source not in declared:
            raise ComposeError(f"{where}: '{source}' must be a volume declared under top-level volumes "
                               "(host paths cannot be mounted).")
        return
    check_keys(where, spec, LONG_VOLUME_KEYS)
    kind = spec.get("type", "volume")
    if kind == "tmpfs":
        return
    if kind != "volume":
        raise ComposeError(f"{where}: type '{kind}' not allowed (only volume and tmpfs).")
    if "volume" in spec:
        check_keys(f"{where}.volume", spec["volume"], {"nocopy"})
    if "source" in spec and no_interpolation(f"{where}.source", spec["source"]) not in declared:
        raise ComposeError(f"{where}: '{spec['source']}' must be a volume declared under top-level volumes.")


def check_service(name, service, volumes, networks):
    where = f"services.{name}"
    if str(name).lower() in RESERVED_SERVICE_NAMES or not NAME.match(str(name)):
        raise ComposeError(f"{where}: service name not allowed (lowercase letters, digits, . _ -; not a Dokploy name).")
    check_keys(where, service, SERVICE_KEYS)
    if "image" not in service:
        raise ComposeError(f"{where}: needs an image (building is only possible from a GitHub repo).")
    image = no_interpolation(f"{where}.image", service["image"])
    if not image_allowed(image):
        raise ComposeError(f"{where}: image '{image}' is not in ALLOWED_REGISTRIES or ALLOWED_IMAGES.")
    env_files = service.get("env_file", [])
    for item in env_files if isinstance(env_files, list) else [env_files]:
        path = item.get("path") if isinstance(item, dict) else item
        if path not in (".env", "./.env"):
            raise ComposeError(f"{where}.env_file: only .env (the variables set with set_env_vars) is allowed.")
    for i, spec in enumerate(service.get("volumes") or []):
        check_volume(f"{where}.volumes[{i}]", spec, volumes)
    check_labels(f"{where}.labels", service.get("labels"))
    if "deploy" in service:
        check_keys(f"{where}.deploy", service["deploy"], DEPLOY_KEYS)
    service_networks = service.get("networks") or []
    for net in service_networks:
        if not isinstance(net, str) or net not in networks:
            raise ComposeError(f"{where}.networks: '{net}' must be declared under top-level networks.")
        if isinstance(service_networks, dict) and service_networks[net] is not None:
            check_keys(f"{where}.networks.{net}", service_networks[net], SERVICE_NETWORK_KEYS)


def validate(text):
    """Parse and check a compose file; returns it unchanged, or raises ComposeError."""
    if not raw_compose_enabled():
        raise ComposeError("Raw compose deploys are disabled: set ALLOWED_REGISTRIES and/or ALLOWED_IMAGES on the MCP server.")
    if len(text.encode()) > MAX_SIZE:
        raise ComposeError(f"The compose file is larger than {MAX_SIZE // 1024} KiB.")
    if "${{" in text:
        raise ComposeError("Dokploy ${{...}} references are not allowed.")
    try:
        doc = yaml.load(text, Loader=NoAliasLoader)  # noqa: S506 (a SafeLoader subclass)
    except yaml.YAMLError as exc:
        raise ComposeError(f"Invalid YAML: {exc}") from None
    check_keys("The compose file", doc, TOP_LEVEL)
    volumes, networks = doc.get("volumes") or {}, doc.get("networks") or {}
    for kind, declared, allowed in (("volumes", volumes, VOLUME_KEYS), ("networks", networks, NETWORK_KEYS)):
        check_keys(kind, declared, set(declared))
        for name, spec in declared.items():
            if not NAME.match(str(name)):
                raise ComposeError(f"{kind}.{name}: name not allowed.")
            if spec is not None:
                check_keys(f"{kind}.{name}", spec, allowed)
                check_labels(f"{kind}.{name}.labels", spec.get("labels"))
    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        raise ComposeError("The compose file needs at least one service.")
    for name, service in services.items():
        check_service(name, service, volumes, networks)
    return text
