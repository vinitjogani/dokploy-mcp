"""Settings for the Dokploy MCP server. Everything deployment-specific comes from the environment
(see .env.example); the defaults are the production ones, so a missing variable fails closed."""
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)


def env_list(name, default=""):
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


# The origin connectors reach us on (https://mcp.example.com). Every OAuth URL we advertise is built
# from it rather than from request headers, so no proxy hop or caller can rewrite it.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
_public = urlsplit(PUBLIC_BASE_URL)
if _public.scheme not in {"http", "https"} or not _public.hostname or _public.path:
    raise ImproperlyConfigured("PUBLIC_BASE_URL must be an origin such as https://mcp.example.com")

ALLOWED_HOSTS = [_public.hostname]
CSRF_TRUSTED_ORIGINS = [PUBLIC_BASE_URL]

# Generated once and kept on the data volume (delete the file to rotate it).
_key_file = DATA_DIR / "secret_key"
if not _key_file.exists():
    _key_file.write_text(secrets.token_urlsafe(64))
    _key_file.chmod(0o600)
SECRET_KEY = _key_file.read_text().strip()

# Dokploy is reached over dokploy-network (the panel is the swarm service "dokploy"), so API
# traffic never leaves the host.
DOKPLOY_URL = os.getenv("DOKPLOY_URL", "http://dokploy:3000").rstrip("/")
DOKPLOY_API_KEY = os.getenv("DOKPLOY_API_KEY", "")
# Domains add_domain may route (subdomains included); a bare "blog" becomes "blog.<first one>".
# Defaults to the parent domain of PUBLIC_BASE_URL (mcp.example.com -> example.com).
DOMAINS = [d.strip(".").lower() for d in env_list("DOMAINS", _public.hostname.partition(".")[2])]
# Compose services the MCP may read but never change, in addition to its own (the one serving
# PUBLIC_BASE_URL, or named dokploy-mcp). Matched case-insensitively against the service's id,
# name, appName, or GitHub repository ("owner/name" or "name").
PROTECTED_SERVICES = {s.lower() for s in env_list("PROTECTED_SERVICES")} | {"dokploy-mcp"}
# Hosts that may never be routed to a service (the Dokploy panel, this server, ...).
PROTECTED_HOSTS = {h.lower() for h in env_list("PROTECTED_HOSTS")} | {_public.hostname}
# Raw compose deploys (no GitHub repo) are off unless one of these is set. Every image in such a
# compose file must come from an ALLOWED_REGISTRIES host ("*" for any) or match ALLOWED_IMAGES:
# "ghcr.io/acme/blog" (any tag), "nginx:1.27" (that tag only), "ghcr.io/acme/*" (a namespace).
ALLOWED_REGISTRIES = {"docker.io" if r in {"index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"} else r
                      for r in (r.lower() for r in env_list("ALLOWED_REGISTRIES"))}
ALLOWED_IMAGES = env_list("ALLOWED_IMAGES")
# Redirect URIs a connector may register, besides http://localhost:<port>/... for local apps.
OAUTH_REDIRECT_URIS = env_list("OAUTH_REDIRECT_URIS", "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "mcp",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "project.urls"
WSGI_APPLICATION = "project.wsgi.application"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": DATA_DIR / "db.sqlite3"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
TIME_ZONE = "UTC"
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {"staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"}}

# The admin login is the only thing guarding the Dokploy instance, so: strong passwords, and
# failed logins throttled per client (see mcp.oauth.ThrottledBackend).
AUTHENTICATION_BACKENDS = ["mcp.oauth.ThrottledBackend"]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LOGIN_FAILURE_LIMIT = 10  # per client IP per 15 minutes; five times that from everyone together

# TLS terminates at Traefik, which always sets X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 31536000
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = _public.scheme == "https"
SESSION_COOKIE_AGE = 12 * 3600
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,  # keep gunicorn's access log
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
