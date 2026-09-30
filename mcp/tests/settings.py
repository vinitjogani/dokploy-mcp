import os
import tempfile

os.environ.update(PUBLIC_BASE_URL="https://mcp.example.com", DATA_DIR=tempfile.mkdtemp(), DOMAINS="example.com",
                  PROTECTED_HOSTS="dokploy.example.com", PROTECTED_SERVICES="dokploy-mcp")

from project.settings import *  # noqa: E402,F403

ALLOWED_HOSTS = ["mcp.example.com", "testserver"]
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # speed only
STORAGES = {"staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}}
