import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from mcp.models import SCOPE_DESTRUCTIVE, OAuthClient, OAuthToken
from mcp.oauth import ACCESS_TTL, REFRESH_TTL, sha256


@pytest.fixture
def admin(db):
    return get_user_model().objects.create_superuser("admin", password="a-long-enough-passw0rd")


def make_token(user, scope=f"dokploy {SCOPE_DESTRUCTIVE}", raw="raw-token"):
    client = OAuthClient.objects.create(client_id=f"c-{raw}", redirect_uris=["https://claude.ai/cb"])
    now = timezone.now()
    return OAuthToken.objects.create(access_token_hash=sha256(raw), refresh_token_hash=sha256(raw + "r"), client=client,
                                     user=user, scope=scope, expires_at=now + ACCESS_TTL, refresh_expires_at=now + REFRESH_TTL)


@pytest.fixture
def token(admin):
    return make_token(admin)
