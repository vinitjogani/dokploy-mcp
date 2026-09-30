"""OAuth 2.1 storage (only SHA-256 hashes of secrets are ever stored) and the audit log of every
tool call."""
from django.conf import settings
from django.db import models

SCOPE_DESTRUCTIVE = "dokploy:destructive"


class OAuthClient(models.Model):
    client_id = models.CharField(max_length=64, unique=True)
    client_secret_hash = models.CharField(max_length=64, blank=True, default="")
    client_name = models.CharField(max_length=100, blank=True, default="")
    redirect_uris = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.client_name or self.client_id


class OAuthGrant(models.Model):
    code_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    redirect_uri = models.CharField(max_length=500)
    code_challenge = models.CharField(max_length=128)
    scope = models.CharField(max_length=100)
    expires_at = models.DateTimeField()


class OAuthToken(models.Model):
    access_token_hash = models.CharField(max_length=64, unique=True)
    refresh_token_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    scope = models.CharField(max_length=100)
    revoked = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.client} ({self.scope})"


class AuditLog(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    token = models.ForeignKey(OAuthToken, null=True, on_delete=models.SET_NULL)
    tool = models.CharField(max_length=64)
    arguments = models.JSONField(default=dict)
    ok = models.BooleanField()
    result = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
