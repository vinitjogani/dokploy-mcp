"""Revoke a connector by deleting its client (cascades to its tokens) or ticking a token's
``revoked``; review every tool call an agent made in the audit log."""
from django.contrib import admin
from django.contrib.auth.models import Group, User

from mcp.models import AuditLog, OAuthClient, OAuthToken

# ADMIN_USERNAME / ADMIN_PASSWORD are the source of truth (see ensure_admin): accounts and
# passwords changed here would be silently reset on the next boot.
admin.site.unregister(User)
admin.site.unregister(Group)


class ReadOnly(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields if f.name != "revoked"]


@admin.register(OAuthClient)
class ClientAdmin(ReadOnly):
    list_display = ("client_name", "client_id", "created_at")


@admin.register(OAuthToken)
class TokenAdmin(ReadOnly):
    list_display = ("client", "user", "scope", "revoked", "expires_at", "created_at")
    list_filter = ("revoked",)


@admin.register(AuditLog)
class AuditLogAdmin(ReadOnly):
    list_display = ("created_at", "tool", "ok", "token", "arguments")
    list_filter = ("ok", "tool")
