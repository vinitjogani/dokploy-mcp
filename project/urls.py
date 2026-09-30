from django.contrib import admin
from django.urls import path, re_path

from mcp import oauth, views

urlpatterns = [
    path("admin/", admin.site.urls),
    re_path(r"^mcp/?$", views.mcp),
    path("oauth/register", oauth.register),
    path("oauth/authorize", oauth.authorize, name="oauth_authorize"),
    path("oauth/token", oauth.token),
    # Clients may insert the resource path into the well-known URL (RFC 9728 section 3.1).
    re_path(r"^\.well-known/oauth-authorization-server(?:/mcp)?$", oauth.authorization_server_metadata),
    re_path(r"^\.well-known/oauth-protected-resource(?:/mcp)?$", oauth.protected_resource_metadata),
]
