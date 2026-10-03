#!/bin/sh
# Writes the nginx config on every start, so every deploy applies the current environment:
#   REGISTRY_PROFILES  the stack's COMPOSE_PROFILES; containing "registry" turns the registry on.
#   REGISTRY_USERS     its logins, "user:password,user2:password2" (a password may contain ":").
# The registry itself runs without auth on a private network: nginx checks every login.
set -eu

conf=/etc/nginx/conf.d/default.conf
users=/etc/nginx/registry.htpasswd

case ",${REGISTRY_PROFILES:-}," in *,registry,*) registry=1 ;; *) registry= ;; esac

# Docker's resolver, re-asked every 10 s: upstreams are looked up per request, so nginx starts
# (and the MCP stays up) whatever state the other containers are in.
cat > "$conf" <<'NGINX'
resolver 127.0.0.11 valid=10s ipv6=off;

map $upstream_http_docker_distribution_api_version $docker_distribution_api_version {
    "" "registry/2.0";
}

server {
    listen 80 default_server;
    server_tokens off;

    # Image layers: no size limit, stream both ways.
    client_max_body_size 0;
    chunked_transfer_encoding on;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 900s;
    proxy_send_timeout 900s;

    # Pass on what Traefik saw, unchanged: the MCP rate-limits logins by the last X-Forwarded-For
    # entry, which must stay the client's address rather than Traefik's.
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
    proxy_set_header X-Forwarded-Host $host;

    set $mcp http://dokploy-mcp-app:8000;
NGINX

if [ -n "$registry" ]; then
    tmp="$users.tmp"
    : > "$tmp"
    n=0
    # Never fails: a bad entry is skipped and logged, since failing here would take the MCP down.
    set -f  # no globbing of passwords
    IFS=,
    for entry in ${REGISTRY_USERS:-}; do
        case "$entry" in
            ?*:?*) htpasswd -Bbn "${entry%%:*}" "${entry#*:}" | head -n1 >> "$tmp"; n=$((n + 1)) ;;
            "") ;;
            *) echo "gateway: skipping a REGISTRY_USERS entry that is not user:password" >&2 ;;
        esac
    done
    unset IFS
    set +f
    chmod 640 "$tmp" && chgrp nginx "$tmp" && mv "$tmp" "$users"
    if [ "$n" -eq 0 ]; then
        echo "gateway: registry on but REGISTRY_USERS has no logins: every request will be refused" >&2
    else
        echo "gateway: registry on, users: $(cut -d: -f1 "$users" | paste -sd, -)"
    fi

    cat >> "$conf" <<'NGINX'
    set $registry http://dokploy-mcp-registry:5000;
    set $registry_ui http://dokploy-mcp-registry-ui:80;

    # The MCP server (Django): its URL prefixes.
    location ~ ^/(mcp|oauth|admin|static|\.well-known)(/|$) {
        proxy_pass $mcp;
    }

    # The registry API (docker login/push/pull, and the UI's own calls).
    location /v2/ {
        auth_basic "Registry";
        auth_basic_user_file /etc/nginx/registry.htpasswd;
        add_header Docker-Distribution-Api-Version $docker_distribution_api_version always;
        # Docker 1.5 and earlier mishandle the auth flow.
        if ($http_user_agent ~ "^(docker/1\.(3|4|5(?!\.[0-9]-dev))|Go ).*$") {
            return 404;
        }
        proxy_pass $registry;
    }

    # Everything else: the UI, behind the same login, so the browser asks once.
    location / {
        auth_basic "Registry";
        auth_basic_user_file /etc/nginx/registry.htpasswd;
        proxy_pass $registry_ui;
    }
}
NGINX
else
    rm -f "$users"
    echo "gateway: registry off"
    cat >> "$conf" <<'NGINX'
    location / {
        proxy_pass $mcp;
    }
}
NGINX
fi
