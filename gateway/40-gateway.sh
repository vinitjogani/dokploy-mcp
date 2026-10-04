#!/bin/sh
# Mounted into the stock nginx image's /docker-entrypoint.d/: writes the gateway's config on every
# start. REGISTRY_PROFILES is the stack's COMPOSE_PROFILES; containing "registry" turns on the
# registry routes. The registry itself has no auth: nginx checks every login against
# /auth/htpasswd, which the registry-auth container rewrites on every deploy (nginx re-reads it
# on each request, so new logins apply without a restart).
#
# REGISTRY_IPS (comma-separated addresses or CIDR ranges) limits the registry and its UI to those
# client addresses; the MCP's routes stay open to everyone. "*" opens the registry to any address;
# empty (or unset) closes it to every address.
set -eu

conf=/etc/nginx/conf.d/default.conf

case ",${REGISTRY_PROFILES:-}," in *,registry,*) registry=1 ;; *) registry= ;; esac
if [ -n "$registry" ]; then echo "gateway: registry on"; else echo "gateway: registry off"; fi

# Prints 0 if $1 is an IPv4 or IPv6 address, optionally with a /prefix, that nginx's "allow" takes.
valid_ip() {
    case "$1" in
        */) return 1 ;;
        */*) addr=${1%/*} prefix=${1#*/} ;;
        *) addr=$1 prefix= ;;
    esac
    case "$prefix" in *[!0-9]*) return 1 ;; esac
    case "$addr" in
        *:*)
            case "$addr" in *[!0-9a-fA-F:.]*|*:::*) return 1 ;; esac
            [ -z "$prefix" ] || [ "$prefix" -le 128 ]
            ;;
        *.*.*.*)
            echo "$addr" | awk -F. 'NF != 4 { exit 1 }
                { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }' || return 1
            [ -z "$prefix" ] || [ "$prefix" -le 32 ]
            ;;
        *) return 1 ;;
    esac
}

# The registry's allowlist, as the body of an nginx "geo" block. Closed unless REGISTRY_IPS says
# otherwise, and any bad entry denies everyone, so a typo never opens the registry up wider than
# intended.
closed="    default 0;
"
rules=$closed
if [ -n "$registry" ]; then
    entries=
    allowed=
    bad=
    any=
    set -f
    IFS=', '
    for entry in ${REGISTRY_IPS:-}; do
        if [ "$entry" = "*" ]; then
            any=1
        elif valid_ip "$entry"; then
            entries="$entries    $entry 1;
"
            allowed="$allowed $entry"
        else
            bad="$bad $entry"
        fi
    done
    unset IFS
    set +f
    if [ -n "$bad" ]; then
        echo "gateway: REGISTRY_IPS has invalid entries:$bad; the registry refuses everyone" >&2
    elif [ -n "$any" ] && [ -n "$allowed" ]; then
        echo "gateway: REGISTRY_IPS mixes \"*\" with addresses; use \"*\" alone to open it to all. The registry refuses everyone" >&2
    elif [ -n "$any" ]; then
        echo "gateway: REGISTRY_IPS=*: the registry is open to any address (logins still apply)"
        rules="    default 1;
"
    elif [ -n "$allowed" ]; then
        echo "gateway: registry open only to:$allowed"
        rules="$closed$entries"
    else
        echo "gateway: REGISTRY_IPS is empty; the registry refuses every address (set it, or \"*\" for any)" >&2
    fi
fi

write_conf() {
: > "$conf"
if [ -n "$registry" ]; then
    cat >> "$conf" <<'NGINX'
# Behind Cloudflare, the peer is a Cloudflare edge and the client's address is in
# CF-Connecting-IP, which Cloudflare always sets itself. It is believed only when the peer is one
# of Cloudflare's published ranges (www.cloudflare.com/ips), so nobody else can forge it.
geo $registry_peer_is_cloudflare {
    default 0;
    173.245.48.0/20 1; 103.21.244.0/22 1; 103.22.200.0/22 1; 103.31.4.0/22 1;
    141.101.64.0/18 1; 108.162.192.0/18 1; 190.93.240.0/20 1; 188.114.96.0/20 1;
    197.234.240.0/22 1; 198.41.128.0/17 1; 162.158.0.0/15 1; 104.16.0.0/13 1;
    104.24.0.0/14 1; 172.64.0.0/13 1; 131.0.72.0/22 1;
    2400:cb00::/32 1; 2606:4700::/32 1; 2803:f800::/32 1; 2405:b500::/32 1;
    2405:8100::/32 1; 2a06:98c0::/29 1; 2c0f:f248::/32 1;
}

map "$registry_peer_is_cloudflare $http_cf_connecting_ip" $registry_client {
    "~^1 (?<cf_client>[0-9A-Fa-f.:]+)$" $cf_client;
    default $remote_addr;
}

log_format gateway '$remote_addr - $remote_user [$time_local] "$request" $status '
                   '$body_bytes_sent "$http_referer" "$http_user_agent" client=$registry_client';

geo $registry_client $registry_ip_allowed {
NGINX
    printf '%s' "$rules" >> "$conf"
    echo '}' >> "$conf"
fi

# Docker's resolver, re-asked every 10 s: upstreams are looked up per request, so nginx starts
# (and the MCP stays up) whatever state the other containers are in.
cat >> "$conf" <<'NGINX'
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
    cat >> "$conf" <<'NGINX'
    set $registry http://dokploy-mcp-registry:5000;
    set $registry_ui http://dokploy-mcp-registry-ui:80;

    # The peer Traefik saw, the same address the MCP uses: Traefik overwrites X-Forwarded-For
    # from untrusted clients, and its last entry is that peer. $registry_client (below) is the
    # address REGISTRY_IPS is checked against; the access log shows it as client=.
    set_real_ip_from 0.0.0.0/0;
    set_real_ip_from ::/0;
    real_ip_header X-Forwarded-For;
    real_ip_recursive off;
    access_log /var/log/nginx/access.log gateway;

    # The MCP server (Django): its URL prefixes. Open to every address.
    location ~ ^/(mcp|oauth|admin|static|\.well-known)(/|$) {
        proxy_pass $mcp;
    }

    # The registry API (docker login/push/pull, and the UI's own calls).
    location /v2/ {
        if ($registry_ip_allowed = 0) {
            return 403;
        }
        auth_basic "Registry";
        auth_basic_user_file /auth/htpasswd;
        add_header Docker-Distribution-Api-Version $docker_distribution_api_version always;
        # Docker 1.5 and earlier mishandle the auth flow.
        if ($http_user_agent ~ "^(docker/1\.(3|4|5(?!\.[0-9]-dev))|Go ).*$") {
            return 404;
        }
        proxy_pass $registry;
    }

    # Everything else: the UI, behind the same login, so the browser asks once.
    location / {
        if ($registry_ip_allowed = 0) {
            return 403;
        }
        auth_basic "Registry";
        auth_basic_user_file /auth/htpasswd;
        proxy_pass $registry_ui;
    }
}
NGINX
else
    cat >> "$conf" <<'NGINX'
    location / {
        proxy_pass $mcp;
    }
}
NGINX
fi
}

write_conf

# Should nginx still reject an address, lock the registry rather than take the MCP down with it.
if [ -n "$registry" ] && ! nginx -t -q 2>/dev/null; then
    echo "gateway: nginx rejected the REGISTRY_IPS rules; the registry refuses everyone" >&2
    rules=$closed
    write_conf
fi
