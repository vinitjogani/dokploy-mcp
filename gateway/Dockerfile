# Front door for the whole stack: Traefik routes the domain here (port 80), and this routes the
# MCP's paths to it and, with the registry profile on, /v2/ to the registry and the rest to its UI.
FROM nginx:1.29-alpine
# htpasswd, to hash REGISTRY_USERS into nginx's basic-auth file at start-up.
RUN apk add --no-cache apache2-utils
COPY 40-gateway.sh /docker-entrypoint.d/
