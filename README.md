# dokploy-mcp

A small, locked-down [MCP](https://modelcontextprotocol.io) server that lets AI agents
(claude.ai, the Claude apps, Claude Code, …) deploy and manage **Docker Compose services on
your Dokploy instance**, straight from your GitHub repos, or (if you allow it) from raw compose
files using prebuilt images from registries you allowlist. It runs as a Dokploy app itself, at
`https://mcp.example.com/mcp`.

Django + OAuth 2.1, no MCP SDK: `mcp/tools.py` (the tools and their guards), `mcp/oauth.py`
(authorization server), `mcp/views.py` (JSON-RPC endpoint), `mcp/dokploy.py` (API client),
`mcp/compose.py` (raw compose file checks).

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `list_services` | read | Projects and their compose services with repo, branch, status and URLs; `repo` filter finds the service that deploys a given GitHub repo. |
| `get_service` | read | One service: settings, env var **names**, domains, compose service names, recent deployments (and the compose file, for raw ones). |
| `get_deployment_logs` | read | Build/deploy log of the latest (or a given) deployment: git pull, image build, start-up. |
| `get_container_logs` | read | Runtime stdout/stderr of one running container of a service. |
| `create_service` | write | Project (found or created) + compose service building from `owner/repo`, auto-deploying on every push to the branch (so a merged PR deploys itself), optional env vars. |
| `create_compose_service` | write | Same, from a raw compose file instead of a repo: prebuilt images only, from `ALLOWED_REGISTRIES` / `ALLOWED_IMAGES` (see below). No auto-deploy. Only offered when an allowlist is set. |
| `set_compose_file` | write | Replace a service's compose file with raw content (same checks); switches a GitHub service to it. |
| `update_service` | write | Repo, branch, compose path, auto-deploy, watch paths. |
| `set_env_vars` | write | Add/overwrite variables; other variables are kept. |
| `add_domain` | write | `https://blog.example.com` → a compose service/port, Let's Encrypt certificate. `"blog"` is enough. `https=false` for hosts behind a TLS proxy such as Cloudflare (Flexible SSL), which would otherwise redirect-loop. |
| `deploy_service` | write | Pull, build, restart now (applies env/domain changes). |
| `rename_service` | destructive | Rename (display name only; containers/volumes keep their prefix). |
| `remove_env_vars` | destructive | Delete variables. |
| `remove_domain` | destructive | Unroute a domain. |
| `stop_service` | destructive | Stop containers (data kept). |
| `delete_service` | destructive | Delete a service; volumes too only if asked. |
| `delete_project` | destructive | Delete an **empty** project. |

A typical agent session: `list_services(repo="acme/blog")` → nothing → `create_service` →
`add_domain(host="blog", service="web", port=3000)` → `set_env_vars` → `deploy_service` →
`get_deployment_logs` until it is green (`get_container_logs` once it runs). From then on, every merge to `main` redeploys automatically; the
agent only calls `deploy_service` after changing env vars or domains.

Env values given to the server are written in the `.env` Dokploy places next to the compose file
(used for `${VAR}` interpolation, or `env_file: .env`). They are never shown back to agents.

## Raw compose files

Off by default. Set `ALLOWED_REGISTRIES` and/or `ALLOWED_IMAGES` to let agents deploy a compose
file directly (`create_compose_service`, `set_compose_file`) using prebuilt images:

```
ALLOWED_REGISTRIES=ghcr.io                      # any image from these registries ("*" = any registry)
ALLOWED_IMAGES=nginx,redis:7,quay.io/acme/*     # or just these, whatever their registry
```

An `ALLOWED_IMAGES` entry without a tag allows every tag (`nginx`); with a tag or digest, only that
one (`redis:7`); ending in `/*`, everything under that namespace (`quay.io/acme/*`). `docker.io`
means Docker Hub, and `nginx` is `docker.io/library/nginx`.

A compose file is root on the host, so only a safe subset of the compose spec is accepted; the
rest is refused with an error naming the offending key:

* every service needs an allowed `image` (no `build`, no `${...}` in it);
* volumes are named volumes declared under top-level `volumes` (no host paths, Docker socket,
  `driver_opts` binds, or `external`/`name` adopting another stack's data), or `tmpfs`;
* no `privileged`, `cap_add`, `devices`, `security_opt`, `network_mode`, `pid`, `ipc`, `ports`,
  `container_name`, `extends`, `include`, `secrets`/`configs`, top-level `name`, external networks;
* no `traefik.*`/`com.docker.*` labels (routing goes through `add_domain`), no Dokploy
  `${{...}}` references, `env_file` only as `.env`, no YAML anchors, at most 64 KiB.

Raw services do not auto-deploy: the agent changes the tag and calls `deploy_service` (or uses
`pull_policy: always` to re-pull the same tag on every deploy).

## Approvals for destructive tools

Destructive tools are separate tools, annotated `destructiveHint: true`, so every client can gate
them on their own:

* **Claude Code** — they also carry `_meta["anthropic/requiresUserInteraction"]`, so Claude Code
  (v2.1.199+) asks you before **every** call, in any permission mode and whatever your allow
  rules say. Allow the rest if you like: `"allow": ["mcp__dokploy__list_services", ...]`.
* **claude.ai / Claude apps** — connector settings → *Tool permissions*: set the destructive
  tools to **Needs approval** (Claude prompts for them by default) and the rest to *Always allow*.
* **Per connection** — the consent screen has an "Also allow destructive tools" checkbox. Untick
  it and that connector never even sees them.

## Security model

Assume a prompt-injected agent holds a valid token. Everything below holds anyway; each is
enforced in code and covered by tests.

* **Only your code is deployed.** A repo must be one the Dokploy GitHub App can already access
  (checked live), and the branch must exist. Raw compose files are off unless you set an image
  allowlist, and then pass the checks above (only images you allow, nothing that reaches the
  host). No custom git URLs or custom `docker` commands: those give root on the host. Only
  allowlisted Dokploy fields are ever sent.
* **Strict input patterns** on every argument (names, branches, compose paths, hosts, URL paths,
  env keys/values) block the injection points found in Dokploy itself: `..` in compose paths
  (arbitrary file writes on the host), Traefik rule injection through the domain path, and
  newline injection into `.env`. Env keys may not steer Docker itself (`COMPOSE_*`, `DOCKER_*`),
  and values may not use Dokploy's `${{...}}` references, which could copy other secrets into an
  app whose logs an agent can read.
* **No host hijacking.** `add_domain` refuses hosts used by another service, the Dokploy panel,
  this server, or `PROTECTED_HOSTS`, and hosts outside `DOMAINS`. (Hosts that a compose file
  routes with its own hand-written Traefik labels are invisible to Dokploy, so to this check.)
* **The server cannot change itself** (the service serving its own host, or named/deployed from
  `dokploy-mcp`) or anything in `PROTECTED_SERVICES`, so an agent cannot, say, reset
  `ADMIN_PASSWORD` or repoint it at another repo. Only compose services are managed;
  applications and databases are out of reach.
* **Secrets stay put.** Env values, deploy-webhook tokens and SSH keys that Dokploy returns are
  never forwarded; the audit log redacts env values.
* **Deleting a project** only works once it is empty (Dokploy would otherwise leave its
  containers running and publicly routed).
* **Logins.** OAuth 2.1 + PKCE (S256) with rotating refresh tokens; client registration only
  accepts Claude's exact callback URLs (`OAUTH_REDIRECT_URIS`) or local `http://localhost` ones;
  the consent screen needs your superuser login (≥12 characters, not a common password; 10
  failures per IP, or 50 overall, per 15 minutes lock the login). `ADMIN_USERNAME` is the only
  account: any other is deactivated on boot. The Dokploy API key goes only to `DOKPLOY_URL`: no
  proxies, no redirects.
* **Audit log** of every tool call (who, what, result) in `/admin`.

Remaining trust: whoever can push to your repos can run anything in their compose files (and so
also, for example, claim the `dokploy` name on `dokploy-network` that `DOKPLOY_URL` uses). That is
Dokploy's model too; this server just makes sure it is *your* repos. Likewise, whoever can push
to an allowlisted image (or registry, or `*`: all of Docker Hub) can run their code on the host
inside an unprivileged container, with the network access every container has.

## Setup

1. **Dokploy API key**: Dokploy → Settings → Profile → API keys, as the owner/admin, with rate
   limiting **off** (if enabled, its default is 10 requests per day).
2. **Create the service** in Dokploy: a project (e.g. `infra`) → *Compose* service named
   `dokploy-mcp`, source: this GitHub repo, branch `main`, compose path `docker-compose.yml`.
3. **Environment** (see `.env.example`):
   ```
   PUBLIC_BASE_URL=https://mcp.example.com
   ADMIN_PASSWORD=<a long passphrase>
   DOKPLOY_API_KEY=<from step 1>
   DOMAINS=example.com
   ```
   If the site is down after a deploy, check the `mcp` container logs: a weak `ADMIN_PASSWORD`
   stops it from starting.
4. **Domain**: `mcp.example.com` → service `gateway`, port `80`, HTTPS, Let's Encrypt. Deploy.
   (`gateway` is a stock nginx in front of the MCP, configured by `gateway/40-gateway.sh`; it also
   serves the optional registry below.)
5. **Connect an agent** to `https://mcp.example.com/mcp`:
   * claude.ai: Settings → Connectors → *Add custom connector*.
   * Claude Code: `claude mcp add --transport http dokploy https://mcp.example.com/mcp`, then `/mcp`
     to sign in.

   A browser window asks you to log in (`admin` / `ADMIN_PASSWORD`) and approve the connection.

The container reaches Dokploy at `http://dokploy:3000` over `dokploy-network` (the panel's own
swarm service), so API traffic never leaves the machine and no host networking or published
port is needed. If your Dokploy runs differently, set `DOKPLOY_URL` (for example
`http://host.docker.internal:3000` plus `extra_hosts: ["host.docker.internal:host-gateway"]`).

## Operating it

* **Change the password / kick every agent out:** change `ADMIN_PASSWORD` and redeploy. The new
  password applies on boot and every existing token is revoked.
* **Revoke one connector:** `/admin` → OAuth clients → delete it (or tick *revoked* on a token).
* **Rotate the session/signing key:** delete `/data/secret_key` from the volume and redeploy.
* **What did an agent do?** `/admin` → Audit logs.

## Optional: container registry

The same deploy can also run a private Docker registry (`registry:2`) with a web UI
(`joxit/docker-registry-ui`), on the **same domain**, handy for pushing images that raw compose
services then pull. It is off by default. To turn it on, add to the service's environment and
deploy:

```
COMPOSE_PROFILES=registry
REGISTRY_USERS=alice:<password>,ci:<password>
REGISTRY_IPS=203.0.113.5,198.51.100.0/24   # optional: who may reach the registry and UI
```

No extra domains: the gateway keeps routing the MCP's paths (`/mcp`, `/oauth/`, `/admin/`,
`/static/`, `/.well-known/`) to it, sends `/v2/` to the registry, and everything else to the UI.
Then `docker login mcp.example.com` and push `mcp.example.com/team/app:1`; the UI is at
`https://mcp.example.com/`.

* **Logins** live only in `REGISTRY_USERS` (`user:password`, comma-separated; a password may
  contain `:` but not `,`). On every deploy a one-shot `registry-auth` container (stock
  `httpd:2-alpine`, for its `htpasswd`) rebuilds a bcrypt htpasswd file from it, and the gateway
  (stock `nginx:1.29-alpine`) checks every registry and UI request against that file, re-reading
  it each time. So adding a user, changing a password or removing someone is an env edit plus a
  deploy. The registry itself has no auth and sits on a private network only the gateway can
  reach. An entry without `user:password` is skipped and `registry-auth` exits with an error
  (see its logs); with no valid entry, every registry request is refused. The MCP keeps working
  either way.
* **IP allowlist:** `REGISTRY_IPS=203.0.113.5,198.51.100.0/24` (addresses or CIDR ranges, IPv4 or
  IPv6, comma-separated) limits the registry API and the UI to those client addresses; anyone
  else gets `403` before the login prompt. The MCP's paths stay open to every address. Empty (the
  default) means any address, logins still required. The gateway takes the client's address from
  the last `X-Forwarded-For` entry, as the MCP does, so behind a CDN or another proxy in front of
  Traefik that is the proxy's address, not the client's. An invalid entry locks the registry for
  everyone (see the `gateway` logs) rather than opening it; the MCP keeps working. Since the
  address comes from a header, a container on the host's `dokploy-network` could forge it, which
  is why the logins still apply on top. Changes take effect on the next deploy.
* **Optional:** `REGISTRY_HTTP_SECRET` (a long random string; otherwise a random one per start,
  which only interrupts uploads in flight during a restart), `REGISTRY_TITLE` (shown in the UI).
* Agents cannot touch any of this: it is part of this server's own service, which the tools never
  change. (The `mcp` container does receive these variables through `env_file: .env`, so changing
  them restarts it too.)
* To turn it off, remove `COMPOSE_PROFILES`, deploy, and stop the leftover `registry*` containers;
  images stay in the `registry-data` volume.

To let agents deploy from it, add it to `ALLOWED_REGISTRIES=mcp.example.com` and run
`docker login mcp.example.com` once on the Dokploy host so compose deploys can pull.

## Development

```
pip install -r requirements.txt pytest pytest-django
pytest
```

Tests use a fake Dokploy. The tools were also run end to end against a real Dokploy v0.30.8,
including a full OAuth consent in a browser through Dokploy's Traefik.
