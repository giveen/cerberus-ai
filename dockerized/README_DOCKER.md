# Dockerized Layout

All operational Docker assets now live under `dockerized/`.

## Files

- `dockerized/Dockerfile` is the single multi-stage build definition.
- `dockerized/docker-compose.yml` is the canonical compose entrypoint.
- `dockerized/docker-compose.dev.yaml` overlays source mounts for iterative development.
- `dockerized/.env/` contains tracked, non-secret environment defaults.
- `dockerized/volumes/` is the host-side persistence root for workspaces, logs, Redis, and Qdrant data.

The build is intentionally split:

- `frontend` keeps the Reflex dashboard on the existing Python slim lineage.
- `runtime` uses `kalilinux/kali-rolling` plus `kali-linux-headless` so the operator container retains the red-team toolchain.

## Default Stack

From the repository root, start the dashboard and Redis services with:

```bash
docker compose -f dockerized/docker-compose.yml up --build
```

This publishes:

- Dashboard UI on `http://localhost:8000`
- Reflex backend on `http://localhost:8001`
- Redis on `localhost:6379`

## Runtime Profile

Enable the host-networked runtime and Qdrant services when you need the full operator toolchain:

```bash
docker compose -f dockerized/docker-compose.yml --profile runtime up --build
```

That adds:

- `cerberus` runtime with `NET_ADMIN`, `NET_RAW`, `/dev/net/tun`, and a Kali-backed `kali-linux-headless` tool baseline
- Qdrant on `localhost:6333` and `localhost:6334`
- MCP sidecars for `container-mcp` (SSE on `http://container-mcp:8000/sse`) and `hexstrike-server` (HTTP on `http://hexstrike-server:8888`)

The runtime inherits its OpenAI-compatible LLM endpoint from `../.env`, for example `CEREBRO_API_BASE` or `CERBERUS_API_BASE`.

Do not point that value at `http://localhost:8001` or `http://127.0.0.1:8001`. Port `8001` is the Reflex dashboard backend, not an LLM API, so LiteLLM/OpenAI calls will return 404 there.

LiteLLM runs in client mode by default in this stack, so proxy/cold-storage message logging is disabled unless you explicitly opt in. Set `CERBERUS_LITELLM_MESSAGE_LOGGING=1` only when proxy extras are intentionally installed (for example `litellm[proxy]` with `orjson`) and you need that logging path.

If you only start the default stack, the runtime container is not launched and those Kali tools are not available to the operator path.

## MCP Wiring In Kali Runtime

The runtime image includes MCP bootstrap support and enables autoload by default. Managed servers (for example `wiremcp` and `nmap-mcp`) are prepared during image build, then connected at runtime when required binaries and environment variables are present.

External integrations are configured through `dockerized/.env/runtime.env`:

- `CERBERUS_HEXSTRIKE_MCP_COMMAND`: stdio launch command for the HexStrike bridge (for example `python3 /opt/hexstrike-ai/hexstrike_mcp.py --server http://127.0.0.1:8888`)
- `CERBERUS_PORTSWIGGER_MCP_URL`: Burp MCP SSE endpoint (for example `http://127.0.0.1:9876/sse`)
- `CERBERUS_CONTAINER_MCP_URL`: Container-MCP SSE endpoint (for example `http://127.0.0.1:8000/sse`)
- `CERBERUS_AWSOME_KALI_MCP_COMMAND`: stdio docker command for awsome-kali MCP (for example `docker run -i --rm kali-mcps:latest`)

If an integration variable is unset, MCP autoload skips that server and reports it as skipped with a missing-env reason.

To inspect current connect/skip/error status inside the runtime container:

```bash
docker compose -f dockerized/docker-compose.yml --profile runtime exec -T cerberus \
	python -c "import json; from cerberus.repl.commands.mcp import ensure_configured_mcp_servers, reset_mcp_bootstrap_state; reset_mcp_bootstrap_state(); print(json.dumps(ensure_configured_mcp_servers(force=True), indent=2))"
```

To explicitly include MCP sidecars while launching runtime:

```bash
docker compose -f dockerized/docker-compose.yml --profile runtime --profile mcp up --build
```

## Shutdown

If you started runtime or MCP profile services, stop the stack with the same profile set:

```bash
cd dockerized
docker compose --profile runtime --profile mcp down --remove-orphans
```

From the repository root you can also use:

```bash
make docker-down
```

Plain `docker compose down` only tears down services in the active Compose config and can leave profile-backed containers such as `cerberus`, `qdrant`, `container-mcp`, and `hexstrike-server` running.

## Development Overlay

To mount live source into both the runtime and dashboard containers:

```bash
docker compose -f dockerized/docker-compose.yml --profile runtime -f dockerized/docker-compose.dev.yaml up --build
```

After edits, restart only the affected service:

```bash
docker compose -f dockerized/docker-compose.yml --profile runtime -f dockerized/docker-compose.dev.yaml restart cerberus
docker compose -f dockerized/docker-compose.yml --profile runtime -f dockerized/docker-compose.dev.yaml restart cerberus-dashboard
```

## Volumes

Docker state now sits below `dockerized/volumes/`. The repository tracks only `dockerized/volumes/.gitkeep`; generated runtime data stays out of the Docker build context and out of version control.