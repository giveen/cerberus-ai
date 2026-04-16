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

The runtime inherits its OpenAI-compatible LLM endpoint from `../.env`, for example `CEREBRO_API_BASE` or `CERBERUS_API_BASE`.

Do not point that value at `http://localhost:8001` or `http://127.0.0.1:8001`. Port `8001` is the Reflex dashboard backend, not an LLM API, so LiteLLM/OpenAI calls will return 404 there.

LiteLLM runs in client mode by default in this stack, so proxy/cold-storage message logging is disabled unless you explicitly opt in. Set `CERBERUS_LITELLM_MESSAGE_LOGGING=1` only when proxy extras are intentionally installed (for example `litellm[proxy]` with `orjson`) and you need that logging path.

If you only start the default stack, the runtime container is not launched and those Kali tools are not available to the operator path.

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