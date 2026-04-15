# Cerberus AI

Headless multi-agent security runtime with a Reflex command-and-control dashboard.

Cerberus AI is built for operators who need deterministic execution, concurrent sessions, and a web control plane that reflects real runtime state. The project combines a policy-verified Python core, a session-aware subprocess engine, Redis-backed dashboard state, and a Docker-native deployment path for supervised investigations.

## Why It Exists

Security workflows break down when the model is asked to simulate controls that do not exist in code. Cerberus moves the important boundaries into the runtime itself: tool validation, workspace scoping, process lifecycle management, and operator kill controls are enforced programmatically instead of being left to prompt compliance.

## Core Runtime

### Command And Control Engine

The C2 path is implemented in the shared subprocess runtime at `src/cerberus/utils/process_handler.py`. It tracks processes by session, streams stdout and stderr in real time, and gives the dashboard a single source of truth for active task state.

### Kill Switch

The dashboard STOP action is wired through the same session registry used for execution. When an operator stops a session, the runtime calls the shared termination path and tears down the subprocess tree associated with that session instead of relying on UI-only state.

### Persistent State

`rxconfig.py` enables Redis-backed Reflex state automatically when `REDIS_URL` or `REFLEX_REDIS_URL` is present. The default Docker stack already includes Redis, so dashboard sessions can persist across refreshes without changing the application code.

### Commercial Permissiveness

Cerberus is released under MIT and is intended to be usable in internal platforms, professional services, and commercial products. The active runtime has been scrubbed away from the earlier proprietary framing rather than leaving the legal story ambiguous.

## Repository Layout

- `src/cerberus/` contains mission control, tool dispatch, memory services, policy enforcement, and the headless runtime.
- `cerberus_dashboard/` contains the Reflex web dashboard and multi-session operator surface.
- `dockerized/` contains the centralized Dockerfile, compose stack, env templates, and persistent Docker volume mounts.
- `docs/` contains architecture, operations, model, and workflow documentation.

## Quick Start

Prerequisites:

- Docker
- Docker Compose

Start the centralized stack from the repository root:

```bash
docker compose -f dockerized/docker-compose.yml up --build
```

Enable the host-networked runtime and Qdrant services when you need the full operator toolchain:

```bash
docker compose -f dockerized/docker-compose.yml --profile runtime up --build
```

> [!NOTE]
> The default stack publishes the dashboard on port `8000`, the backend API on port `8001`, and Redis on port `6379`. The optional runtime profile also exposes Qdrant on ports `6333` and `6334`.

After the services are ready:

1. Open `http://localhost:8000`.
2. Dispatch commands through the 2x2 session grid.
3. Watch live session logs stream in the terminal panes.
4. Use STOP on any active session to terminate its registered subprocesses.

## Architecture

- Frontend: Reflex provides the operator dashboard, session panes, and command surface.
- Runtime: Python mission control handles tool execution, workspace isolation, memory services, and streaming callbacks.
- Policy: deterministic validation gates commands before execution and enforces runtime boundaries in code.
- State: Redis backs Reflex state when configured, with disk fallback for local-only runs.

## Testing

Recent focused validation covered the runtime paths that drive the current dashboard and C2 flow.

- `tests/core/test_process_handler.py`
- `tests/tools/test_tool_generic_linux_sessions.py`
- `tests/tools/test_tool_generic_linux_command.py`
- `tests/tools/test_generic_linux_command_guardrails.py`

That set accounts for 25 passing tests across the process handler, session wiring, command execution, and guardrail paths.

## Documentation

- `INSTALL.md` for installation details.
- `dockerized/README_DOCKER.md` for the centralized container layout and compose commands.
- `docs/cai_architecture.md` and `docs/command_runner_design.md` for system design.
- `docs/quickstart.md` and `docs/running_agents.md` for operator workflow guidance.