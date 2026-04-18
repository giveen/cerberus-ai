# Cerberus AI

Headless multi-agent security runtime with a web operator dashboard.

Cerberus AI gives operators a controlled execution environment where policy-verified tools run deterministically. Unlike simulated security workflows, Cerberus enforces real boundaries in code: tool validation, workspace isolation, process lifecycle management, and immediate kill-switch control—all programmatic, not prompt-based.

## What You Get

- **Web Command & Control**: 2x2 session grid with live log streams and persistent operator state
- **Concurrent Sessions**: Run multiple agents or tasks independently with full isolation
- **Process Control**: Real subprocess tracking with instant termination
- **Policy Enforcement**: Deterministic validation gates and runtime guardrails
- **Redis State Persistence**: Sessions survive dashboard restarts (or run local-only)
- **Docker-Ready**: Centralized compose stack with optional runtime profiling tools

## Quick Start

**Prerequisites:** Docker and Docker Compose

Build from the `dockerized/` directory:

```bash
cd dockerized
docker compose build
```

Or from the repository root:

```bash
make docker-build
```

Start the default dashboard stack:

```bash
docker compose up -d
```

If you want the full runtime profile as well:

```bash
docker compose --profile runtime --profile mcp up -d
```

To stop the stack cleanly, use the profile-aware shutdown command:

```bash
make docker-down
```

Equivalent direct command:

```bash
cd dockerized
docker compose --profile runtime --profile mcp down --remove-orphans
```

Then:

1. Open `http://localhost:8000` in your browser
2. Wait up to a minute on first startup while the dashboard services warm up and health checks settle
3. Dispatch commands through the 2x2 session grid
4. Watch live logs stream in the terminal panes  
5. Click **STOP** on any session to terminate its subprocess tree

> [!NOTE]
> Default ports: dashboard (8000), API (8001), Redis (6379). The first dashboard load can take a minute after `docker compose up -d`, especially after a fresh build or when runtime sidecars are also starting.

> [!IMPORTANT]
> Plain `docker compose down` from `dockerized/` only tears down services visible in the currently active Compose profile set. If you previously started `runtime` or `mcp` services, use the profile-aware shutdown command above so `cerberus`, `qdrant`, `container-mcp`, and `hexstrike-server` are removed as well.

## Local Development Setup

For hands-on development without containers:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[browser,crawler,vault,voice,viz]"
python -m playwright install chromium
```

See [INSTALL.md](INSTALL.md) for detailed environment configuration and optional dependencies.

## How It Works

| Component | Purpose |
|-----------|---------|
| **Frontend** | Reflex-based dashboard with session panes, command bar, and log viewers |
| **Runtime** | Python mission control: tool execution, workspace isolation, memory services, streaming |
| **Policy** | Validation gates and guardrails enforce execution boundaries at runtime |
| **State** | Redis-backed (persistent) or disk-based (local) session and command history |

The core subprocess engine lives in [src/cerberus/utils/process_handler.py](src/cerberus/utils/process_handler.py) and tracks sessions in real time. Dashboard STOP actions route through the same session registry, guaranteeing clean subprocess teardown.

## Repository Structure

```
src/cerberus/            Core runtime, tools, agents, memory, guardrails
├── dashboard/           Reflex web UI components
├── agents/              Agent orchestration and execution
├── tools/               Tool library (network, web, recon, etc.)
├── memory/              Episodic and semantic memory services
└── utils/               Shared utilities (process handling, validation)

dockerized/              Docker Compose, env templates, volume mounts
tests/                   Test suite covering runtime, tools, guards
```

## Testing

Core validation includes:

- Process handler lifecycle and session tracking
- Command execution with workspace isolation  
- Tool guardrails and policy enforcement
- Live dashboard/C2 state flow

Run tests with:

```bash
pytest tests/core/test_process_handler.py
pytest tests/tools/test_generic_linux_command_guardrails.py
```

## Further Reading

- [INSTALL.md](INSTALL.md) – Full setup with optional extras (browser, vault, voice, viz)
- [dockerized/README_DOCKER.md](dockerized/README_DOCKER.md) – Container layout and compose profiles
- [LICENSE](LICENSE) – MIT License

## License

MIT. Designed for use in internal platforms, professional services, and commercial products.