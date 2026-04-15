# Cerberus AI

The Headless Multi-Agent Security Engine | Command & Control Dashboard

Cerberus AI is a headless-first security runtime built for teams that need deterministic controls, concurrent agent execution, and an operator-facing command surface that behaves like infrastructure instead of a demo. It combines a policy-verified Python core, a Reflex command-and-control dashboard, and Docker-native execution paths for multi-session investigations.

## The Problem

Most security-flavored LLM products fall into one of two traps.

- They ship behind research-only licenses that block serious internal deployment, client work, or commercial productization.
- They rely on logic-only prompting, hidden thought boxes, and narrative guardrails that still hallucinate, drift out of scope, or approve actions they cannot actually verify.

That combination is weak engineering for security operations. Operators need explicit boundaries, reproducible execution, and controls that exist in code instead of prose.

## The Solution

Cerberus AI is a clean-room refactor designed to replace prompt theater with programmatic control.

- Programmatic Policy Engine: Cerberus uses a deterministic Python verification layer with Tier 1 through Tier 4 enforcement so tool execution, path boundaries, and target validation are checked in code instead of delegated to LLM reasoning.
- Multi-Session Dashboard: The Reflex web interface provides a fast 2x2 command-and-control grid for concurrent agent sessions, live log streaming, and per-session operator stop controls.
- Commercial Freedom: Cerberus is licensed under MIT and explicitly positioned for professional and commercial use after scrubbing legacy proprietary logic from the active codepaths.
- Headless-First Architecture: The runtime is designed to live comfortably inside Docker, execute tools asynchronously, and stream process output in real time back to the dashboard.

## Architecture

- Frontend: Reflex (FastAPI/React) powers the command-and-control dashboard, session views, and operator controls.
- Backend: Cerberus Core (Python 3.10+) handles mission control, tool dispatch, workspace isolation, memory services, and agent orchestration.
- Policy: Registry-backed tool validation and boundary enforcement gate commands before execution and verify runtime context with deterministic checks.

## What This Repository Contains

- `src/cerberus/` contains the core runtime, agent stack, tool registry, policy engine, and headless execution layer.
- `cerberus_dashboard/` contains the Reflex dashboard for multi-session command and control.
- `docker-compose.yml` starts the dashboard stack with Redis-backed state support.
- `dockerized/` contains alternate container assets and local development compose variants.
- `docs/` contains architecture, operations, and reference material for deeper reading.

## Quick Start

### Prerequisites

- Docker
- Docker Compose

### Launch The Dashboard Stack

From the repository root:

```bash
docker-compose up --build
```

This starts the Cerberus dashboard and Redis-backed state services defined in the root compose file.

> [!NOTE]
> The default compose stack publishes the dashboard on port `3000`, the backend API on port `8000`, and mounts the local `workspaces/`, `src/`, `cerberus_dashboard/`, and `rxconfig.py` paths into the container for an operator-friendly development loop.

After the stack is ready:

1. Open `http://localhost:3000`.
2. Use the 2x2 dashboard grid to dispatch concurrent agent actions.
3. Watch live runtime logs stream per session.
4. Use the STOP control on any active cell to terminate the running subprocess tree.

## Why Cerberus Is Different

- It treats policy as executable infrastructure, not model narration.
- It is designed for supervised, concurrent security operations instead of single-chat toy flows.
- It keeps operator controls close to runtime state through session-aware process tracking and real-time streaming.
- It is structured for Dockerized deployment and commercial use without research-only licensing baggage.

## License

Licensed under the MIT License - Commercial use permitted.