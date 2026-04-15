# Cerberus AI

Headless Multi-Agent Security Engine with Programmatic Policy Enforcement.

Cerberus AI is a workspace-isolated security orchestration framework for running supervised agent workflows, interactive investigations, and policy-gated headless actions from a single runtime. The repository combines a CLI and REPL, a Reflex command-and-control dashboard, audit-friendly workspace separation, and operator controls for local or provider-backed execution.

> [!NOTE]
> The current Python package path and CLI entry point still use `cai` for compatibility during the branding transition.

## Highlights

- Headless and interactive workflows through `cai`, `cai repl`, and `cai run`.
- Workspace-scoped execution with isolated artifacts under `workspaces/`.
- Programmatic policy enforcement, approvals, and environment-aware controls.
- Operator-facing tooling for memory, diagnostics, model selection, and runtime inspection.
- Reflex dashboard for session visibility and command-and-control monitoring.

## Getting Started

### Prerequisites

- Python 3.9+
- `uv` for the managed development workflow

### Install

```bash
uv sync --all-extras --all-packages --group dev
```

For a pip-based editable install and additional setup notes, see [INSTALL.md](INSTALL.md).

### Quickstart

```bash
uv run cai --help
uv run cai
uv run cai doctor
uv run cai run "Summarize the current workspace posture."
```

To start with an explicit isolated workspace:

```bash
uv run cai repl --workspace ./workspaces/demo
```

## Project Layout

- `src/cai/`: core runtime, agents, REPL, memory, tools, and policy-aware execution paths
- `app/`: Reflex dashboard and command-and-control surface
- `tests/`: regression, unit, and integration coverage
- `dockerized/`: containerized runtime assets
- `workspaces/`: isolated engagement roots and generated artifacts

## Developer Workflow

```bash
make sync
make lint
make tests
```

## Further Reading

- [INSTALL.md](INSTALL.md)
- [pyproject.toml](pyproject.toml)
- [Makefile](Makefile)