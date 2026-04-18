# Outstanding Technical Debt Report

## Scope
This report captures the current state of technical debt and incomplete architecture migration items observed during the April 2026 dashboard/policy audit.

## Executive Status
- Dashboard declutter pass: implemented in `src/cerberus/dashboard/app.py` (collapsible sidebar, progressive disclosure for tool payloads, focus dimming on inactive terminals).
- Policy guardrail for natural-language command payloads: implemented in `src/cerberus/verification/policy_engine.py` and validated by `tests/core/test_policy_engine.py`.
- Architecture migration from historical `src/cai/*` model to `src/cerberus/*`: incomplete.
- Redis hydration and live stream reconnection: functionally present, but not fully aligned with stated no-duplication/multi-session goals.

## Severity-Ranked Findings

### P0 High
1. Tool-argument empty-object fallback still exists in model coercion path.
- Evidence: `src/cerberus/agents/models/openai_chatcompletions.py` still returns `"{}"` when coercion input is empty.
- Locations:
  - `_coerce_tool_arguments_for_api` with trace event `tool_arguments_coerced_empty_object`.
- Impact:
  - Reintroduces the class of failures where schema-required fields are lost and execution receives an empty object.
  - Can mask the original parse problem and degrade model correction loops.
- Status: open.

2. Redis hydration is still single-session biased and can replay into the wrong pane.
- Evidence: `src/cerberus/dashboard/app.py` hydration and live subscription append recovered logs to `self._session_copy(0)`.
- Impact:
  - Multi-session dashboards can rehydrate all history into AGENT-1 even when source session differs.
  - Increases risk of ghost context and operator confusion.
- Status: open.

### P1 Medium
3. Namespace/migration drift remains (`caiextensions` and `.cai` residue).
- Evidence:
  - Optional imports from `caiextensions` remain in `src/cerberus/__init__.py`.
  - REPL help imports `caiextensions.platform.base.platform_manager` in `src/cerberus/repl/commands/help.py`.
  - Build excludes still reference legacy `.cai/` in `pyproject.toml` hatch excludes.
- Impact:
  - Indicates partial migration and increases long-term maintenance complexity.
  - Makes clean-room architecture claims harder to validate.
- Status: open.

4. Policy-engine architecture is split across two modules with overlapping semantics.
- Evidence:
  - `src/cerberus/verification/policy_engine.py` contains tiered verifier and NL command block.
  - `src/cerberus/guardrails/policy_engine.py` contains separate risk-tier decision logic.
- Impact:
  - Potential for drift in decisions depending on call path.
  - Harder to reason about enforcement guarantees.
- Status: open.

5. Metasploit path not functionally wired as an executable tool.
- Evidence:
  - `run_metasploit` appears in policy tier references, but no executable tool wrapper was found in `src/cerberus/tools/**/*.py`.
- Impact:
  - Capability appears declared in policy assumptions but is not end-to-end operational in tools layer.
- Status: open.

### P2 Low
6. Static analysis/deprecation cleanup remains.
- Evidence from current test runs:
  - Pydantic class-based `Config` deprecation warnings in `src/cerberus/tools/all_tools.py`.
  - `datetime.utcnow()` deprecation warning in `src/cerberus/tools/all_tools.py`.
- Impact:
  - Not an immediate blocker, but raises future breakage risk as dependencies advance.
- Status: open.

## Dashboard De-Clutter Refactor Delivered
Implemented in `src/cerberus/dashboard/app.py`:
- Collapsible sidebar sections for session overview, health, metadata, and CLV tier state.
- Sidebar open/collapse behavior with explicit toggle state.
- Progressive disclosure for tool payloads via `View Raw` details block.
- Focus-driven terminal styling: active/busy panes remain full contrast; inactive panes are visually dimmed.

Operational effect:
- Main workspace now prioritizes terminal output; high-noise operational metadata moved into collapsible zones.

## Redis Rehydration Gap vs Phase Claims
Repository phase notes claim no duplication and seamless merge behavior, but implementation still has two architectural caveats:
- Rehydration and live append target first session index, not per-session routing.
- Snapshot + Redis replay ordering can still produce repeated context if both persistence channels contain overlapping events.

Recommendation:
- Add event-level IDs and session IDs to Redis payloads.
- Track last-applied event ID in dashboard state and skip previously applied events.
- Route hydration/live events to session by session_id instead of fixed index 0.

## Clean-Room Architecture Delta
Compared with historical clean-room phase documentation (centered around `src/cai/*` modules), current codebase shows mixed lineage:
- Runtime and dashboard are now under `src/cerberus/*`.
- Legacy extension naming (`caiextensions`) and `.cai` build residue persist.
- Some architectural claims in phase notes (fully complete migration/no duplication) are not reflected by current implementation details.

Conclusion:
- Migration is substantial but not complete; current state is a hybrid architecture.

## Functional Status: Metasploit and Session Re-attach
- Metasploit execution:
  - Status: not fully functional end-to-end based on current tools inventory.
  - Reason: policy mentions exist, but executable tool implementation was not found in tools layer.
- Session re-attach/resume:
  - Status: partially functional.
  - Reason: checkpoint resume/export/list tooling exists in `src/cerberus/tools/sessions.py` and registry references, but this is semantic checkpoint resume, not full live terminal/process re-attachment for active runtime streams.

## Skipped Test Inventory (Requested)
From `tests/core/test_openai_chatcompletions_stream.py`:
- Skipped: line 28 (`RUN_AGENT_INTEGRATION_TESTS=1` required)
- Skipped: line 119 (`RUN_AGENT_INTEGRATION_TESTS=1` required)
- Skipped: line 197 (`RUN_AGENT_INTEGRATION_TESTS=1` required)
- Skipped: line 282 (`RUN_AGENT_INTEGRATION_TESTS=1` required)

## Validation Snapshot
- `tests/core/test_policy_engine.py`: 14 passed.
- `tests/core/test_openai_chatcompletions_stream.py`: 4 skipped (integration-gated), 0 failed.
- Dashboard-focused test command set: one failure in `test_dashboard_nmap_enhanced.py` due to Playwright test bug (`parent` treated as string before `.evaluate`), not a dashboard runtime import/syntax break.

## Remaining Work Phases
1. Unify policy enforcement.
- Consolidate `guardrails/policy_engine.py` and `verification/policy_engine.py` into one authoritative decision path.

2. Eliminate `{}` fallback in tool-arg coercion.
- Replace terminal fallback with structured parse-error envelope everywhere.

3. Finish Redis multi-session rehydration.
- Session-aware routing + dedupe IDs + ordering reconciliation between snapshot and Redis replay.

4. Complete namespace cleanup.
- Remove/replace `caiextensions` optional imports and clean `.cai` legacy excludes if no longer required.

5. Resolve static-analysis debt.
- Migrate Pydantic class `Config` usage to `ConfigDict`.
- Replace `datetime.utcnow()` with timezone-aware UTC calls.

6. Enable integration stream tests in CI profile.
- Add gated job profile that sets `RUN_AGENT_INTEGRATION_TESTS=1` for periodic validation.
