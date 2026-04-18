<todos title="Cerberus-AI Resilience & Automation" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [-] harden-parallel-executor-isolation: Wrap each parallel tool execution path in explicit try/except isolation and preserve metadata through failures. 🔴
- [ ] add-locks-to-sast-shared-counters: Apply asyncio.Lock to shared counters in SAST agents and guard all counter mutations. 🔴
- [ ] fix-argument-preservation-and-retryable-failure: Audit openai_chatcompletions.py and parallel_tool_executor.py to keep original_arguments and route malformed JSON to _is_retryable_prompt_dispatch_failure path. 🔴
- [ ] create-playwright-2x2-grid-busy-active-test: Add e2e test that spawns 4 agents, submits dry-run tool calls, and verifies BUSY -> ACTIVE transitions across 4 panes. 🔴
- [ ] verify-runtime-and-restart-container-mcp: Verify app.env volume patch state and restart container-mcp via docker compose. 🟡
- [ ] run-targeted-validations: Run focused tests/checks for Python and Playwright changes and summarize residual risks. 🟡
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
