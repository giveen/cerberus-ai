<todos title="repair tool-calling pipeline and realtime streaming" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] map-legacy-paths-to-current-tree: Map requested src/cerberus/sdk targets to current refactored file locations and confirm concrete patch points. 🔴
  _Mapped sdk requests to src/cerberus/agents/* and dashboard handling in src/cerberus/dashboard/app.py because terminal.py does not exist in current tree._
- [x] harden-openai-arg-dispatch: Ensure conservative parsing in openai_chatcompletions with COMMITTING_JSON regex fallback, explicit parse-failure logging, and no silent {} argument fallbacks. 🔴
  _Added explicit trace_debug logging for missing payload/parse failure/missing name in COMMITTING_JSON extraction path and retained conservative parse behavior._
- [x] enforce-runner-argument-integrity: Ensure validation gate catches malformed/required-field missing args and execution path retains raw argument metadata including parallel executor result items. 🔴
  _Runner validation gate already enforced malformed/required-field checks; patched parallel_tool_executor to preserve serialized raw_arguments and parsed arguments in raw_item metadata without {} fallback on missing metadata._
- [x] verify-tool-invocation-streaming: Confirm tool invocation uses kwargs for execution and partial stdout is emitted immediately with structured tool output preserved. 🔴
  _Confirmed function_tool invocation passes kwargs; partial stdout emission flows via process_handler and nmap now emits immediate version + start tokens from active container path._
- [x] sync-dashboard-token-handling: Verify dashboard runtime handles on_token/on_tool_call equivalents for call-scoped append and busy/active/error state transitions. 🟡
  _Added on_token and on_tool_call channel aliases in dashboard runtime handler; existing busy/active/error transitions remained intact._
- [x] run-regression-and-live-verification: Run test_openai_chatcompletions_stream.py and attempt live Nmap verification against 192.168.0.4 with immediate header visibility. 🔴
  _pytest target executed (4 skipped); live docker exec nmap confirms immediate header and probe via NMAP_TOOL streaming context shows first partial_stdout event as Nmap version._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
