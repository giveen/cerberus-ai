<todos title="Fortify streamed tool-call JSON parsing" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] inspect-streamed-tool-parse-path: Inspect streamed tool-call accumulation/parsing in openai_chatcompletions.py and related runtime paths that may overwrite malformed arguments with empty dicts. 🔴
  _Completed before compaction; mapped runtime path and pending approval payloads._
- [x] implement-json-repair-runtime-fix: Implement runtime pending-approval bridge and decision handling: dashboard modal payload mapping plus runner approval/reject argument handling. 🔴
  _Implemented dashboard runtime approval modal wiring plus runner-level approve/reject decision plumbing and Tier-4 tool tagging._
- [x] validate-dashboard-path: Run targeted validation for runtime parsing and dashboard pending-approval flow. 🔴
  _Validated with get_errors diagnostics and python3 -m py_compile on all touched files._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
