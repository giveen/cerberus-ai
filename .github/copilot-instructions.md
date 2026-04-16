<todos title="Fix dropped tool-call arguments in dispatcher" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] find-tool-dispatch-core-loop: Locate the router/core loop that receives LLM tool_calls and invokes registered Python tools 🔴
  _Confirmed execution flow in SDK runner and tool wrapper: process_model_response -> execute_function_tool_calls -> FunctionTool.on_invoke_tool._
- [x] patch-argument-json-parsing: Parse tool_call.function.arguments via json.loads with explicit try/except and debug logging on failure 🔴
  _Updated openai_chatcompletions parser to attempt json.loads then parse_json_lenient, and log explicit 'Failed to parse tool arguments: ...' on parse failure instead of silent fallback._
- [x] patch-tool-invocation-unpacking: Ensure dispatcher passes parsed dict via kwargs instead of empty/default dict 🔴
  _Verified invocation path already uses parsed schema args/kwargs and function call unpacking via the tool wrapper; patched stream normalization path to preserve original arguments when parse fails so kwargs are not fed from coerced {}._
- [x] validate-with-targeted-tests: Run focused tests or smoke checks covering tool dispatch and argument propagation 🟡
  _Ran focused OpenAI chat/completions converter+stream tests; all passed after adding regression tests for argument parsing behavior._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
