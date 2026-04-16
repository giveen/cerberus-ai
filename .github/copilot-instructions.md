<todos title="deterministic category scoring resolver" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] add-resolution-result-model: Implement ResolutionResult and deterministic resolve_category(prompt) scoring in all_tools.py with fallback_reason and scored outputs for all categories. 🔴
  _Added CATEGORY_SCORING_RULES and resolve_category returning primary_category, secondary_categories, confidence_scores, fallback_reason; detect_intent now delegates to resolver primary for compatibility._
- [x] wire-runner-to-scored-resolution: Refactor runner intent path to use resolve_category result instead of raw detect_intent category and enforce no unscored category selection. 🔴
  _Runner now imports resolve_category/ResolutionResult, emits score/fallback traces in debug mode, and _normalize_detected_intent_category rejects unscored primary categories with safe fallback._
- [x] validate-deterministic-resolution-behavior: Run compile and runtime checks proving every prompt gets scores, low-confidence fallback to misc, and usable toolset remains produced. 🔴
  _Validated with py_compile, diagnostics, prompt samples (recon/web/unknown), and a forced malformed resolver output showing unscored-category guardrail fallback without breaking tool selection._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
