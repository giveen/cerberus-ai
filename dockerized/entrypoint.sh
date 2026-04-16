#!/usr/bin/env sh
set -eu

if [ -z "${CERBERUS_WORKSPACE_ROOT:-}" ]; then
  export CERBERUS_WORKSPACE_ROOT="/workspace/workspaces"
fi

if [ -z "${CERBERUS_API_KEY:-}" ] && [ -n "${CEREBRO_API_KEY:-}" ]; then
  export CERBERUS_API_KEY="$CEREBRO_API_KEY"
fi
if [ -z "${CERBERUS_API_KEY:-}" ] && [ -n "${ALIAS_API_KEY:-}" ]; then
  export CERBERUS_API_KEY="$ALIAS_API_KEY"
fi
if [ -z "${CERBERUS_API_BASE:-}" ] && [ -n "${CEREBRO_API_BASE:-}" ]; then
  export CERBERUS_API_BASE="$CEREBRO_API_BASE"
fi
if [ -z "${CERBERUS_MODEL:-}" ] && [ -n "${CEREBRO_MODEL:-}" ]; then
  export CERBERUS_MODEL="$CEREBRO_MODEL"
fi
if [ -z "${CERBERUS_AGENT_TYPE:-}" ] && [ -n "${CEREBRO_AGENT_TYPE:-}" ]; then
  export CERBERUS_AGENT_TYPE="$CEREBRO_AGENT_TYPE"
fi
if [ -z "${CERBERUS_ACTIVE_CONTAINER:-}" ] && [ -n "${CEREBRO_ACTIVE_CONTAINER:-}" ]; then
  export CERBERUS_ACTIVE_CONTAINER="$CEREBRO_ACTIVE_CONTAINER"
fi
if [ -z "${CERBERUS_SUPPORT_MODEL:-}" ] && [ -n "${CEREBRO_SUPPORT_MODEL:-}" ]; then
  export CERBERUS_SUPPORT_MODEL="$CEREBRO_SUPPORT_MODEL"
fi
if [ -n "${CERBERUS_API_BASE:-}" ]; then
  export OPENAI_BASE_URL="$CERBERUS_API_BASE"
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

# Early runtime bootstrap: disable LiteLLM proxy message logging and
# safely wrap cold-storage key generation to avoid ImportError spam when
# optional proxy extras (e.g., orjson) are not installed.
if command -v /opt/cerberus-venv/bin/python >/dev/null 2>&1; then
  /opt/cerberus-venv/bin/python - <<'PY' || true
try:
  import importlib
  litellm = importlib.import_module('litellm')
  if hasattr(litellm, 'turn_off_message_logging'):
    litellm.turn_off_message_logging = True
  if hasattr(litellm, 'store_audit_logs'):
    litellm.store_audit_logs = False
  if hasattr(litellm, 'use_litellm_proxy'):
    litellm.use_litellm_proxy = False
  try:
    from litellm.litellm_core_utils import litellm_logging as _litellm_logging
    payload_setup = getattr(_litellm_logging, 'StandardLoggingPayloadSetup', None)
    original = getattr(payload_setup, '_generate_cold_storage_object_key', None)
    if payload_setup is not None and original is not None and not getattr(original, '_cerberus_safe_wrap', False):
      def _safe_generate_cold_storage_object_key(*args, **kwargs):
        try:
          return original(*args, **kwargs)
        except Exception:
          return None
      _safe_generate_cold_storage_object_key._cerberus_safe_wrap = True
      payload_setup._generate_cold_storage_object_key = staticmethod(_safe_generate_cold_storage_object_key)
  except Exception:
    pass
except Exception:
  pass
PY
fi

exec cerberus