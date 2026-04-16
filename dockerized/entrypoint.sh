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

exec cerberus