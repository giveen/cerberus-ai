#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [[ -f /tmp/tools_hub_compose_started ]]; then
    docker compose -f /workspace/dockerized/internal-tools.yml down --remove-orphans || true
  fi
  if [[ -n "${dockerd_pid:-}" ]]; then
    kill "${dockerd_pid}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

# Start inner Docker daemon.
dockerd-entrypoint.sh >/var/log/dockerd.log 2>&1 &
dockerd_pid=$!

# Wait for daemon readiness.
for _ in $(seq 1 90); do
  if docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker info >/dev/null 2>&1; then
  echo "tools-hub: dockerd failed to become ready" >&2
  cat /var/log/dockerd.log >&2 || true
  exit 1
fi

# Bring up internal tool stack.
docker compose -f /workspace/dockerized/internal-tools.yml up -d
touch /tmp/tools_hub_compose_started

# Keep container alive with inner dockerd lifecycle.
wait "${dockerd_pid}"
