from __future__ import annotations

from typing import Any

KALI_DOCKER_ENVIRONMENT_ID = "Kali-Docker"
KALI_DOCKER_ENVIRONMENT_BADGE = "Environment: Kali-Docker"


def extract_execution_environment_id(output: Any) -> str:
    """Extract execution environment identifier from tool output payload."""

    if not isinstance(output, dict):
        return ""

    metadata = output.get("metadata")
    if not isinstance(metadata, dict):
        return ""

    env_id = str(metadata.get("execution_environment_id", "") or "").strip()
    return env_id


def environment_badge_text(output: Any) -> str:
    env_id = extract_execution_environment_id(output)
    if env_id == KALI_DOCKER_ENVIRONMENT_ID:
        return KALI_DOCKER_ENVIRONMENT_BADGE
    if env_id:
        return f"Environment: {env_id}"
    return ""
