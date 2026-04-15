from cerberus.sdk.agents._run_impl import truncate_output
from cerberus.tools.runners.docker import CerebroDockerTool


def test_model_truncate_output_inserts_summary_marker_for_large_payload(monkeypatch):
    monkeypatch.setenv("CERBERUS_TOOL_OUTPUT_MODEL_MAX_CHARS", "2000")
    monkeypatch.setenv("CERBERUS_TOOL_OUTPUT_MODEL_HEAD_CHARS", "900")
    monkeypatch.setenv("CERBERUS_TOOL_OUTPUT_MODEL_TAIL_CHARS", "900")

    payload = "A" * 50_000
    result = truncate_output(payload)

    assert len(result) > 0
    assert len(result) <= 2500
    assert "TRUNCATED" in result
    assert "omitted" in result


def test_model_truncate_output_preserves_small_payload():
    payload = "short output"
    result = truncate_output(payload, max_length=2000)
    assert result == payload


def test_docker_compact_output_truncates_and_summarizes_large_payload():
    payload = "B" * 200_000
    compacted, was_truncated, summary = CerebroDockerTool._compact_output(payload)

    assert was_truncated is True
    assert "Output truncated:" in summary
    assert "Output truncated:" in compacted
    assert len(compacted) < len(payload)


def test_docker_compact_output_keeps_small_payload():
    payload = "ok"
    compacted, was_truncated, summary = CerebroDockerTool._compact_output(payload)
    assert compacted == payload
    assert was_truncated is False
    assert summary == ""
