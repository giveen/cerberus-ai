from __future__ import annotations

from cai.verification.policy_engine import (
    PolicyEngine,
    format_logic_audit_report,
    render_logic_audit_report_markdown,
)


def test_verify_blocks_unknown_tool(tmp_path):
    engine = PolicyEngine(workspace_dir=str(tmp_path), project_id="eng-1")

    report = engine.verify(
        {
            "tool_name": "definitely_not_a_real_tool",
            "arguments": {},
            "available_tools": ["read_file", "write_file"],
        }
    )

    assert report.blocked is True
    assert any(f.code == "tool_unavailable" for f in report.findings)


def test_post_audit_blocks_dangerous_command(tmp_path):
    engine = PolicyEngine(workspace_dir=str(tmp_path), project_id="eng-1")
    report = engine.run_post_audit(
        planned_calls=[
            {
                "tool_name": "execute_cli_command",
                "arguments": {"command": "rm -rf /tmp/test"},
            }
        ],
        available_tools=["execute_cli_command"],
        previous_signature=None,
    )

    assert report.blocked is True
    assert report.risk_score >= 80
    assert report.manual_approval_required is True
    assert any(f.code == "dangerous_command" for f in report.findings)


def test_post_audit_flags_boundary_violation(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    engine = PolicyEngine(workspace_dir=str(workspace), project_id="eng-1")
    report = engine.run_post_audit(
        planned_calls=[
            {
                "tool_name": "read_file",
                "arguments": {"path": "/etc/passwd"},
            }
        ],
        available_tools=["read_file"],
        previous_signature=None,
    )

    assert report.blocked is True
    assert any(f.code == "path_guard_violation" for f in report.findings)


def test_verify_blocks_sibling_workspace_access(tmp_path):
    workspace = tmp_path / "workspace"
    sibling_file = workspace / "workspaces" / "eng-2" / "secret.txt"
    sibling_file.parent.mkdir(parents=True, exist_ok=True)
    sibling_file.write_text("blocked", encoding="utf-8")

    engine = PolicyEngine(workspace_dir=str(workspace), project_id="eng-1")
    report = engine.verify(
        {
            "tool_name": "read_file",
            "arguments": {"file_path": str(sibling_file)},
            "available_tools": ["read_file"],
        }
    )

    assert report.blocked is True
    assert any(f.code == "path_guard_violation" for f in report.findings)


def test_verify_blocks_missing_binary_dependency(monkeypatch, tmp_path):
    engine = PolicyEngine(workspace_dir=str(tmp_path), project_id="eng-1")

    def _which(name: str) -> str | None:
        if name == "sqlmap":
            return None
        return f"/usr/bin/{name}"

    monkeypatch.setattr("cai.verification.policy_engine.shutil.which", _which)

    report = engine.verify(
        {
            "tool_name": "sqlmap",
            "arguments": {"target": "127.0.0.1"},
            "available_tools": ["sqlmap"],
        }
    )

    assert report.blocked is True
    assert any(f.code == "missing_dependency" for f in report.findings)


def test_logic_audit_report_formatter_from_committing_json():
    rows = format_logic_audit_report(
        'COMMITTING_JSON: {"status":"OPTIMIZE","mode":"MODE_CRITIQUE","rationale":"duplicate call","suggested_adjustment":"change tool","risk_level":"Medium"}'
    )
    markdown = render_logic_audit_report_markdown(rows)

    assert rows[0]["attribute"] == "Status"
    assert rows[0]["value"] == "OPTIMIZE"
    assert "### Logic Audit Report" in markdown
    assert "MODE_CRITIQUE" in markdown


def test_verify_detects_looping_behavior_without_state_change(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    target_file = workspace / "workspaces" / "eng-1" / "evidence.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("ok", encoding="utf-8")

    engine = PolicyEngine(workspace_dir=str(workspace), project_id="eng-1")
    action = {
        "tool_name": "read_file",
        "arguments": {"file_path": str(target_file)},
        "available_tools": ["read_file"],
        "system_state": {"snapshot": "alpha"},
        "chat_history": [
            {
                "tool_name": "read_file",
                "arguments": {"file_path": str(target_file)},
                "system_state": {"snapshot": "alpha"},
            },
            {
                "tool_name": "read_file",
                "arguments": {"file_path": str(target_file)},
                "system_state": {"snapshot": "alpha"},
            },
        ],
    }

    report = engine.verify(action)

    assert report.blocked is True
    assert any(f.code == "looping_behavior_detected" for f in report.findings)


def test_verify_high_risk_command_can_be_manually_approved(tmp_path):
    engine = PolicyEngine(workspace_dir=str(tmp_path), project_id="eng-1")
    target = tmp_path / "workspaces" / "eng-1" / "demo.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("demo", encoding="utf-8")

    blocked_report = engine.verify(
        {
            "tool_name": "execute_cli_command",
            "arguments": {"command": f"chmod 777 {target}"},
            "available_tools": ["execute_cli_command"],
        }
    )
    approved_report = engine.verify(
        {
            "tool_name": "execute_cli_command",
            "arguments": {"command": f"chmod 777 {target}"},
            "available_tools": ["execute_cli_command"],
            "manual_approval_granted": True,
        }
    )

    assert blocked_report.blocked is True
    assert blocked_report.manual_approval_required is True
    assert blocked_report.requires_approval is True
    assert approved_report.blocked is False
    assert approved_report.manual_approval_required is False
    assert approved_report.requires_approval is False
    assert approved_report.risk_level == "HIGH"
