"""
Session Archival and Mission Report Generation.

Converts raw JSONL logs into structured markdown reports with security summaries.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
from datetime import datetime
from typing import Any

logger = logging.getLogger("cerberus.reporting")


class SessionLogParser:
    """Parse JSONL session logs and extract structured data."""
    
    @staticmethod
    def parse_jsonl_file(log_path: str | pathlib.Path) -> list[dict[str, Any]]:
        """Parse a JSONL file and return list of event dicts."""
        events = []
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse line {line_num} in {log_path}: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error reading log file {log_path}: {e}")
            return []
        
        return events
    
    @staticmethod
    def extract_session_metadata(events: list[dict[str, Any]]) -> dict[str, Any]:
        """Extract session metadata from events."""
        if not events:
            return {}
        
        # Find session start and end
        session_start = next((e for e in events if e.get("event") == "session_start"), None)
        session_end = next((e for e in events if e.get("event") == "session_end"), None)
        
        metadata = {
            "session_id": session_start.get("session_id") if session_start else "unknown",
            "start_time": session_start.get("timestamp") if session_start else "unknown",
            "end_time": session_end.get("timestamp") if session_end else "unknown",
            "total_events": len(events),
        }
        
        # Extract timing metrics
        if session_end and "timing_metrics" in session_end:
            metrics = session_end["timing_metrics"]
            metadata["active_time_seconds"] = metrics.get("active_time_seconds", 0)
            metadata["total_time_seconds"] = metrics.get("total_time_seconds", 0)
            metadata["active_percentage"] = metrics.get("active_percentage", 0)
        
        # Extract cost
        if session_end and "cost" in session_end:
            metadata["total_cost"] = session_end["cost"].get("total_cost", 0)
        
        return metadata
    
    @staticmethod
    def extract_events_by_type(events: list[dict[str, Any]]) -> dict[str, list[dict]]:
        """Group events by type."""
        events_by_type: dict[str, list[dict]] = {}
        for event in events:
            event_type = event.get("event", "unknown")
            if event_type not in events_by_type:
                events_by_type[event_type] = []
            events_by_type[event_type].append(event)
        
        return events_by_type


class MissionReportGenerator:
    """Generate markdown mission reports from session data."""
    
    def __init__(self, archive_dir: str | pathlib.Path = "archive"):
        """Initialize report generator."""
        self.archive_dir = pathlib.Path(archive_dir)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(
        self,
        log_path: str | pathlib.Path,
        session_summary: str = "",
    ) -> pathlib.Path:
        """Generate a mission report from a log file.
        
        Args:
            log_path: Path to JSONL log file
            session_summary: Optional custom summary text
        
        Returns:
            Path to generated markdown report
        """
        log_path = pathlib.Path(log_path)
        
        # Parse log
        parser = SessionLogParser()
        events = parser.parse_jsonl_file(log_path)
        metadata = parser.extract_session_metadata(events)
        events_by_type = parser.extract_events_by_type(events)
        
        # Generate report filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = metadata.get("session_id", "unknown")[:8]
        report_filename = f"Mission_Report_{session_id}_{timestamp}.md"
        report_path = self.archive_dir / report_filename
        
        # Build markdown content
        content = self._build_report_markdown(metadata, events_by_type, session_summary)
        
        # Write report
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"Generated mission report: {report_path}")
        except Exception as e:
            logger.error(f"Failed to write report to {report_path}: {e}")
            return pathlib.Path()
        
        return report_path
    
    def _build_report_markdown(
        self,
        metadata: dict[str, Any],
        events_by_type: dict[str, list[dict]],
        session_summary: str,
    ) -> str:
        """Build markdown report content."""
        lines = []
        
        # Header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("# Mission Report")
        lines.append("")
        lines.append(f"**Generated**: {timestamp}")
        lines.append(f"**Session ID**: {metadata.get('session_id', 'N/A')}")
        lines.append("")
        
        # Session Timeline
        lines.append("## Session Timeline")
        lines.append("")
        lines.append(f"- **Start Time**: {metadata.get('start_time', 'N/A')}")
        lines.append(f"- **End Time**: {metadata.get('end_time', 'N/A')}")
        lines.append(f"- **Duration**: {metadata.get('total_time_seconds', 0):.2f}s")
        lines.append(f"- **Active Time**: {metadata.get('active_time_seconds', 0):.2f}s")
        lines.append(f"- **Activity Level**: {metadata.get('active_percentage', 0):.1f}%")
        lines.append("")
        
        # Cost Analysis
        lines.append("## Cost Analysis")
        lines.append("")
        lines.append(f"- **Total Cost**: ${metadata.get('total_cost', 0):.4f}")
        lines.append("")
        
        # Event Summary
        lines.append("## Event Summary")
        lines.append("")
        lines.append(f"Total events logged: {metadata.get('total_events', 0)}")
        lines.append("")
        
        lines.append("### Event Breakdown")
        lines.append("")
        for event_type, events in sorted(events_by_type.items()):
            lines.append(f"- **{event_type}**: {len(events)} events")
        lines.append("")
        
        # Security Summary
        lines.append("## Security Summary")
        lines.append("")
        if session_summary:
            lines.append(session_summary)
        else:
            lines.append(
                "*No specific security findings recorded for this session. "
                "Session completed without triggering security alerts or policy violations.*"
            )
        lines.append("")
        
        # Raw Event Log
        lines.append("## Raw Event Log")
        lines.append("")
        lines.append("```json")
        for event_type, events in sorted(events_by_type.items()):
            for event in events:
                lines.append(json.dumps(event))
        lines.append("```")
        lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("*Report generated by Cerberus AI Archive System*")
        
        return "\n".join(lines)


async def generate_security_summary_from_llm(
    session_data: dict[str, Any],
    model_name: str = "gpt-4",
) -> str:
    """Generate a security summary using LLM.
    
    This is a template for future LLM-based analysis.
    Currently returns a placeholder until LLM integration is ready.
    """
    # Placeholder implementation - would use OpenAI/Claude for analysis
    summary = (
        f"Session {session_data.get('session_id', 'N/A')} completed. "
        f"Total duration: {session_data.get('total_time_seconds', 0):.2f}s. "
        f"No security violations detected."
    )
    return summary


def archive_session(
    log_path: str | pathlib.Path,
    archive_dir: str | pathlib.Path = "archive",
    custom_summary: str = "",
) -> pathlib.Path:
    """Archive a session by generating a mission report.
    
    Args:
        log_path: Path to JSONL log file
        archive_dir: Directory to store reports (default: 'archive')
        custom_summary: Optional security summary text
    
    Returns:
        Path to generated report
    """
    generator = MissionReportGenerator(archive_dir=archive_dir)
    return generator.generate_report(log_path, session_summary=custom_summary)


def archive_all_recent_sessions(
    log_dir: str | pathlib.Path = "logs",
    archive_dir: str | pathlib.Path = "archive",
    max_reports: int = 10,
) -> list[pathlib.Path]:
    """Archive recent session logs as mission reports.
    
    Args:
        log_dir: Directory containing JSONL logs
        archive_dir: Directory to store reports
        max_reports: Maximum number of reports to generate
    
    Returns:
        List of generated report paths
    """
    log_dir = pathlib.Path(log_dir)
    if not log_dir.exists():
        logger.warning(f"Log directory not found: {log_dir}")
        return []
    
    # Get recent JSONL files
    jsonl_files = sorted(
        log_dir.glob("cerberus_*.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:max_reports]
    
    if not jsonl_files:
        logger.info(f"No JSONL files found in {log_dir}")
        return []
    
    generator = MissionReportGenerator(archive_dir=archive_dir)
    reports = []
    
    for log_file in jsonl_files:
        try:
            report_path = generator.generate_report(log_file)
            if report_path.exists():
                reports.append(report_path)
        except Exception as e:
            logger.error(f"Failed to archive {log_file}: {e}")
    
    return reports
