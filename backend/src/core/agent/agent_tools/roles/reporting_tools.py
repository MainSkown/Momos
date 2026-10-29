"""Reporting role's tool-name-set constants - see the tool matrix in
docs/features/multi-agent-pentest-pipeline.md's implementation plan.
Reporting has exactly one tool, report_vulnerability, reused as-is from
agent_tools.create_vulnerability_tool (see agent_tools.build_reporting_agent_tools,
the actual gatherer) rather than reimplemented here - there is no new tool
body for this role at all. No target-touching tool and so no writer at
all - reporting never acts on the target itself, only reads a pentesting
run's already-real transcript and writes it up - so there is nothing for
the turn-level race guard (roles/common.py's make_guarded_tools_node) to
actually guard, and no interrupt approval is ever needed."""

from src.core.agent import agent_tools

REPORT_VULNERABILITY_TOOL_NAME = agent_tools.REPORT_VULNERABILITY_TOOL_NAME

WRITER_TOOL_NAMES: set = set()
READER_TOOL_NAMES = {REPORT_VULNERABILITY_TOOL_NAME}
INTERRUPT_GATED_TOOL_NAMES: set = set()
ALWAYS_INTERRUPT_TOOL_NAMES: set = set()
