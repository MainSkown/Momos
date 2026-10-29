"""Import-smoke test for the agent_tools.py -> agent_tools/ package split
(see docs/plans/milestone-2-new-pentest-tools-and-tool-access-control.md's
Part R). Asserts that a representative name from every category the old
flat module exposed is still reachable as `agent_tools.X` - catches a
dropped re-export immediately as a loud AttributeError, rather than a
silent gap only noticed once something tries to import the missing name."""

from src.core.agent import agent_tools

_EXPECTED_NAMES = [
    # file_tools.py
    "WRITE_LOCAL_FILE_TOOL_NAME",
    "LOCAL_FILES_DIR",
    "create_file_tools",
    # pentest_tools.py
    "NMAP_SCAN_TOOL_NAME",
    "HYDRA_BRUTEFORCE_TOOL_NAME",
    "GOBUSTER_SCAN_TOOL_NAME",
    "SEARCHSPLOIT_SEARCH_TOOL_NAME",
    "METASPLOIT_RUN_TOOL_NAME",
    "create_pentest_tools",
    # guided_session_tools.py
    "FTP_CONNECT_TOOL_NAME",
    "SSH_RUN_TOOL_NAME",
    "TELNET_PROBE_TOOL_NAME",
    "create_guided_session_tools",
    # terminal_tools.py
    "RUN_TOOL_NAME",
    "NEW_SESSION_TOOL_NAME",
    "INTERRUPT_SESSION_TOOL_NAME",
    "create_terminal_tools",
    # admin_tools.py
    "INSTALL_PACKAGE_TOOL_NAME",
    "REPORT_VULNERABILITY_TOOL_NAME",
    "REQUEST_PORT_ACCESS_TOOL_NAME",
    "ATTACK_OUTCOMES",
    "create_vulnerability_tool",
    "create_kali_tool",
    # common.py
    "DEFAULT_SESSION_NAME",
    "CLAIM_REJECTED_MARKER",
    "_get_target_info",
    "_execute_one_shot",
    # builders.py
    "build_agent_tools",
    "build_scouting_agent_tools",
    "build_pentesting_agent_tools",
    "build_reporting_agent_tools",
    "build_orchestrator_agent_tools",
    # external module references the existing test suite monkeypatches
    # directly as agent_tools.db_manager / agent_tools.kali_registry.
    "db_manager",
    "kali_registry",
]


def test_every_representative_name_is_still_exposed_after_the_package_split():
    missing = [name for name in _EXPECTED_NAMES if not hasattr(agent_tools, name)]
    assert missing == []


def test_tool_factories_are_still_callable_through_the_package():
    assert callable(agent_tools.create_file_tools)
    assert callable(agent_tools.create_pentest_tools)
    assert callable(agent_tools.create_guided_session_tools)
    assert callable(agent_tools.create_terminal_tools)
    assert callable(agent_tools.build_agent_tools)
