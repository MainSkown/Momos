from dataclasses import dataclass
from typing import Final, FrozenSet, List, Optional, Set, Tuple

# Single source of truth for the "vulnerability testing" tools a project can
# individually enable/disable (project_scheme.py's ProjectSettings.
# enabled_tools) - deliberately its own module rather than living in
# agent_tools.py or kali_manager.py: agent_tools.py already imports FROM
# kali_integration (KaliManger/kali_registry), so kali_registry.py importing
# this data back out of agent_tools.py would cycle. Both sides import this
# module instead. Tool-name strings below are plain literals matching each
# tool's @tool(...) name in agent_tools.py exactly - the same duplication-
# by-convention already used between agent_tools.py and the frontend's
# AgentLogs.vue TOOL_LABELS map, since there's no shared runtime the two
# layers (and this module) could all import a single constant from without
# creating a cycle.
#
# Deliberately NOT included here - core/always-on, never shown as a toggle,
# never interrupt-gated (see agent.py's _INTERRUPT_GATED_TOOL_NAMES): nmap_scan,
# searchsploit_search, searchsploit_view - none of these touch the target's
# actual services, they're local/recon-only. Also not included: run/
# new_session/the rest of the shell-session tools - gated solely by
# allow_shell, a fully separate capability this module must not touch; the
# local file read/write/list tools - unconditional utility tools, not tied
# to any target-interaction group either.

# Always installed regardless of which groups below are enabled - core
# sandbox infra (nftables, libcap2-bin for nmap's setcap), general recon
# utilities the base system prompt itself references (whatweb/nikto/
# smbclient/...), or a dependency of a core/always-on tool: exploitdb and
# bsdextrautils are needed by searchsploit_search/searchsploit_view (both
# always-on, see above), so they can't be conditional on the
# searchsploit_run group below - only run() Metasploit-module detection and
# the "-p"/"-m" path resolution used by search/view actually need them.
BASELINE_KALI_PACKAGES: Final[Tuple[str, ...]] = (
    "wordlists",
    "curl",
    "wget",
    "nmap",
    "netcat-openbsd",
    "nftables",
    "nikto",
    "iputils-ping",
    "bind9-dnsutils",
    "whois",
    "smbclient",
    "whatweb",
    "sqlmap",
    "traceroute",
    "libcap2-bin",
    "dirb",
    "exploitdb",
    "bsdextrautils",
)


@dataclass(frozen=True)
class ToolGroup:
    id: str
    tool_names: Tuple[str, ...]
    # Extra apt packages this group needs on top of BASELINE_KALI_PACKAGES -
    # empty when the group's only requirement is already baseline (e.g.
    # searchsploit_run needs nothing beyond what searchsploit_search/view
    # already require unconditionally).
    packages: Tuple[str, ...]
    # Whether this group counts as enabled when a project's enabled_tools
    # is still None (never explicitly saved) - True for every pre-existing
    # group, preserving the exact set a project had before this field
    # existed. metasploit is the one exception: it must be off by default
    # for every project, not just ones created before it existed (it's a
    # ~518MB download - see kali_manager.py's DEFAULT_KALI_PACKAGES
    # comment), so it sets this False and requires explicit opt-in.
    default_enabled: bool = True


TOOL_GROUPS: Final[Tuple[ToolGroup, ...]] = (
    ToolGroup("hydra", ("hydra_bruteforce",), ("hydra",)),
    ToolGroup("gobuster", ("gobuster_scan",), ("gobuster",)),
    ToolGroup("searchsploit_run", ("searchsploit_run",), ()),
    ToolGroup("ftp", ("ftp_connect", "ftp_command"), ("ftp",)),
    ToolGroup("ssh", ("ssh_check_login", "ssh_run"), ("openssh-client", "sshpass")),
    ToolGroup("telnet", ("telnet_probe",), ("telnet",)),
    ToolGroup(
        "metasploit", ("metasploit_run",), ("metasploit-framework",), default_enabled=False
    ),
)

TOOL_GROUP_IDS: Final[FrozenSet[str]] = frozenset(g.id for g in TOOL_GROUPS)

# All tool names covered by TOOL_GROUPS, regardless of which are currently
# enabled - this is also the "vulnerability testing" set agent.py's
# _INTERRUPT_GATED_TOOL_NAMES reads, kept as one derived constant so the
# picker's filtering and the interrupt gate can't drift apart from each
# other the way two independently-hardcoded sets could.
ALL_GROUPED_TOOL_NAMES: Final[FrozenSet[str]] = frozenset(
    name for g in TOOL_GROUPS for name in g.tool_names
)


def tool_names_for(enabled_tools: Optional[List[str]]) -> Set[str]:
    """enabled_tools=None -> every group whose default_enabled is True
    (today's existing behavior for pre-existing groups; opt-in-only groups
    like metasploit stay excluded even then). An explicit list overrides
    defaults entirely - only the listed group ids' tools are included,
    regardless of their own default_enabled. An unknown id (already
    rejected at the API boundary, see project_router.py) is silently
    ignored rather than raising here."""
    if enabled_tools is None:
        return {name for g in TOOL_GROUPS if g.default_enabled for name in g.tool_names}
    enabled = set(enabled_tools)
    return {name for g in TOOL_GROUPS if g.id in enabled for name in g.tool_names}


def packages_for_enabled_tools(enabled_tools: Optional[List[str]]) -> List[str]:
    """BASELINE_KALI_PACKAGES plus every enabled group's own packages.
    enabled_tools=None means every default_enabled group - mirrors
    tool_names_for's own None handling."""
    if enabled_tools is None:
        return list(BASELINE_KALI_PACKAGES) + [
            p for g in TOOL_GROUPS if g.default_enabled for p in g.packages
        ]
    enabled = set(enabled_tools)
    packages = list(BASELINE_KALI_PACKAGES)
    for g in TOOL_GROUPS:
        if g.id in enabled:
            packages.extend(g.packages)
    return packages
