import re
from typing import List

# Matches nmap -sn's own host-discovery line in either form it prints:
# "Nmap scan report for 10.0.0.5" (bare IP) or
# "Nmap scan report for somehost.local (10.0.0.5)" (hostname + parenthesized
# IP) - the two alternatives below capture the IP from whichever form
# matched, group 1 for the parenthesized case, group 2 for the bare case.
# This is a different output shape from _NMAP_PORT_LINE in agent_tools.py
# (nmap's port table), which this deliberately does not reuse.
_NMAP_HOST_LINE = re.compile(
    r"^Nmap scan report for (?:\S+ \(([\da-fA-F:.]+)\)|([\da-fA-F:.]+))$",
    re.MULTILINE,
)


def parse_nmap_ping_sweep(raw_output: str) -> List[str]:
    """Deterministic, LLM-free extraction of the host list from nmap -sn's
    own output - mirrors _parse_nmap_output's non-LLM parsing style in
    agent_tools.py, applied to the ping-sweep output format instead of the
    port-table format. Returns an empty list when nmap found zero hosts up,
    not an error (see the feature spec's "Discovery finds zero hosts"
    edge case)."""
    hosts = []
    for match in _NMAP_HOST_LINE.finditer(raw_output):
        hosts.append(match.group(1) or match.group(2))
    return hosts
