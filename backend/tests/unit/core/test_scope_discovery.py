"""Pure-function unit tests for backend/src/core/agent/scope_discovery.py -
parse_nmap_ping_sweep, the deterministic (no Docker, no LLM) extraction of
the host list from nmap -sn's own output. See docs/features/
project-scope-and-authorization.md's "Discovery sweep" section and its
"Discovery finds zero hosts" edge case."""

from src.core.agent.scope_discovery import parse_nmap_ping_sweep

_MULTI_HOST_OUTPUT = """\
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-28 12:00 UTC
Nmap scan report for 10.0.0.1
Host is up (0.00040s latency).
Nmap scan report for printer.local (10.0.0.5)
Host is up (0.0020s latency).
Nmap scan report for 10.0.0.9
Host is up (0.0011s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.50 seconds
"""

_ZERO_HOST_OUTPUT = """\
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-28 12:00 UTC
Nmap done: 256 IP addresses (0 hosts up) scanned in 1.80 seconds
"""


def test_extracts_bare_ip_and_hostname_with_parenthesized_ip_forms():
    assert parse_nmap_ping_sweep(_MULTI_HOST_OUTPUT) == [
        "10.0.0.1",
        "10.0.0.5",
        "10.0.0.9",
    ]


def test_zero_hosts_up_returns_empty_list_not_error():
    assert parse_nmap_ping_sweep(_ZERO_HOST_OUTPUT) == []


def test_empty_string_returns_empty_list():
    assert parse_nmap_ping_sweep("") == []


def test_ignores_unrelated_lines():
    output = "Starting Nmap 7.94SVN ( https://nmap.org )\nHost is up.\n"
    assert parse_nmap_ping_sweep(output) == []
