"""Pure-function unit tests for backend/src/core/tool_groups.py - which tools a
group id maps to and which apt packages a project's enabled groups install.
No Docker, no database."""

import pytest

from src.core.tool_groups import (
    BASELINE_KALI_PACKAGES,
    packages_for_enabled_tools,
    tool_names_for,
)


@pytest.mark.parametrize(
    ("group_id", "expected_tool", "other_group_tool"),
    [
        ("sqlmap", "sqlmap_run", "hydra_bruteforce"),
        ("mysql", "mysql_connect", "sqlmap_run"),
        ("mysql", "mysql_query", "hydra_bruteforce"),
        ("snmp", "snmp_enum", "sqlmap_run"),
        ("testssl", "testssl_scan", "sqlmap_run"),
        ("wpscan", "wpscan_enum", "sqlmap_run"),
        ("dnsrecon", "dns_recon", "sqlmap_run"),
        ("tshark", "packet_capture", "sqlmap_run"),
        ("netexec", "netexec_run", "sqlmap_run"),
        ("impacket", "impacket_kerberoast", "sqlmap_run"),
        ("impacket", "impacket_exec", "sqlmap_run"),
        ("responder", "responder_start", "sqlmap_run"),
        ("responder", "responder_read", "sqlmap_run"),
        ("responder", "responder_stop", "sqlmap_run"),
        ("password_cracking", "crack_hashes", "sqlmap_run"),
        ("commix", "commix_run", "sqlmap_run"),
    ],
)
def test_group_selects_its_own_tool_and_excludes_other_groups(
    group_id, expected_tool, other_group_tool
):
    selected = tool_names_for([group_id])
    assert expected_tool in selected
    assert other_group_tool not in selected


@pytest.mark.parametrize(
    ("group_id", "expected_package"),
    [
        ("sqlmap", "sqlmap"),
        ("mysql", "default-mysql-client"),
        ("snmp", "snmp"),
        ("testssl", "testssl.sh"),
        ("wpscan", "wpscan"),
        ("dnsrecon", "dnsrecon"),
        ("tshark", "tshark"),
        ("netexec", "netexec"),
        ("impacket", "impacket-scripts"),
        ("responder", "responder"),
        ("password_cracking", "hashcat"),
        ("password_cracking", "john"),
        ("commix", "commix"),
    ],
)
def test_enabling_group_installs_its_package_on_top_of_baseline(group_id, expected_package):
    packages = packages_for_enabled_tools([group_id])
    assert expected_package in packages
    assert set(BASELINE_KALI_PACKAGES) <= set(packages)


@pytest.mark.parametrize(
    "tool_name",
    [
        "sqlmap_run",
        "mysql_connect",
        "mysql_query",
        "snmp_enum",
        "testssl_scan",
        "wpscan_enum",
        "dns_recon",
        "packet_capture",
        "commix_run",
    ],
)
def test_default_none_enables_new_groups_tools(tool_name):
    assert tool_name in tool_names_for(None)


@pytest.mark.parametrize(
    "tool_name",
    [
        "netexec_run",
        "impacket_kerberoast",
        "impacket_exec",
        "responder_start",
        "responder_read",
        "responder_stop",
        "crack_hashes",
    ],
)
def test_default_none_excludes_opt_in_only_groups_tools(tool_name):
    assert tool_name not in tool_names_for(None)


def test_scripting_is_excluded_from_default_none():
    assert "run_python_script" not in tool_names_for(None)


def test_scripting_is_included_when_explicitly_enabled():
    assert "run_python_script" in tool_names_for(["scripting"])


def test_default_none_installs_new_groups_packages():
    packages = packages_for_enabled_tools(None)
    assert "default-mysql-client" in packages
    assert "snmp" in packages
    assert "testssl.sh" in packages
    assert "tshark" in packages
    assert "commix" in packages
    assert "hashcat" not in packages
    assert "netexec" not in packages
