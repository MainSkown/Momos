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
    ],
)
def test_enabling_group_installs_its_package_on_top_of_baseline(group_id, expected_package):
    packages = packages_for_enabled_tools([group_id])
    assert expected_package in packages
    assert set(BASELINE_KALI_PACKAGES) <= set(packages)


@pytest.mark.parametrize(
    "tool_name",
    ["sqlmap_run", "mysql_connect", "mysql_query", "snmp_enum"],
)
def test_default_none_enables_new_groups_tools(tool_name):
    assert tool_name in tool_names_for(None)


def test_scripting_is_excluded_from_default_none():
    assert "run_python_script" not in tool_names_for(None)


def test_scripting_is_included_when_explicitly_enabled():
    assert "run_python_script" in tool_names_for(["scripting"])


def test_default_none_installs_new_groups_packages():
    packages = packages_for_enabled_tools(None)
    assert "default-mysql-client" in packages
    assert "snmp" in packages
