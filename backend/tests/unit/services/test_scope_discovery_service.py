"""ScopeDiscoveryService (backend/src/services/scope_discovery_service.py) -
the nmap -sn discovery sweep: builds the command from the project's
ProjectScope.host_range, runs it via kali_registry.get_manager/
manager.execute (mocked here, never real Docker - that tier is
live_tools-marked, see docs/testing-plan.md), parses the result and tags
each discovered host in_scope/out_of_scope against the SAME containment
check ProjectScopeService uses (CLAUDE.md rule 4 - no second copy of the
containment logic)."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.schemas.project_scheme import DiscoveredHost, ProjectScope
from src.services import scope_discovery_service as module
from src.services.scope_discovery_service import ScopeDiscoveryService
from src.utils.exceptions import ProjectDoesNotExistException

PROJECT_ID = str(uuid.uuid4())


def make_scope(**overrides):
    defaults = dict(
        project_id=PROJECT_ID,
        host_range="10.0.0.0/30",
        port_range_start=1,
        port_range_end=1024,
    )
    defaults.update(overrides)
    return ProjectScope(**defaults)


@pytest.fixture
def fake_manager():
    manager = MagicMock()
    manager.execute = AsyncMock(return_value="")
    return manager


@pytest.fixture
def fake_kali_registry(monkeypatch, fake_manager):
    fake = MagicMock()
    fake.get_manager = AsyncMock(return_value=fake_manager)
    monkeypatch.setattr(module, "kali_registry", fake)
    return fake


@pytest.fixture
def patched_db(fake_db_manager, monkeypatch):
    monkeypatch.setattr(module, "db_manager", fake_db_manager)
    fake_db_manager.get_project.return_value = MagicMock()
    fake_db_manager.get_project_scope.return_value = make_scope()
    return fake_db_manager


_NMAP_OUTPUT = """\
Nmap scan report for 10.0.0.1
Host is up.
Nmap scan report for 10.0.0.5
Host is up.
"""


async def test_discover_hosts_tags_in_scope_and_out_of_scope(
    patched_db, fake_kali_registry, fake_manager
):
    fake_manager.execute.return_value = _NMAP_OUTPUT

    result = await ScopeDiscoveryService.discover_hosts(PROJECT_ID)

    assert result == [
        DiscoveredHost(host="10.0.0.1", in_scope=True),
        DiscoveredHost(host="10.0.0.5", in_scope=False),
    ]


async def test_discover_hosts_builds_nmap_command_from_scope_host_range(
    patched_db, fake_kali_registry, fake_manager
):
    await ScopeDiscoveryService.discover_hosts(PROJECT_ID)

    command = fake_manager.execute.call_args.args[0]
    assert command.startswith("nmap -sn ")
    assert "10.0.0.0/30" in command


async def test_discover_hosts_uses_comma_separated_scope_as_space_separated_targets(
    patched_db, fake_kali_registry, fake_manager
):
    patched_db.get_project_scope.return_value = make_scope(
        host_range="10.0.0.1,10.0.0.9"
    )

    await ScopeDiscoveryService.discover_hosts(PROJECT_ID)

    command = fake_manager.execute.call_args.args[0]
    # nmap's own target spec takes multiple targets space-separated on the
    # command line, not comma-separated like host_range stores them - a
    # literal comma here would make nmap treat the whole thing as one
    # malformed target instead of two.
    assert "," not in command
    assert "10.0.0.1/32" in command
    assert "10.0.0.9/32" in command


async def test_discover_hosts_zero_hosts_returns_empty_list(
    patched_db, fake_kali_registry, fake_manager
):
    fake_manager.execute.return_value = "Nmap done: 4 IP addresses (0 hosts up)\n"

    result = await ScopeDiscoveryService.discover_hosts(PROJECT_ID)

    assert result == []


async def test_discover_hosts_unknown_project_raises(patched_db, fake_kali_registry):
    patched_db.get_project.return_value = None

    with pytest.raises(ProjectDoesNotExistException):
        await ScopeDiscoveryService.discover_hosts(PROJECT_ID)


async def test_discover_hosts_propagates_kali_execution_failure(
    patched_db, fake_kali_registry, fake_manager
):
    fake_manager.execute.side_effect = RuntimeError("nmap exited with status 1")

    with pytest.raises(RuntimeError):
        await ScopeDiscoveryService.discover_hosts(PROJECT_ID)


async def test_discover_hosts_multi_entry_scope_does_not_only_check_first_entry(
    patched_db, fake_kali_registry, fake_manager
):
    """Same risk B3/B5 guard against: a discovered host must be checked
    against EVERY entry in a comma-separated host_range, not just the
    first one."""
    patched_db.get_project_scope.return_value = make_scope(
        host_range="192.168.0.0/28,10.0.0.0/30"
    )
    fake_manager.execute.return_value = (
        "Nmap scan report for 192.168.0.5\n"
        "Host is up.\n"
        "Nmap scan report for 10.0.0.2\n"
        "Host is up.\n"
        "Nmap scan report for 172.16.0.1\n"
        "Host is up.\n"
    )

    result = await ScopeDiscoveryService.discover_hosts(PROJECT_ID)

    assert result == [
        DiscoveredHost(host="192.168.0.5", in_scope=True),
        DiscoveredHost(host="10.0.0.2", in_scope=True),
        DiscoveredHost(host="172.16.0.1", in_scope=False),
    ]
