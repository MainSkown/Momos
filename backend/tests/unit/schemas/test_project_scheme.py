import uuid

import pytest

from src.core.pipeline_modes import PIPELINE_MODES
from src.schemas.project_scheme import (
    AuthorizationAcknowledgment,
    ProjectRequest,
    ProjectScope,
    ProjectSettings,
    base_starting_prompt,
    orchestrator_starting_prompt,
    pentesting_starting_prompt,
    project_settings_factory,
    reporting_starting_prompt,
    scouting_starting_prompt,
)
from src.schemas.scope_parsing import host_count, parse_host_range


def test_factory_echoes_project_id():
    project_id = uuid.uuid4()

    assert project_settings_factory(project_id).project_id == project_id


def test_factory_puts_new_projects_on_multi_agent_pipeline():
    assert project_settings_factory(uuid.uuid4()).pipeline_mode == "multi_agent"


def test_factory_leaves_enabled_tools_as_none_meaning_all_groups():
    assert project_settings_factory(uuid.uuid4()).enabled_tools is None


def test_factory_copies_single_agent_prompt_and_per_role_prompts_from_constants():
    settings = project_settings_factory(uuid.uuid4())

    assert settings.starting_prompt == base_starting_prompt
    assert settings.orchestrator_starting_prompt == orchestrator_starting_prompt
    assert settings.scouting_starting_prompt == scouting_starting_prompt
    assert settings.pentesting_starting_prompt == pentesting_starting_prompt
    assert settings.reporting_starting_prompt == reporting_starting_prompt


def test_factory_leaves_model_names_empty_not_none():
    settings = project_settings_factory(uuid.uuid4())

    assert settings.base_model_name == ""
    assert settings.orchestrator_model_name == ""


def test_settings_without_pipeline_mode_default_to_single_agent():
    settings = ProjectSettings(
        should_interrupt=False,
        starting_prompt="p",
        base_model_name="",
        parsing_model_name="",
        project_id=uuid.uuid4(),
    )

    assert settings.pipeline_mode == "single_agent"


def test_pipeline_mode_literals_match_pipeline_modes_module():
    assert set(PIPELINE_MODES) == {"single_agent", "multi_agent"}


def test_project_request_requires_scope_fields():
    request = ProjectRequest(
        name="proj",
        base_model_name="base",
        parsing_model_name="parse",
        host_range="10.0.0.1",
        port_range_start=1,
        port_range_end=1024,
    )

    assert request.host_range == "10.0.0.1"
    assert request.port_range_start == 1
    assert request.port_range_end == 1024


def test_project_scope_round_trips_its_fields():
    project_id = uuid.uuid4()

    scope = ProjectScope(
        project_id=project_id,
        host_range="10.0.0.0/24",
        port_range_start=1,
        port_range_end=65535,
    )

    assert scope.project_id == project_id
    assert scope.host_range == "10.0.0.0/24"
    assert scope.port_range_start == 1
    assert scope.port_range_end == 65535


def test_authorization_acknowledgment_round_trips_its_fields():
    project_id = uuid.uuid4()

    ack = AuthorizationAcknowledgment(
        project_id=project_id,
        acknowledged_by="alice",
        description="authorized by client contract #42",
        acknowledged_host_range="10.0.0.0/24",
        acknowledged_port_range_start=1,
        acknowledged_port_range_end=1024,
    )

    assert ack.project_id == project_id
    assert ack.acknowledged_by == "alice"
    assert ack.description == "authorized by client contract #42"
    assert ack.acknowledged_host_range == "10.0.0.0/24"
    assert ack.acknowledged_port_range_start == 1
    assert ack.acknowledged_port_range_end == 1024
    assert ack.id is not None
    assert ack.created_at is not None


def test_authorization_acknowledgment_mints_a_fresh_id_per_row():
    kwargs = dict(
        project_id=uuid.uuid4(),
        acknowledged_by="alice",
        description="d",
        acknowledged_host_range="10.0.0.1",
        acknowledged_port_range_start=1,
        acknowledged_port_range_end=1,
    )

    assert AuthorizationAcknowledgment(**kwargs).id != AuthorizationAcknowledgment(**kwargs).id


def test_parse_host_range_accepts_a_single_ipv4_address():
    networks = parse_host_range("10.0.0.1")

    assert len(networks) == 1
    assert str(networks[0]) == "10.0.0.1/32"


def test_parse_host_range_accepts_a_cidr_block():
    networks = parse_host_range("10.0.0.0/24")

    assert len(networks) == 1
    assert str(networks[0]) == "10.0.0.0/24"


def test_parse_host_range_accepts_a_comma_separated_list():
    networks = parse_host_range("10.0.0.1, 10.0.0.2")

    assert [str(n) for n in networks] == ["10.0.0.1/32", "10.0.0.2/32"]


def test_parse_host_range_accepts_an_ipv6_address():
    networks = parse_host_range("2001:db8::1")

    assert len(networks) == 1
    assert str(networks[0]) == "2001:db8::1/128"


@pytest.mark.parametrize("garbage", ["not an ip", "", "   ", "10.0.0.1,,10.0.0.2"])
def test_parse_host_range_rejects_garbage(garbage):
    with pytest.raises(ValueError):
        parse_host_range(garbage)


def test_host_count_returns_one_for_a_single_ip():
    assert host_count("10.0.0.1") == 1


def test_host_count_returns_256_for_a_slash_24():
    assert host_count("10.0.0.0/24") == 256


def test_host_count_sums_every_entry_in_a_comma_separated_list():
    assert host_count("10.0.0.1,10.0.1.0/24") == 1 + 256
