from src.schemas.agent_run_scheme import AGENT_RUN_ROLES, AgentRunBase


def test_agent_run_roles_are_exactly_the_five_known_roles():
    assert AGENT_RUN_ROLES == (
        "single_agent",
        "orchestrator",
        "scouting",
        "pentesting",
        "reporting",
    )


def test_agent_run_role_default_is_a_known_role():
    default_role = AgentRunBase.model_fields["role"].default

    assert default_role in AGENT_RUN_ROLES
