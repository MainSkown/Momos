import uuid

from src.schemas.attack_vector_scheme import AttackVector


def make_attack_vector(**overrides) -> AttackVector:
    return AttackVector(
        description="vsftpd 2.3.4 backdoor",
        project_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        **overrides,
    )


def test_extra_tool_groups_round_trips_through_the_model():
    vector = make_attack_vector(extra_tool_groups=["ftp", "ssh"])

    assert vector.extra_tool_groups == ["ftp", "ssh"]


def test_extra_tool_groups_defaults_to_none_not_empty_list():
    assert make_attack_vector().extra_tool_groups is None
