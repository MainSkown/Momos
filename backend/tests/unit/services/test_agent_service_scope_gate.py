"""AgentService.start_agent's scope-acknowledgment gate (milestone 1, B4).

No tests/unit/services/test_agent_service.py exists yet to exercise
start_agent's other pre-condition checks (duration/model) directly against
the service - those are currently only pinned at the router level (see
tests/unit/routers/test_agent_router.py) and through the heavier §1.4b
integration tier (tests/integration/api/test_agent_api.py). Rather than
build a large integration-style file to cover the whole function, this
file mocks just enough of start_agent's preceding state (owned target,
running-checks, project settings) to reach the new scope check, and proves
the ordering around it without executing the rest of the function (Kali/
Ollama/checkpointer wiring) that the existing tiers already own.
"""

import uuid
from unittest.mock import MagicMock

import pytest

from src.schemas.project_scheme import Project, ProjectSettings
from src.schemas.target_scheme import Target
from src.services.agent_service import AgentService
from src.utils.exceptions import ScopeNotAcknowledgedException


@pytest.fixture
def service_db(monkeypatch, fake_db_manager):
    monkeypatch.setattr("src.services.agent_service.db_manager", fake_db_manager)
    return fake_db_manager


class _ReachedResumeLogic(Exception):
    """Raised by a mocked get_agent_run to prove start_agent's execution
    reached the pipeline-mode/resume logic that comes right after the new
    scope check - the thing that comes "after" in the ordering this check
    must not disturb."""


def _wire_passing_preconditions(service_db, project_id, target_id):
    project = Project(id=project_id, name="scoped-project")
    target = Target(
        id=target_id,
        project_id=project_id,
        name="scoped-target",
        ipv4=None,
        ipv6=None,
        description=None,
        ports=None,
        task_duration=None,
        # "until_vectors_checked" needs no task_duration, so the existing
        # DurationNotDefinedInTarget check (which runs before the scope
        # gate) never fires here - keeps this file scoped to the new check.
        run_mode="until_vectors_checked",
    )
    settings = ProjectSettings(
        project_id=project_id,
        should_interrupt=False,
        starting_prompt="",
        base_model_name="qwen3:8b",
        parsing_model_name="",
    )

    service_db.get_project.return_value = project
    service_db.get_target.return_value = target
    service_db.get_project_settings.return_value = settings
    service_db.get_agent_run.side_effect = _ReachedResumeLogic()


async def test_start_agent_raises_when_scope_not_acknowledged(service_db, monkeypatch):
    project_id = uuid.uuid4()
    target_id = uuid.uuid4()
    _wire_passing_preconditions(service_db, project_id, target_id)

    monkeypatch.setattr(
        "src.services.agent_service.ProjectScopeService.is_acknowledged",
        MagicMock(return_value=False),
    )

    with pytest.raises(ScopeNotAcknowledgedException):
        await AgentService.start_agent(str(project_id), str(target_id))

    # The gate must short-circuit before the pipeline-mode/resume logic -
    # get_agent_run (and so _ReachedResumeLogic) is never reached.
    service_db.get_agent_run.assert_not_called()


async def test_start_agent_proceeds_past_scope_gate_when_acknowledged(
    service_db, monkeypatch
):
    project_id = uuid.uuid4()
    target_id = uuid.uuid4()
    _wire_passing_preconditions(service_db, project_id, target_id)

    monkeypatch.setattr(
        "src.services.agent_service.ProjectScopeService.is_acknowledged",
        MagicMock(return_value=True),
    )

    # Proves the gate doesn't swallow or stop execution on the acknowledged
    # path - start_agent runs on into the existing resume/fresh-start logic
    # immediately after it, hitting the mocked get_agent_run call.
    with pytest.raises(_ReachedResumeLogic):
        await AgentService.start_agent(str(project_id), str(target_id))
