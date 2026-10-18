import uuid

import pytest

from src.schemas.project_scheme import (
    ProjectSettings,
    ProjectSettingsBody,
    project_settings_factory,
)
from src.services.project_service import ProjectService
from src.utils.exceptions import ProjectDoesNotExistException


@pytest.fixture
def service_db(monkeypatch, fake_db_manager):
    monkeypatch.setattr("src.services.project_service.db_manager", fake_db_manager)
    fake_db_manager.add_project.side_effect = lambda project: project
    fake_db_manager.get_project_settings.side_effect = project_settings_factory
    fake_db_manager.update_project_settings.side_effect = lambda settings: settings
    return fake_db_manager


def test_add_project_stores_both_model_names_on_the_new_projects_settings(service_db):
    project = ProjectService.add_project("alpha", "base-model", "parse-model")

    saved_settings = service_db.update_project_settings.call_args.args[0]
    assert saved_settings.project_id == project.id
    assert saved_settings.base_model_name == "base-model"
    assert saved_settings.parsing_model_name == "parse-model"


def test_add_project_reads_settings_for_the_created_project_id(service_db):
    project = ProjectService.add_project("alpha", "base-model", "parse-model")

    service_db.get_project_settings.assert_called_once_with(project.id)


def test_add_project_raises_when_settings_row_was_not_created(service_db):
    service_db.get_project_settings.side_effect = None
    service_db.get_project_settings.return_value = None

    with pytest.raises(AttributeError):
        ProjectService.add_project("alpha", "base-model", "parse-model")


def test_add_project_leaves_project_behind_when_settings_update_fails(service_db):
    service_db.update_project_settings.side_effect = RuntimeError("db down")

    with pytest.raises(RuntimeError):
        ProjectService.add_project("alpha", "base-model", "parse-model")

    service_db.add_project.assert_called_once()


def test_get_project_settings_raises_when_project_missing(service_db):
    """get_project_settings(create_new=True) would otherwise insert a
    settings row referencing a nonexistent project and surface the FK
    violation as a raw IntegrityError - see routers.md's confirmed gap for
    GET/PUT /project/{id}/settings."""
    service_db.get_project.return_value = None

    with pytest.raises(ProjectDoesNotExistException):
        ProjectService.get_project_settings(str(uuid.uuid4()))

    service_db.get_project_settings.assert_not_called()


def test_update_project_settings_forwards_every_body_field_unchanged(service_db):
    body = ProjectSettingsBody(
        project_id=uuid.uuid4(),
        should_interrupt=True,
        starting_prompt="custom prompt",
        base_model_name="base",
        parsing_model_name="parse",
        pipeline_mode="single_agent",
        max_concurrent_agents=3,
        enabled_tools=["nmap", "hydra"],
        max_context_window=8192,
        allow_shell=False,
    )

    ProjectService.update_project_settings(body)

    forwarded = service_db.update_project_settings.call_args.args[0]
    assert isinstance(forwarded, ProjectSettings)
    assert forwarded.model_dump() == body.model_dump()


def test_update_project_settings_returns_the_saved_settings(service_db):
    body = ProjectSettingsBody(
        project_id=uuid.uuid4(),
        should_interrupt=False,
        starting_prompt="p",
        base_model_name="base",
        parsing_model_name="parse",
    )

    result = ProjectService.update_project_settings(body)

    assert isinstance(result, ProjectSettings)
    assert result.model_dump() == body.model_dump()
