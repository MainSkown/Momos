"""Verifies the pg_container fixture itself actually works end-to-end -
real container, real init_db(), a real write and read back. Every other
test under tests/integration/ depends on this fixture being trustworthy,
so it gets its own minimal, direct proof rather than being assumed correct
from the other suites passing."""

from src.schemas.project_scheme import Project


def test_pg_container_round_trips_a_real_row(pg_container):
    created = pg_container.add_project(Project(name="pg_container smoke test"))

    fetched = pg_container.get_project(created.id)

    assert fetched is not None
    assert fetched.name == "pg_container smoke test"
