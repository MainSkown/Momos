from unittest.mock import patch

from src.core.database_manager import DatabaseManager


def test_constructing_a_database_manager_does_not_run_init_db():
    # init_db runs CREATE EXTENSION/create_all/several ALTER TABLE statements
    # against a real connection - constructing a DatabaseManager must stay
    # lazy (just build the engine) so importing this module never requires a
    # live Postgres. See docs/testing-plan.md §1.0.
    with patch.object(DatabaseManager, "init_db") as mocked_init_db:
        DatabaseManager("postgresql://user:pass@nonexistent-host:5432/db")

        mocked_init_db.assert_not_called()
