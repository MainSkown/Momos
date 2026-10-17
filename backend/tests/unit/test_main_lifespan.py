from unittest.mock import AsyncMock, MagicMock

import pytest

import main


@pytest.mark.asyncio
async def test_lifespan_initializes_db_before_checking_orphaned_sessions(monkeypatch):
    # mark_orphaned_sessions_aborted queries tables init_db() creates - if
    # the two calls were ever reordered it would break against a fresh
    # database. See docs/testing-plan.md §1.0.
    call_order = []
    monkeypatch.setattr(main, "export_json_schema", MagicMock())
    monkeypatch.setattr(main, "setup_checkpointer", AsyncMock())
    monkeypatch.setattr(main, "shutdown_checkpointer", AsyncMock())
    monkeypatch.setattr(main.kali_registry, "shutdown", AsyncMock())
    monkeypatch.setattr(
        main.db_manager, "init_db", lambda: call_order.append("init_db")
    )
    monkeypatch.setattr(
        main.db_manager,
        "mark_orphaned_sessions_aborted",
        lambda: call_order.append("mark_orphaned_sessions_aborted"),
    )

    app = MagicMock()

    async with main.lifespan(app):
        pass

    assert call_order == ["init_db", "mark_orphaned_sessions_aborted"]
