import asyncio
from dataclasses import dataclass
from typing import Callable, Dict, Optional
from src.schemas import KaliCreationStage
from src.websocket import ws_registry, WsTypes, KaliContainerActiveMessage
from src.core import db_manager, tool_groups
from .kali_manager import KaliManger


@dataclass
class KaliBuildStatus:
    stage: KaliCreationStage
    # The target whose run triggered this build, if any - None for a build
    # triggered by an explicit console connect (kali_user.py) rather than
    # an agent run (agent_service.py).
    target_id: Optional[str]


class KaliRegistry:
    def __init__(self):
        self._active_managers: Dict[str, KaliManger] = {}
        # Per-project build progress - set at the same on_stage closures
        # that already emit the live KaliCreationStageMessage (kali_user.py,
        # agent_service.py), so a client that missed those (e.g. a page
        # refresh mid-build) can still recover current progress via
        # get_build_status instead of only ever seeing "not building".
        self._build_status: Dict[str, KaliBuildStatus] = {}
        # Guards ONLY the dict check/insert below, never the slow Docker
        # build itself - see get_manager's own comment for why, and
        # _builds_in_progress for how a second concurrent caller for the
        # SAME project still only triggers one build despite that.
        self._lock = asyncio.Lock()
        # project_id -> a Future that resolves to that project's manager
        # once its in-flight build finishes (or raises, if it fails) - see
        # get_manager. Lets two concurrent get_manager calls for the SAME
        # project still only build once, without needing to hold self._lock
        # across the whole build to do it: the second caller finds this
        # future already present and awaits it instead of starting its own.
        self._builds_in_progress: Dict[str, "asyncio.Future[KaliManger]"] = {}

    async def get_manager(
        self,
        project_id: str,
        on_stage: Optional[Callable[[KaliCreationStage], None]] = None,
    ) -> KaliManger:
        # Double-checked locking: the lock here only ever guards the cheap
        # dict check/insert, NOT the slow manager.start() Docker build below
        # - holding it across the whole build would block every OTHER
        # project's get_manager_if_exists/delete_manager for the entire
        # build's duration, despite those having nothing to do with this
        # project. A per-project future (`_builds_in_progress`) takes over
        # the "only build once" guarantee instead: the first caller for a
        # given project_id becomes that project's builder and stores a
        # not-yet-resolved future for it; every other concurrent caller for
        # the SAME project_id sees that future already there and awaits it
        # (outside the lock) rather than starting a second build.
        async with self._lock:
            if project_id in self._active_managers:
                return self._active_managers[project_id]

            existing_build = self._builds_in_progress.get(project_id)
            if existing_build is not None:
                is_builder = False
                build_future = existing_build
            else:
                is_builder = True
                build_future = asyncio.get_running_loop().create_future()
                # Marks a failed build's exception "retrieved" even when no
                # concurrent waiter ever awaits this future (the solo-caller
                # case: the builder itself raises the same exception
                # directly, below) - without this, asyncio logs a spurious
                # "exception was never retrieved" warning on every failed
                # build that had no concurrent waiter.
                build_future.add_done_callback(
                    lambda f: f.exception() if not f.cancelled() else None
                )
                self._builds_in_progress[project_id] = build_future

        if not is_builder:
            # Someone else is already building this exact project - wait
            # for THEIR result instead of starting a second one. Raises
            # here if their build itself failed, same as if this call had
            # done the (failing) build itself.
            return await build_future

        try:
            # Only reached once per project (every other call above hits
            # the cached-manager branch, or awaits this call's own build
            # above) - the one place that needs to know which tool groups
            # this project has enabled, so no other get_manager caller
            # needs a new parameter. A container that already exists keeps
            # whatever packages it was built with even if enabled_tools
            # changes later - by design, see tool_groups.py/ProjectSettings.
            # enabled_tools' own comments.
            loop = asyncio.get_running_loop()
            settings = await loop.run_in_executor(
                None, db_manager.get_project_settings, project_id
            )
            packages = tool_groups.packages_for_enabled_tools(
                settings.enabled_tools if settings else None
            )
            manager = KaliManger(
                container_name=f"momos-kali-worker-{project_id}", packages=packages
            )
            await manager.start(on_stage=on_stage)
        except BaseException as e:
            async with self._lock:
                self._builds_in_progress.pop(project_id, None)
            build_future.set_exception(e)
            raise

        async with self._lock:
            self._active_managers[project_id] = manager
            self._builds_in_progress.pop(project_id, None)
        build_future.set_result(manager)

        # Broadcast outside the lock (send_message doesn't need it, and
        # holding a lock across a websocket send is unnecessary). This is
        # the single chokepoint every trigger - an agent run, an explicit
        # console connect, or any Kali-using tool - goes through, unlike
        # CreatedKaliUserMessage which only fires for the console-connect
        # flow. Only the builder sends this (once per actual build) - a
        # waiter that joined via build_future above just returns the same
        # result without broadcasting again.
        await ws_registry.send_message(
            KaliContainerActiveMessage(
                project_id=project_id, type=WsTypes.KaliContainerActive
            )
        )
        return manager

    def has_manager(self, project_id: str) -> bool:
        return project_id in self._active_managers

    def set_build_stage(
        self, project_id: str, stage: KaliCreationStage, target_id: Optional[str] = None
    ) -> None:
        self._build_status[project_id] = KaliBuildStatus(stage=stage, target_id=target_id)

    def clear_build_status(self, project_id: str) -> None:
        self._build_status.pop(project_id, None)

    def get_build_status(self, project_id: str) -> Optional[KaliBuildStatus]:
        return self._build_status.get(project_id)

    async def get_manager_if_exists(self, project_id: str) -> Optional[KaliManger]:
        """Like get_manager, but never creates one - for cleanup paths (e.g.
        closing a target's sessions when its run ends) that shouldn't spin
        up a container just because a run is finishing."""
        async with self._lock:
            return self._active_managers.get(project_id)

    async def delete_manager(self, project_id: str):
        async with self._lock:
            manager = self._active_managers.pop(project_id, None)

        if manager is not None:
            await manager.stop()

    async def shutdown(self):
        async with self._lock:
            managers = list(self._active_managers.values())
            self._active_managers.clear()

        await asyncio.gather(
            *(manager.stop() for manager in managers),
            return_exceptions=True,
        )

kali_registry = KaliRegistry()