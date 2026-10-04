from typing import Final, FrozenSet, Tuple

# Single source of truth for ProjectSettings.pipeline_mode's valid values -
# same pattern as tool_groups.py's TOOL_GROUP_IDS, consumed the same way by
# project_router.py's update_project_settings for a 400 on an unknown value
# rather than letting a typo silently persist as a mode nothing reads.
#
# "single_agent" is today's existing one-agent-per-target flow (agent.py) -
# this project hasn't reached an MVP yet, so there's no real "legacy" to
# speak of; it's simply the other supported mode, not a deprecated one.
# "multi_agent" is the new orchestrator/scouting/pentesting/reporting
# pipeline. Stored/compared as these exact snake_case strings; the
# dashboard displays them as "Single Agent" / "Multi Agent".
PIPELINE_MODES: Final[Tuple[str, ...]] = ("single_agent", "multi_agent")
PIPELINE_MODE_IDS: Final[FrozenSet[str]] = frozenset(PIPELINE_MODES)

DEFAULT_PIPELINE_MODE: Final[str] = "single_agent"
