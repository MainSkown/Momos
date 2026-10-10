<template>
  <div class="border field">
    <div class="row log-header">
      <span class="text-red" style="padding-left: 10px">{{
        $t("overview.agent_logs")
      }}</span>
      <HoverMenu v-if="activeAgentCount > 0">
        <template #trigger>
          <span class="text-gray active-agent-count">{{ activeAgentCountLabel }}</span>
        </template>

        <div
          v-for="agent in activeAgents"
          :key="agent.agentRunId"
          class="row active-agent-row"
        >
          <span class="active-agent-label">{{ agentRowLabel(agent.role, agent.agentRunId) }}</span>
          <ContextUsageRing
            v-if="agent.usage"
            :used-tokens="agent.usage.used"
            :context-window="agent.usage.window"
          />
          <span v-else class="text-gray-dark active-agent-pending">—</span>
        </div>
      </HoverMenu>
    </div>
    <div class="separator" />

    <div class="column log-panel-body">
      <LogEntryList :entries="logEntries" :is-running="isRunning" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useMomosStore } from "@/store/momos_store";
import {
  useWebSocketClient,
  type tCallback,
} from "@/websockets/websocket_client";
import {
  getProjectAgentLogs,
  getTargetAgentRunTree,
  isProjectAgentRunning,
  type AgentLogResponse,
  type AgentMessage as AgentLogMessage,
  type AgentRunState,
  type AgentRunStatus,
  type AgentRunTimer as AgentRunTimerMessage,
  type AgentContextUsage as AgentContextUsageMessage,
} from "@/api";
import ContextUsageRing from "../reusable/ContextUsageRing.vue";
import HoverMenu from "../reusable/HoverMenu.vue";
import LogEntryList from "../reusable/LogEntryList.vue";

const { t: $t } = useI18n();
const store = useMomosStore();
const ws_client = useWebSocketClient();

// Multi Agent mode's AgentLogResponse rows carry role/agent_run_id (always
// "single_agent" for the Single Agent flow, never varying within one run -
// see agent_service.py's _run_agent). Only used here for the active-agent
// HoverMenu's own labels (RUN_ROLE_LABELS below) - LogEntryList.vue owns
// its own identical copy for the log-stream dividers, since the two
// genuinely don't share any state, only the same label strings.
type Role = "orchestrator" | "scouting" | "pentesting" | "reporting";

const ROLE_LABELS: Record<Role, string> = {
  orchestrator: $t("agent_logs.role_orchestrator"),
  scouting: $t("agent_logs.role_scouting"),
  pentesting: $t("agent_logs.role_pentesting"),
  reporting: $t("agent_logs.role_reporting"),
};

// Unlike ROLE_LABELS above (only ever used for Multi Agent sub-run
// dividers), the active-agent indicator below also has to label a Single
// Agent mode run - it's the same "N agent(s)" indicator either way, just
// always showing exactly one entry for that mode.
const RUN_ROLE_LABELS: Record<string, string> = {
  ...ROLE_LABELS,
  single_agent: $t("settings.pipeline_mode_single_agent"),
};

const ROLE_SORT_ORDER = ["single_agent", "orchestrator", "scouting", "pentesting", "reporting"];

// A run counts as "active" (not yet ended its task) while it's genuinely
// working or blocked waiting on an interrupt approval - a deliberately
// paused run doesn't count, since the user parked it on purpose.
const ACTIVE_RUN_STATES = new Set<AgentRunState>(["running", "interrupted"]);

interface TrackedRun {
  role: string | null;
  status: AgentRunState;
}

interface RunUsage {
  used: number;
  window: number;
}

const logEntries = ref<AgentLogResponse[]>([]);
const isRunning = ref(false);
// Keyed by agent_run_id - Single Agent mode only ever has one entry,
// Multi Agent mode can have several concurrent ones (the orchestrator's
// own run plus whichever scouting/pentesting/reporting sub-runs it has
// in flight).
const runStatuses = ref<Record<string, TrackedRun>>({});
const runUsages = ref<Record<string, RunUsage>>({});

function agentRowLabel(role: string | null, agentRunId: string): string {
  const label = role && role in RUN_ROLE_LABELS ? RUN_ROLE_LABELS[role] : role ?? "?";
  return `${label} (${agentRunId.slice(0, 8)}…)`;
}

const activeAgents = computed(() =>
  Object.entries(runStatuses.value)
    .filter(([, run]) => ACTIVE_RUN_STATES.has(run.status))
    .map(([agentRunId, run]) => ({
      agentRunId,
      role: run.role,
      usage: runUsages.value[agentRunId] ?? null,
    }))
    .sort((a, b) => {
      const aOrder = a.role ? ROLE_SORT_ORDER.indexOf(a.role) : -1;
      const bOrder = b.role ? ROLE_SORT_ORDER.indexOf(b.role) : -1;
      if (aOrder !== bOrder) return aOrder - bOrder;
      return a.agentRunId.localeCompare(b.agentRunId);
    }),
);

const activeAgentCount = computed(() => activeAgents.value.length);

const activeAgentCountLabel = computed(() =>
  activeAgentCount.value === 1
    ? $t("agent_logs.active_agent_count_one", { count: 1 })
    : $t("agent_logs.active_agent_count_other", { count: activeAgentCount.value }),
);

// Target-scoped (unlike every other load in this file, which is
// project-scoped) because the run-tree endpoint needs a target id - safe
// since only one target can ever be running per project at a time (see
// AgentService.start_agent's own exclusivity rule), same assumption
// AttackVectors.vue's own runningTargetId already relies on.
const activeTargetId = computed(() => store.getRunningTarget(store.openedProject));

watch(
  activeTargetId,
  async (targetId) => {
    runUsages.value = {};

    if (!targetId) {
      runStatuses.value = {};
      return;
    }

    const result = await getTargetAgentRunTree({
      path: { project_id: store.openedProject, target_id: targetId },
    });

    const statuses: Record<string, TrackedRun> = {};
    for (const run of result.data ?? []) {
      statuses[run.id] = { role: run.role ?? null, status: run.status };
    }
    runStatuses.value = statuses;
  },
  { immediate: true },
);

async function loadLogs(project_id: string) {
  if (!project_id) {
    logEntries.value = [];
    return;
  }

  const result = await getProjectAgentLogs({ path: { project_id } });
  logEntries.value = result.data ?? [];
}

async function loadRunningStatus(project_id: string) {
  if (!project_id) {
    isRunning.value = false;
    return;
  }

  const result = await isProjectAgentRunning({ path: { project_id } });
  isRunning.value = result.data?.running ?? false;
}

const onAgentMessage: tCallback = (message) => {
  const agentMessage = message as AgentLogMessage;

  if (agentMessage.error) return;
  if (agentMessage.log.project_id !== store.openedProject) return;

  logEntries.value.push(agentMessage.log);
};

const onAgentRunStatus: tCallback = (message) => {
  const statusMessage = message as AgentRunStatus;

  if (statusMessage.error) return;
  if (statusMessage.project_id !== store.openedProject) return;

  isRunning.value = statusMessage.running;
};

const onContextUsage: tCallback = (message) => {
  const usageMessage = message as AgentContextUsageMessage;

  if (usageMessage.error) return;
  if (usageMessage.project_id !== store.openedProject) return;
  if (!usageMessage.agent_run_id) return;

  runUsages.value[usageMessage.agent_run_id] = {
    used: usageMessage.used_tokens,
    window: usageMessage.context_window,
  };
};

// Unlike AgentRunButton.vue's own AgentRunTimer hook (which only cares
// about the root run, for its own pause/resume display), this one tracks
// every run under the current project's pipeline - including every
// scouting/pentesting/reporting sub-run - to keep activeAgents accurate.
const onAgentRunTimer: tCallback = (message) => {
  const timerMessage = message as AgentRunTimerMessage;

  if (timerMessage.error) return;
  if (timerMessage.run.project_id !== store.openedProject) return;

  runStatuses.value[timerMessage.run.id] = {
    role: timerMessage.run.role ?? null,
    status: timerMessage.run.status,
  };
};

onMounted(() => {
  loadLogs(store.openedProject);
  loadRunningStatus(store.openedProject);

  if (!ws_client.hook_exists("AgentMessage", onAgentMessage))
    ws_client.add_hook("AgentMessage", onAgentMessage);

  if (!ws_client.hook_exists("AgentRunStatus", onAgentRunStatus))
    ws_client.add_hook("AgentRunStatus", onAgentRunStatus);

  if (!ws_client.hook_exists("AgentContextUsage", onContextUsage))
    ws_client.add_hook("AgentContextUsage", onContextUsage);

  if (!ws_client.hook_exists("AgentRunTimer", onAgentRunTimer))
    ws_client.add_hook("AgentRunTimer", onAgentRunTimer);
});

watch(
  () => store.openedProject,
  (newProject) => {
    loadLogs(newProject);
    loadRunningStatus(newProject);
  },
);

</script>

<style scoped lang="css">
.log-header {
  align-items: center;
  justify-content: space-between;
  padding-right: 10px;
}

.active-agent-count {
  font-size: 0.8rem;
  white-space: nowrap;
}

.active-agent-row {
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-md);
}

.active-agent-label {
  white-space: nowrap;
}

.active-agent-pending {
  font-size: 0.8rem;
}

.log-panel-body {
  flex: 1;
  min-height: 0;
}
</style>
