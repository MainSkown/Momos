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
      <div class="agent-log-screen scrollable-panel" ref="logScreenRef">
        <template v-for="(entry, index) in logEntries" :key="entry.id">
          <div
            v-if="dividerLabel(entry, logEntries[index - 1])"
            class="log-section-divider"
          >
            <span>{{ dividerLabel(entry, logEntries[index - 1]) }}</span>
          </div>

          <div class="log-entry">
            <!-- Thinking -->
            <div v-if="entry.type === 'thinking'" class="log-row">
              <span class="material-icons-outlined log-icon log-icon--thinking"
                >psychology</span
              >
              <span class="log-timestamp">{{ formatTimestamp(entry.created_at) }}</span>
              <span class="log-text log-text--thinking">{{ entry.content }}</span>
            </div>

            <!-- Narrated action / status update -->
            <div v-else-if="entry.type === 'action'" class="log-row">
              <span class="material-icons-outlined log-icon log-icon--action"
                >bolt</span
              >
              <span class="log-timestamp">{{ formatTimestamp(entry.created_at) }}</span>
              <span class="log-text">{{ entry.content }}</span>
            </div>

            <!-- Tool usage -->
            <div v-else class="tool-card border">
              <div class="row tool-card-header">
                <span class="material-icons-outlined log-icon log-icon--tool">{{
                  toolIcon(entry.tool_name)
                }}</span>
                <span class="tool-name">{{ toolLabel(entry.tool_name) }}</span>
                <span class="log-timestamp tool-timestamp">{{
                  formatTimestamp(entry.created_at)
                }}</span>
              </div>
              <div class="tool-content">{{ entry.content }}</div>
            </div>
          </div>
        </template>

        <div v-if="logEntries.length === 0" class="text-center no-logs">
          {{ $t("agent_logs.no_logs") }}
        </div>

        <div v-if="isRunning" class="row flex-center running-indicator">
          <span>{{ $t("agent_logs.running") }}</span> <span class="loader" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
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

const { t: $t } = useI18n();
const store = useMomosStore();
const ws_client = useWebSocketClient();

type ToolName =
  | "install_kali_package"
  | "run"
  | "new_session"
  | "switch_session"
  | "close_session"
  | "list_sessions"
  | "interrupt_session"
  | "switch_mode"
  | "report_vulnerability"
  | "log_attack_attempt"
  | "finish_task"
  | "propose_attack_vector"
  | "report_outcome"
  | "dispatch_pentest_batch"
  | "request_report"
  | "run_scouting";

// Multi Agent mode's AgentLogResponse rows carry role/agent_run_id (always
// "single_agent" for the Single Agent flow, never varying within one run -
// see agent_service.py's _run_agent) - a divider is only ever meaningful
// between two different Multi Agent sub-runs.
type Role = "orchestrator" | "scouting" | "pentesting" | "reporting";

const ROLE_LABELS: Record<Role, string> = {
  orchestrator: $t("agent_logs.role_orchestrator"),
  scouting: $t("agent_logs.role_scouting"),
  pentesting: $t("agent_logs.role_pentesting"),
  reporting: $t("agent_logs.role_reporting"),
};

function isKnownRole(role: string): role is Role {
  return role in ROLE_LABELS;
}

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
const logScreenRef = ref<HTMLElement | null>(null);
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

// Auto-scroll to the newest entry as new logs come in
watch(
  logEntries,
  async () => {
    await nextTick();
    if (logScreenRef.value) {
      logScreenRef.value.scrollTop = logScreenRef.value.scrollHeight;
    }
  },
  { deep: true },
);

const TOOL_LABELS: Record<ToolName, string> = {
  install_kali_package: $t("agent_logs.tool_install_package"),
  run: $t("agent_logs.tool_run"),
  new_session: $t("agent_logs.tool_new_session"),
  switch_session: $t("agent_logs.tool_switch_session"),
  close_session: $t("agent_logs.tool_close_session"),
  list_sessions: $t("agent_logs.tool_list_sessions"),
  interrupt_session: $t("agent_logs.tool_interrupt_session"),
  switch_mode: $t("agent_logs.tool_switch_mode"),
  report_vulnerability: $t("agent_logs.tool_report_vulnerability"),
  log_attack_attempt: $t("agent_logs.tool_log_attack_attempt"),
  finish_task: $t("agent_logs.tool_finish_task"),
  propose_attack_vector: $t("agent_logs.tool_propose_attack_vector"),
  report_outcome: $t("agent_logs.tool_report_outcome"),
  dispatch_pentest_batch: $t("agent_logs.tool_dispatch_pentest_batch"),
  request_report: $t("agent_logs.tool_request_report"),
  run_scouting: $t("agent_logs.tool_run_scouting"),
};

const TOOL_ICONS: Record<ToolName, string> = {
  install_kali_package: "download",
  run: "terminal",
  new_session: "power_settings_new",
  switch_session: "swap_horiz",
  close_session: "link_off",
  list_sessions: "list",
  interrupt_session: "block",
  switch_mode: "compare_arrows",
  report_vulnerability: "bug_report",
  log_attack_attempt: "history_edu",
  finish_task: "task_alt",
  propose_attack_vector: "flag",
  report_outcome: "fact_check",
  dispatch_pentest_batch: "call_split",
  request_report: "summarize",
  run_scouting: "travel_explore",
};

function isKnownTool(toolName: string): toolName is ToolName {
  return toolName in TOOL_LABELS;
}

// Shows a divider right before the first entry of a new Multi Agent
// sub-run (grouped by agent_run_id, not just role - two concurrent
// pentesting sub-runs share the same role but are still two distinct
// runs). Single Agent mode's role never varies within a run, so this
// never fires for it.
function dividerLabel(
  entry: AgentLogResponse,
  prevEntry: AgentLogResponse | undefined,
): string | null {
  if (!entry.role || !isKnownRole(entry.role)) return null;
  if (prevEntry && prevEntry.agent_run_id === entry.agent_run_id) return null;

  const label = ROLE_LABELS[entry.role];
  const shortId = entry.agent_run_id ? entry.agent_run_id.slice(0, 8) : null;
  return shortId ? `${label} (${shortId}…)` : label;
}

function toolLabel(toolName?: string | null): string {
  if (!toolName) return "";
  return isKnownTool(toolName) ? TOOL_LABELS[toolName] : toolName;
}

function toolIcon(toolName?: string | null): string {
  if (!toolName || !isKnownTool(toolName)) return "build";
  return TOOL_ICONS[toolName];
}

function formatTimestamp(createdAt: string): string {
  return new Date(createdAt).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}
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

.agent-log-screen {
  display: flex;
  flex-direction: column;
  gap: 10px;

  width: 100%;
  box-sizing: border-box;
  background-color: var(--black);
  border-bottom: 2px solid var(--border-primary);

  padding: 10px var(--spacing-md) var(--spacing-md) var(--spacing-md);

  flex: 1;
  min-height: 0;
}

.log-row {
  display: flex;
  align-items: start ;
  text-justify: center;
  gap: 8px;
}

.log-icon {
  font-size: 18px;
  margin-top: 2px;
  flex-shrink: 0;
}

.log-icon--thinking {
  color: var(--text-gray-dark);
}

.log-icon--action {
  color: var(--red-primary);
}

.log-icon--tool {
  color: var(--red-primary);
}

.log-timestamp {
  color: var(--text-gray-darker);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  margin-top: 5px;
  flex-shrink: 0;
}

.log-text {
  color: var(--text-gray-light);
  font-size: 0.9rem;
  line-height: 1.4;
  /* Tool/thinking content often has real newlines (e.g. nmap_scan's
     per-port digest) - the default `white-space: normal` silently
     collapses them into spaces, squashing multi-line output onto one
     line. Match .tool-content's handling below. */
  white-space: pre-wrap;
  word-break: break-word;
}

.log-text--thinking {
  color: var(--text-gray-dark);
  font-style: italic;
}

.tool-card {
  padding: 8px 10px;
  background-color: var(--card-bg);
  border-color: var(--border-subtle);
}

.tool-card-header {
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.tool-name {
  color: var(--red-light);
  font-size: 0.8rem;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.tool-timestamp {
  margin-left: auto;
}

.tool-content {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--text-white);
  white-space: pre-wrap;
  word-break: break-word;
  padding-left: 26px;
}

.no-logs {
  color: var(--text-gray-dark);
  margin-top: auto;
  margin-bottom: auto;
}

.log-section-divider {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-gray-dark);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.log-section-divider::before,
.log-section-divider::after {
  content: "";
  flex: 1;
  height: 1px;
  background-color: var(--border-subtle);
}

.running-indicator {
  gap: 8px;
  padding: 8px;
  color: var(--text-gray-dark);
  font-size: 0.85rem;
  border-top: 2px solid var(--border-primary);
}
</style>
