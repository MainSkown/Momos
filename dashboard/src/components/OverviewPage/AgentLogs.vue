<template>
  <div class="border field">
    <span class="text-red" style="padding-left: 10px">{{
      $t("overview.agent_logs")
    }}</span>
    <div class="separator" />

    <div class="column log-panel-body">
      <div class="agent-log-screen scrollable-panel" ref="logScreenRef">
        <div
          v-for="entry in logEntries"
          :key="entry.id"
          class="log-entry"
        >
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
import { nextTick, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useMomosStore } from "@/store/momos_store";
import {
  useWebSocketClient,
  type tCallback,
} from "@/websockets/websocket_client";
import {
  getProjectAgentLogs,
  isProjectAgentRunning,
  type AgentLogResponse,
  type AgentMessage as AgentLogMessage,
  type AgentRunStatus,
} from "@/api";

const { t: $t } = useI18n();
const store = useMomosStore();
const ws_client = useWebSocketClient();

type ToolName =
  | "execute_kali_command"
  | "install_kali_package"
  | "open_session"
  | "send_to_session"
  | "read_session"
  | "close_session"
  | "list_sessions"
  | "report_vulnerability"
  | "finish_task";

const logEntries = ref<AgentLogResponse[]>([]);
const logScreenRef = ref<HTMLElement | null>(null);
const isRunning = ref(false);

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

onMounted(() => {
  loadLogs(store.openedProject);
  loadRunningStatus(store.openedProject);

  if (!ws_client.hook_exists("AgentMessage", onAgentMessage))
    ws_client.add_hook("AgentMessage", onAgentMessage);

  if (!ws_client.hook_exists("AgentRunStatus", onAgentRunStatus))
    ws_client.add_hook("AgentRunStatus", onAgentRunStatus);
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
  execute_kali_command: $t("agent_logs.tool_kali_command"),
  install_kali_package: $t("agent_logs.tool_install_package"),
  open_session: $t("agent_logs.tool_open_session"),
  send_to_session: $t("agent_logs.tool_send_to_session"),
  read_session: $t("agent_logs.tool_read_session"),
  close_session: $t("agent_logs.tool_close_session"),
  list_sessions: $t("agent_logs.tool_list_sessions"),
  report_vulnerability: $t("agent_logs.tool_report_vulnerability"),
  finish_task: $t("agent_logs.tool_finish_task"),
};

const TOOL_ICONS: Record<ToolName, string> = {
  execute_kali_command: "terminal",
  install_kali_package: "download",
  open_session: "power_settings_new",
  send_to_session: "keyboard",
  read_session: "visibility",
  close_session: "link_off",
  list_sessions: "list",
  report_vulnerability: "bug_report",
  finish_task: "task_alt",
};

function isKnownTool(toolName: string): toolName is ToolName {
  return toolName in TOOL_LABELS;
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
  align-items: center;
  gap: 8px;
}

.log-icon {
  font-size: 18px;
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
  margin-top: 2px;
  flex-shrink: 0;
}

.log-text {
  color: var(--text-gray-light);
  font-size: 0.9rem;
  line-height: 1.4;
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

.running-indicator {
  gap: 8px;
  padding: 8px;
  color: var(--text-gray-dark);
  font-size: 0.85rem;
  border-top: 2px solid var(--border-primary);
}
</style>
