<template>
  <div class="border field">
    <span class="text-red" style="padding-left: 10px">{{
      $t("overview.agent_logs")
    }}</span>
    <div class="separator" />

    <div class="column log-panel-body">
      <div class="agent-log-screen scrollable-panel">
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
            <span class="log-timestamp">{{ entry.timestamp }}</span>
            <span class="log-text log-text--thinking">{{ entry.content }}</span>
          </div>

          <!-- Narrated action / status update -->
          <div v-else-if="entry.type === 'action'" class="log-row">
            <span class="material-icons-outlined log-icon log-icon--action"
              >bolt</span
            >
            <span class="log-timestamp">{{ entry.timestamp }}</span>
            <span class="log-text">{{ entry.content }}</span>
          </div>

          <!-- Tool usage -->
          <div v-else class="tool-card border">
            <div class="row tool-card-header">
              <span class="material-icons-outlined log-icon log-icon--tool">{{
                toolIcon(entry.toolName)
              }}</span>
              <span class="tool-name">{{ toolLabel(entry.toolName) }}</span>
              <span class="log-timestamp tool-timestamp">{{
                entry.timestamp
              }}</span>
            </div>
            <div class="tool-content">{{ entry.content }}</div>
          </div>
        </div>

        <div v-if="logEntries.length === 0" class="text-center no-logs">
          {{ $t("agent_logs.no_logs") }}
        </div>

        <div class="row flex-center running-indicator">
          <span>{{ $t("agent_logs.running") }}</span> <span class="loader" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from "vue-i18n";

const { t: $t } = useI18n();

type LogEntryType = "thinking" | "action" | "tool";
type ToolName = "execute_kali_command" | "report_vulnerability";

interface AgentLogEntry {
  id: string;
  type: LogEntryType;
  timestamp: string;
  content: string;
  toolName?: ToolName;
}

// Example entries for UI review - static mockup data, not wired to the backend yet.
const logEntries: AgentLogEntry[] = [
  {
    id: "1",
    type: "thinking",
    timestamp: "14:32:01",
    content:
      "The target appears to be a web server. I should enumerate open ports before probing further.",
  },
  {
    id: "2",
    type: "tool",
    toolName: "execute_kali_command",
    timestamp: "14:32:04",
    content: "nmap -sV -p- 10.0.0.5",
  },
  {
    id: "3",
    type: "action",
    timestamp: "14:33:52",
    content:
      "Found 3 open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS). Apache 2.4.52 detected on port 80.",
  },
  {
    id: "4",
    type: "thinking",
    timestamp: "14:33:58",
    content:
      "Apache 2.4.52 is an outdated version with known CVEs. Worth checking for common web vulnerabilities.",
  },
  {
    id: "5",
    type: "tool",
    toolName: "execute_kali_command",
    timestamp: "14:34:02",
    content: "nikto -h http://10.0.0.5",
  },
  {
    id: "6",
    type: "action",
    timestamp: "14:35:41",
    content:
      "Nikto flagged an outdated Apache version and a missing X-Frame-Options header.",
  },
  {
    id: "7",
    type: "tool",
    toolName: "report_vulnerability",
    timestamp: "14:35:47",
    content: "Outdated Apache 2.4.52 exposes known CVEs (CVSS v4.0: 7.5)",
  },
  {
    id: "8",
    type: "action",
    timestamp: "14:35:49",
    content: "Recorded finding. Continuing enumeration on port 443...",
  },
];

const TOOL_LABELS: Record<ToolName, string> = {
  execute_kali_command: $t("agent_logs.tool_kali_command"),
  report_vulnerability: $t("agent_logs.tool_report_vulnerability"),
};

const TOOL_ICONS: Record<ToolName, string> = {
  execute_kali_command: "terminal",
  report_vulnerability: "bug_report",
};

function toolLabel(toolName?: ToolName): string {
  return toolName ? TOOL_LABELS[toolName] : "";
}

function toolIcon(toolName?: ToolName): string {
  return toolName ? TOOL_ICONS[toolName] : "build";
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
