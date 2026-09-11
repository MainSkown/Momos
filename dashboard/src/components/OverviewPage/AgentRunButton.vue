<template>
  <Tooltip v-if="buildingLabel" :message="buildingLabel">
    <button class="button no-border" disabled>
      <span class="loader building-loader" />
    </button>
  </Tooltip>

  <button
    v-else-if="!showTimer"
    class="button no-border"
    :disabled="!hasDuration"
    @click="handleStart"
  >
    <span v-if="hasDuration" class="material-icons-outlined">
      {{ run?.status === "paused" ? "play_circle" : "play_arrow" }}
    </span>
    <Tooltip v-else :message="$t('targets.duration_required')">
      <span class="material-icons-outlined"> timer_off </span>
    </Tooltip>
  </button>

  <button
    v-else
    class="button no-border timer-button"
    :class="{ 'timer-button--interrupted': run?.status === 'interrupted' }"
    @mouseenter="isHovering = true"
    @mouseleave="isHovering = false"
    @click="handlePause"
  >
    <span
      v-if="isHovering && run?.status === 'running'"
      class="material-icons-outlined"
    >
      pause
    </span>
    <span v-else class="timer-text">{{ formattedRemaining }}</span>
  </button>

  <Dialog
    v-if="pendingInterrupt"
    :visible="!!pendingInterrupt"
    :title="$t('targets.agent_wants_to_run')"
    :no-close-button="true"
  >
    <div class="column gap-low interrupt-body">
      <div
        v-for="(tc, idx) in pendingInterrupt.tool_calls"
        :key="idx"
        class="border interrupt-tool-call"
      >
        <div class="row interrupt-tool-header">
          <span class="material-icons-outlined">terminal</span>
          <span class="text-bold">{{ tc.name }}</span>
        </div>
        <div class="interrupt-command">
          {{ toolCallCommand(tc.args) }}
        </div>
      </div>
    </div>
    <div class="row flex-center gap-high" style="padding-inline: 10px; margin-top: 16px">
      <button class="button border" style="flex-grow: 1" @click="respondToInterrupt(true)">
        <span>{{ $t("universal.yes") }}</span>
      </button>
      <button class="button border" style="flex-grow: 1" @click="respondToInterrupt(false)">
        <span>{{ $t("universal.no") }}</span>
      </button>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import {
  getTargetAgentRun,
  startAgent,
  pauseAgent,
  type AgentRunResponse,
  type AgentRunTimer as AgentRunTimerMessage,
  type AgentInterruptRequest as AgentInterruptRequestMessage,
  type KaliCreationStageMessage,
} from "@/api";
import {
  useWebSocketClient,
  type tCallback,
} from "@/websockets/websocket_client";
import Dialog from "../reusable/Dialog.vue";
import Tooltip from "../reusable/Tooltip.vue";
import type { tTarget } from "@/types";

const { t: $t } = useI18n();
const ws_client = useWebSocketClient();

const props = defineProps<{ target: tTarget }>();

const run = ref<AgentRunResponse | null>(null);
const isHovering = ref(false);
const displayNow = ref(Date.now());
const isBuilding = ref(false);
const buildingStage = ref<string | null>(null);

const buildingLabel = computed(() => {
  if (!isBuilding.value) return null;
  return buildingStage.value
    ? $t(`console.stage.${buildingStage.value}`)
    : $t("console.connecting");
});
const pendingInterrupt = ref<AgentInterruptRequestMessage | null>(null);

const hasDuration = computed(
  () => props.target.task_duration !== null && props.target.task_duration > 0,
);

const showTimer = computed(
  () =>
    run.value !== null &&
    (run.value.status === "running" || run.value.status === "interrupted"),
);

const remainingSeconds = computed(() => {
  if (!run.value) return 0;

  if (run.value.status !== "running") return run.value.remaining_seconds;

  const recordedAt = run.value.recorded_at ?? new Date().toISOString();
  const elapsed = (displayNow.value - new Date(recordedAt).getTime()) / 1000;
  return Math.max(0, run.value.remaining_seconds - elapsed);
});

const formattedRemaining = computed(() => {
  const total = Math.max(0, Math.round(remainingSeconds.value));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
});

function toolCallCommand(args: unknown): string {
  if (args && typeof args === "object" && "command" in args) {
    return String((args as { command: unknown }).command);
  }
  return JSON.stringify(args);
}

async function loadRun() {
  const result = await getTargetAgentRun({
    path: { project_id: props.target.project_id, target_id: props.target.id },
  });
  run.value = result.data ?? null;
}

async function handleStart() {
  if (!hasDuration.value) return;

  isBuilding.value = true;
  buildingStage.value = null;

  const result = await startAgent({
    path: { project_id: props.target.project_id, target_id: props.target.id },
  });

  if (result.error) {
    isBuilding.value = false;
    const detail = (result.error as { detail?: string }).detail;
    toast.error(detail ?? $t("targets.agent_start_failed"), {
      position: toast.POSITION.TOP_CENTER,
    });
  }
  // On success, start_agent() returns almost immediately - the container
  // build (if any) and the run itself happen in the background. isBuilding
  // stays true until an AgentRunStatus/AgentRunTimer message confirms the
  // run has actually started, or an error log arrives.
}

async function handlePause() {
  if (run.value?.status !== "running") return;

  const result = await pauseAgent({
    path: { project_id: props.target.project_id, target_id: props.target.id },
  });

  if (result.error) {
    const detail = (result.error as { detail?: string }).detail;
    toast.error(detail ?? $t("targets.agent_pause_failed"), {
      position: toast.POSITION.TOP_CENTER,
    });
  }
}

function respondToInterrupt(approved: boolean) {
  if (!pendingInterrupt.value) return;

  ws_client.send_message({
    type: "AgentInterruptResponse",
    project_id: props.target.project_id,
    target_id: props.target.id,
    approved,
  });

  pendingInterrupt.value = null;
}

const onRunTimer: tCallback = (message) => {
  const timerMessage = message as AgentRunTimerMessage;

  if (timerMessage.error) return;
  if (timerMessage.run.target_id !== props.target.id) return;

  isBuilding.value = false;
  run.value = timerMessage.run;
  displayNow.value = Date.now();

  if (timerMessage.run.status !== "interrupted") {
    pendingInterrupt.value = null;
  }
};

const onInterruptRequest: tCallback = (message) => {
  const interruptMessage = message as AgentInterruptRequestMessage;

  if (interruptMessage.error) return;
  if (interruptMessage.target_id !== props.target.id) return;

  pendingInterrupt.value = interruptMessage;
};

const onKaliStage: tCallback = (message) => {
  const stageMessage = message as KaliCreationStageMessage;

  if (stageMessage.error) return;
  if (stageMessage.project_id !== props.target.project_id) return;
  if (!isBuilding.value) return;

  buildingStage.value = stageMessage.stage;
};

const onAgentMessage: tCallback = (message) => {
  // Any log entry for this target (success or failure) means we're past
  // the "building the container" phase - this is the safety net for a
  // prep failure, which never sends an AgentRunTimer to clear isBuilding.
  const m = message as { error?: unknown; log?: { target_id?: string } };

  if (m.error) return;
  if (m.log?.target_id !== props.target.id) return;

  isBuilding.value = false;
};

let tickInterval: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  loadRun();

  if (!ws_client.hook_exists("AgentRunTimer", onRunTimer))
    ws_client.add_hook("AgentRunTimer", onRunTimer);

  if (!ws_client.hook_exists("AgentInterruptRequest", onInterruptRequest))
    ws_client.add_hook("AgentInterruptRequest", onInterruptRequest);

  if (!ws_client.hook_exists("KaliCreationStage", onKaliStage))
    ws_client.add_hook("KaliCreationStage", onKaliStage);

  if (!ws_client.hook_exists("AgentMessage", onAgentMessage))
    ws_client.add_hook("AgentMessage", onAgentMessage);

  tickInterval = setInterval(() => {
    displayNow.value = Date.now();
  }, 1000);
});

onUnmounted(() => {
  if (tickInterval) clearInterval(tickInterval);
});
</script>

<style scoped lang="css">
.timer-button {
  font-family: var(--font-mono);
  font-size: 0.8rem;
}

.building-loader {
  --size: 0.35px;
}

.timer-button--interrupted {
  color: var(--red-light);
}

.interrupt-body {
  width: 420px;
}

.interrupt-tool-call {
  padding: 8px 10px;
  background-color: var(--card-bg);
  border-color: var(--border-subtle);
}

.interrupt-tool-header {
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.interrupt-command {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--text-white);
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
