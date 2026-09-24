<template>
  <Tooltip v-if="buildingLabel" :message="buildingLabel">
    <button class="button no-border" disabled>
      <span class="loader building-loader" />
    </button>
  </Tooltip>

  <button
    v-else-if="!showTimer && run?.status !== 'paused'"
    class="button no-border"
    :disabled="!hasDuration"
    @click="handleStart"
  >
    <span v-if="hasDuration" class="material-icons-outlined"> play_arrow </span>
    <Tooltip v-else :message="$t('targets.duration_required')">
      <span class="material-icons-outlined"> timer_off </span>
    </Tooltip>
  </button>

  <!-- Paused (click resumes, hold finishes) or running/interrupted (click
       pauses, hold finishes) - both share the same hold-to-finish
       machinery, only the click action and icon differ. -->
  <div v-else class="timer-button-wrapper">
    <!-- Adapted from ContextUsageRing.vue's stroke-dasharray/dashoffset
         technique - not extracted into a shared component since this is a
         live rAF-driven hold-progress ring coupled to icon-swap state,
         while ContextUsageRing is a static fraction display; the overlap
         is small enough that a shared primitive would be premature. -->
    <svg v-if="isHolding" class="hold-ring" viewBox="0 0 40 40">
      <circle
        class="hold-ring-track"
        cx="20"
        cy="20"
        r="17"
        fill="none"
        stroke-width="3"
      />
      <circle
        class="hold-ring-fill"
        cx="20"
        cy="20"
        r="17"
        fill="none"
        stroke-width="3"
        stroke-linecap="round"
        :stroke-dasharray="HOLD_RING_CIRCUMFERENCE"
        :stroke-dashoffset="holdDashOffset"
      />
    </svg>

    <Tooltip :message="holdTooltipMessage">
      <button
        class="button no-border timer-button"
        :class="{
          'timer-button--interrupted': run?.status === 'interrupted',
          'timer-button--holding': isHolding,
        }"
        :disabled="run?.status === 'paused' && !hasDuration"
        @mouseenter="isHovering = true"
        @mouseleave="onButtonLeave"
        @mousedown="onHoldStart"
        @mouseup="onHoldEnd"
        @click="handleClick"
      >
        <span v-if="isHolding" class="material-icons-outlined">stop</span>
        <span v-else-if="run?.status === 'paused'" class="material-icons-outlined">
          play_circle
        </span>
        <span
          v-else-if="isHovering && run?.status === 'running'"
          class="material-icons-outlined"
        >
          pause
        </span>
        <span v-else class="timer-text">{{ formattedRemaining }}</span>
      </button>
    </Tooltip>
  </div>

  <Dialog v-if="pendingInterrupt" :visible="!!pendingInterrupt" :no-close-button="true" :title="$t('targets.agent_wants_to_run')">    
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
        <div v-if="tc.name === REQUEST_PORT_ACCESS_TOOL_NAME" class="column gap-low interrupt-fields">
          <div class="row interrupt-field">
            <span class="interrupt-field-label">{{ $t("targets.request_port_access_port") }}</span>
            <span class="interrupt-field-value">{{ portAccessArgs(tc.args).port }}</span>
          </div>
          <div class="row interrupt-field">
            <span class="interrupt-field-label">{{ $t("targets.request_port_access_protocol") }}</span>
            <span class="interrupt-field-value">{{ portAccessArgs(tc.args).protocol }}</span>
          </div>
          <div class="row interrupt-field">
            <span class="interrupt-field-label">{{ $t("targets.request_port_access_reason") }}</span>
            <span class="interrupt-field-value">{{ portAccessArgs(tc.args).reason }}</span>
          </div>
        </div>
        <div v-else class="interrupt-command">
          {{ toolCallCommand(tc.args) }}
        </div>
      </div>
    </div>
    <div class="row flex-center gap-high" style="padding-inline: 10px; margin-top: 16px">
      <button
        class="button border interrupt-action-button"
        style="flex-grow: 1"
        @click="respondToInterrupt(true)"
      >
        <span>{{ $t("universal.yes") }}</span>
      </button>
      <button
        class="button border interrupt-action-button"
        style="flex-grow: 1"
        @click="respondToInterrupt(false)"
      >
        <span>{{ $t("universal.no") }}</span>
      </button>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import {
  getTargetAgentRun,
  getProjectKaliStatus,
  startAgent,
  pauseAgent,
  finishAgent,
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

const HOLD_DURATION_MS = 3000;
// A normal click's mousedown->mouseup is a lot shorter than this, but not
// instant - without a grace period, EVERY click (even a fast one) flashed
// the ring/stop-icon into view for a frame before reverting, which reads
// as "clicking starts the hold procedure" even though it still correctly
// falls back to pausing. Only an actually-sustained press reveals the
// hold visual; the 3s finish timer itself is unaffected by this delay.
const HOLD_REVEAL_DELAY_MS = 150;
const HOLD_RING_RADIUS = 17;
const HOLD_RING_CIRCUMFERENCE = 2 * Math.PI * HOLD_RING_RADIUS;

const isHolding = ref(false);
const holdProgress = ref(0);
// Set only when the 3s hold actually completes - consumed once by
// handleClick to suppress the native click that still fires on mouseup
// after a long hold (click only needs mousedown+mouseup on the same
// element, regardless of how long between them).
const longPressTriggered = ref(false);

let holdStartTime: number | null = null;
let holdRevealHandle: ReturnType<typeof setTimeout> | null = null;
let holdTimeoutHandle: ReturnType<typeof setTimeout> | null = null;
let holdRafHandle: number | null = null;

const holdDashOffset = computed(
  () => HOLD_RING_CIRCUMFERENCE * (1 - holdProgress.value),
);

// Hold-to-finish is offered from both "running" (click pauses) and
// "paused" (click resumes) - a fresh/never-started/finished/failed run has
// nothing meaningful to finish, and "interrupted" is excluded because
// stop_event has no effect on a run parked awaiting interrupt approval
// (see AgentService.finish_agent's docstring on the backend).
function canHold(status: string | undefined): boolean {
  return status === "running" || status === "paused";
}

const holdTooltipMessage = computed(() =>
  run.value?.status === "paused"
    ? $t("targets.hold_to_finish_tooltip_paused")
    : $t("targets.hold_to_finish_tooltip"),
);

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

// Matches backend's agent_tools.REQUEST_PORT_ACCESS_TOOL_NAME - this tool's
// args (port/protocol/reason) get their own labeled-field rendering in the
// interrupt dialog instead of the generic JSON fallback above, since an
// operator approving a real scope-widening request needs to read it at a
// glance, not parse a JSON blob.
const REQUEST_PORT_ACCESS_TOOL_NAME = "request_port_access";

function portAccessArgs(args: unknown): { port: string; protocol: string; reason: string } {
  const a = (args ?? {}) as Record<string, unknown>;
  return {
    port: a.port !== undefined ? String(a.port) : "",
    protocol: a.protocol !== undefined ? String(a.protocol) : "",
    reason: a.reason !== undefined ? String(a.reason) : "",
  };
}

async function loadRun() {
  const result = await getTargetAgentRun({
    path: { project_id: props.target.project_id, target_id: props.target.id },
  });
  run.value = result.data ?? null;
}

// Recovers the "container is being built for this target" indicator after
// a page refresh - isBuilding is otherwise only ever set by this session's
// own handleStart() call, so a refresh mid-build previously lost it
// entirely (the only sign anything was happening was Agent Logs' "running"
// state, once the run itself actually started).
async function loadBuildStatus() {
  const result = await getProjectKaliStatus({
    path: { project_id: props.target.project_id },
  });

  if (!result.data?.building) return;
  if (result.data.target_id !== props.target.id) return;

  isBuilding.value = true;
  buildingStage.value = result.data.stage ?? null;
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

async function handleFinish() {
  const result = await finishAgent({
    path: { project_id: props.target.project_id, target_id: props.target.id },
  });

  if (result.error) {
    const detail = (result.error as { detail?: string }).detail;
    toast.error(detail ?? $t("targets.agent_finish_failed"), {
      position: toast.POSITION.TOP_CENTER,
    });
  }
}

function tickHoldProgress() {
  if (!isHolding.value || holdStartTime === null) return;

  const elapsed = performance.now() - holdStartTime;
  holdProgress.value = Math.min(1, elapsed / HOLD_DURATION_MS);

  if (holdProgress.value < 1) {
    holdRafHandle = requestAnimationFrame(tickHoldProgress);
  }
}

function onHoldStart() {
  if (!canHold(run.value?.status)) return;

  // A fresh press always clears any stale flag from a prior incomplete
  // interaction (e.g. a hold whose mouseup landed outside the button, so
  // no click ever consumed it) - otherwise it could leak into and silently
  // swallow the next, unrelated click.
  longPressTriggered.value = false;

  holdStartTime = performance.now();
  holdProgress.value = 0;

  // Revealing the ring/stop-icon is deferred - see HOLD_REVEAL_DELAY_MS.
  // Progress is still measured from the real mousedown time, so once
  // revealed the ring starts already slightly filled rather than jumping
  // from 0, and the 3s finish timer below runs independently of this.
  holdRevealHandle = setTimeout(() => {
    holdRevealHandle = null;
    isHolding.value = true;
    holdRafHandle = requestAnimationFrame(tickHoldProgress);
  }, HOLD_REVEAL_DELAY_MS);

  holdTimeoutHandle = setTimeout(() => {
    holdTimeoutHandle = null;
    if (!canHold(run.value?.status)) {
      onHoldEnd();
      return;
    }

    longPressTriggered.value = true;
    handleFinish();
    onHoldEnd();
  }, HOLD_DURATION_MS);
}

function onHoldEnd() {
  // Idempotent - a timeout-triggered auto-end and a subsequent real
  // mouseup/mouseleave must not double-fire. Deliberately does not touch
  // longPressTriggered, which is only ever set by the timeout above and
  // consumed once by handleClick.
  if (
    holdRevealHandle === null &&
    holdTimeoutHandle === null &&
    holdRafHandle === null &&
    !isHolding.value
  ) {
    return;
  }

  if (holdRevealHandle !== null) {
    clearTimeout(holdRevealHandle);
    holdRevealHandle = null;
  }

  if (holdTimeoutHandle !== null) {
    clearTimeout(holdTimeoutHandle);
    holdTimeoutHandle = null;
  }

  if (holdRafHandle !== null) {
    cancelAnimationFrame(holdRafHandle);
    holdRafHandle = null;
  }

  isHolding.value = false;
  holdProgress.value = 0;
  holdStartTime = null;
}

function onButtonLeave() {
  isHovering.value = false;
  onHoldEnd();
}

function handleClick() {
  if (longPressTriggered.value) {
    longPressTriggered.value = false;
    return;
  }

  if (run.value?.status === "paused") {
    handleStart();
  } else {
    handlePause();
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

// An external event (another tab pausing it, the run finishing/failing,
// duration running out, ...) can change the run's status mid-hold - cancel
// the visual hold immediately rather than leaving a stale filling ring
// that would silently no-op once the 3s timeout re-checks status itself.
watch(
  () => run.value?.status,
  (status) => {
    if (!canHold(status)) onHoldEnd();
  },
);

onMounted(() => {
  loadRun();
  loadBuildStatus();

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
  if (holdRevealHandle) clearTimeout(holdRevealHandle);
  if (holdTimeoutHandle) clearTimeout(holdTimeoutHandle);
  if (holdRafHandle) cancelAnimationFrame(holdRafHandle);
});
</script>

<style scoped lang="css">
.timer-button-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.hold-ring {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 48px;
  height: 48px;
  transform: translate(-50%, -50%) rotate(-90deg);
  pointer-events: none;
}

.hold-ring-track {
  stroke: var(--border-subtle);
}

.hold-ring-fill {
  stroke: var(--red-primary);
}

.timer-button {
  font-family: var(--font-mono);
  font-size: 0.8rem;
}

.timer-button--holding {
  width: 40px;
  height: 40px;
  border-radius: 50%;
}

.building-loader {
  --size: 0.35px;
}

.timer-button--interrupted {
  color: var(--red-light);
}

.interrupt-action-button {
  /* Flatter than the shared .border/.button look elsewhere in the app -
     a plain neutral border/background, no red glow, for this dialog's
     Yes/No buttons specifically. */
  border-color: var(--border-subtle);
  box-shadow: none;
}

.interrupt-action-button:hover {
  box-shadow: none;
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

.interrupt-fields {
  font-size: 0.85rem;
}

.interrupt-field {
  align-items: baseline;
  gap: 8px;
}

.interrupt-field-label {
  flex-shrink: 0;
  min-width: 64px;
  color: var(--text-muted);
}

.interrupt-field-value {
  color: var(--text-white);
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
