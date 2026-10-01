<template>
  <div class="border field">
    <div class="row">
      <span class="text-red" style="padding-left: 10px">{{
        $t("console.user_console")
      }}</span>

      <!-- user radio -->
      <div
        v-if="client_dict[store.openedProject] !== undefined"
        class="radio-group"
        style="margin-left: auto"
      >
        <!-- Root Option -->
        <input
          type="radio"
          id="root"
          value="root"
          v-model="radioUser"
          class="radio-input"
        />
        <label
          for="root"
          class="radio-label"
          style="
            border-right: none;
            border-top: none;
            border-bottom: none;
            padding: 2px 10px;
            font-size: 0.85rem;
          "
          >{{ $t("console.root") }}</label
        >

        <!-- Momos option -->
        <input
          type="radio"
          id="momos"
          value="momos"
          v-model="radioUser"
          class="radio-input"
        />
        <label
          for="momos"
          class="radio-label"
          style="
            border-right: none;
            border-top: none;
            border-bottom: none;
            padding: 2px 10px;
            font-size: 0.85rem;
          "
          >{{ $t("console.momos") }}</label
        >
      </div>
    </div>
    <div class="separator" />
    <div class="column console-body" v-if="client_dict[store.openedProject] !== undefined">
      <div class="terminal-output-screen scrollable-panel" ref="terminalRef">
        <div v-if="!activeSessionName" class="system-message no-session-placeholder">
          {{ $t("console.no_sessions") }}
        </div>

        <div
          v-for="(line, idx) in currentOutput"
          :key="idx"
          class="terminal-line"
        >
          <span v-if="line.type === 'cmd'" class="prompt-prefix output-line"
            >> {{ line.line }}
          </span>
          <span v-if="line.type === 'error'" class="prompt-prefix error-message"
            >X: {{ line.line }}
          </span>
          <span v-if="line.type === 'user'" class="prompt-prefix command-line"
            >[{{ line.user }}]$ {{ line.line }}
          </span>
          <span v-if="line.type === 'system'" class="system-message"
            >{{ line.line }}
          </span>
        </div>
      </div>

      <!-- Session tabs - only the currently selected user's own sessions.
           No close button - hold a tab to close it (same hold-to-confirm
           gesture as AgentRunButton.vue's hold-to-finish), so closing
           works even while that session's own input is disabled waiting
           on a still-running command. -->
      <div class="row session-tabs">
        <Tooltip
          v-for="session in trackSessions"
          :key="session.name"
          :message="$t('console.hold_to_close')"
        >
          <div class="session-tab-wrapper">
            <svg
              v-if="holdingSession === session.name"
              class="hold-ring session-hold-ring"
              viewBox="0 0 40 40"
            >
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
                :stroke-dasharray="SESSION_HOLD_RING_CIRCUMFERENCE"
                :stroke-dashoffset="holdDashOffset"
              />
            </svg>
            <button
              class="button border no-border session-tab-button"
              :class="{
                'is-active': activeSessionName === session.name,
                'session-tab-button--holding': holdingSession === session.name,
              }"
              @mousedown="onSessionHoldStart(session.name)"
              @mouseup="onSessionHoldEnd"
              @mouseleave="onSessionHoldEnd"
              @click="handleSessionTabClick(session.name)"
            >
              {{ sessionLabel(session) }}
            </button>
          </div>
        </Tooltip>

        <Tooltip v-if="atSessionLimit" :message="$t('console.max_sessions_reached')">
          <button class="button border no-border session-tab-add" disabled>+</button>
        </Tooltip>
        <button
          v-else
          class="button border no-border session-tab-add"
          @click="createSession(currentUser)"
        >
          +
        </button>
      </div>

      <!-- Command input field -->
      <div class="row">
        <div class="terminal-input-group" style="flex: 1; margin: 0 5px">
          <input
            v-model="user_command"
            class="input-field"
            :disabled="!activeSessionName || isActiveSessionPending"
            @keydown.enter="sendCommand"
          />
          <!-- Send button - a spinner in place of ">" while this
               session's last command hasn't come back yet, so a second
               Enter/click can't fire a command on top of one still
               running (there's no local queueing - the backend would
               just run them one after another against the SAME shell
               underneath, in whatever order they happened to arrive). -->
          <button
            class="button border send-button"
            :disabled="!activeSessionName || isActiveSessionPending"
            @click="sendCommand"
          >
            <span v-if="isActiveSessionPending" class="loader send-button-loader" />
            <span v-else>&gt;</span>
          </button>
        </div>
      </div>
    </div>
    <div
      class="column full-height"
      v-else-if="loading_dict[store.openedProject] === true"
    >
      <div class="flex flex-center connecting border text-center">
        <span>{{ connectingLabel }}</span> <span class="loader" />
      </div>
    </div>

    <div
      class="column full-height"
      v-else-if="checking_dict[store.openedProject] !== false"
    >
      <div class="flex flex-center connecting border text-center">
        <span>{{ $t("console.checking_session") }}</span>
        <span class="loader" />
      </div>
    </div>

    <div class="column full-height flex-center" v-else>
      <div class="empty-console">
        <span class="material-icons-outlined empty-console-icon">terminal</span>
        <p class="empty-console-text">{{ $t("console.no_active_session") }}</p>
        <button class="button border connect-button" @click="createNewKaliUser">
          {{ $t("console.connect_to_kali") }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useMomosStore } from "@/store/momos_store";
import {
  useWebSocketClient,
  type tCallback,
} from "@/websockets/websocket_client";
import { computed, nextTick, onUnmounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import Tooltip from "../reusable/Tooltip.vue";
import {
  createKaliUser,
  getProjectKaliClient,
  getConsoleSessions,
  type ReceiveCommandOutputMessage,
  type CreatedKaliUserMessage,
  type KaliCreationStageMessage,
  type KaliCreationStage,
  type SendCommandMessage,
  type CreateConsoleSessionMessage,
  type CloseConsoleSessionMessage,
  type ConsoleSessionCreatedMessage,
  type ConsoleSessionClosedMessage,
} from "@/api";

const { t: $t } = useI18n();
const ws_client = useWebSocketClient();
const store = useMomosStore();

// Mirrors backend/src/core/kali_session.py's MAX_SESSIONS_PER_TARGET - the
// console shares the exact same per-namespace cap the agent's own sessions
// use (see kali_user.py's CONSOLE_TARGET_ID), root+momos combined, not 5
// each. Purely a UI convenience (disabling "+" early) - the backend is the
// real enforcement.
const MAX_SESSIONS = 5;

const client_dict = ref<{ [project_id: string]: string }>({});
const loading_dict = ref<{ [project_id: string]: boolean }>({});
const checking_dict = ref<{ [project_id: string]: boolean }>({});
const stage_dict = ref<{ [project_id: string]: KaliCreationStage }>({});

const connectingLabel = computed(() => {
  const stage = stage_dict.value[store.openedProject];
  return stage
    ? $t(`console.stage.${stage}`)
    : $t("console.connecting");
});

type tUser = "root" | "momos";
type tSession = { name: string; user: tUser };

const sessions = ref<{ [project_id: string]: tSession[] }>({});
// Which of root/momos is currently being viewed, per project - defaults to
// root (see selectedUser/currentUser below).
const selectedUser = ref<{ [project_id: string]: tUser }>({});
// The active (visible) session name for EACH user, per project, so
// switching root<->momos comes back to whichever session you were last on
// in that track rather than forgetting it.
const activeSessionByUser = ref<{
  [project_id: string]: { root: string | null; momos: string | null };
}>({});
const user_command = ref<string>("");

// Whether a given session's last SendCommandMessage hasn't gotten its
// matching ReceiveCommandOutputMessage/ConsoleSessionClosedMessage back
// yet - true from the moment sendCommand fires until that reply arrives.
// Per (project, session), not a single global flag, since several
// sessions can each have a command in flight at once and switching tabs
// must not lose track of which ones are actually still busy.
const pendingCommands = ref<{ [project_id: string]: { [session: string]: boolean } }>({});

// Hold-to-close a session tab - same gesture/timing as AgentRunButton.vue's
// hold-to-finish, adapted to a per-tab button instead of one fixed button.
// Deliberately NOT gated on isSessionPending (unlike the command input/
// send button) - this is the only way to close a session whose own
// foreground command is still blocking a read on it, so it must keep
// working exactly when the input doesn't.
const SESSION_HOLD_DURATION_MS = 3000;
const SESSION_HOLD_REVEAL_DELAY_MS = 150;
const SESSION_HOLD_RING_RADIUS = 17;
const SESSION_HOLD_RING_CIRCUMFERENCE = 2 * Math.PI * SESSION_HOLD_RING_RADIUS;

// Only one tab can be held at a time (one mouse) - a single scalar is
// enough, no need for per-session state.
const holdingSession = ref<string | null>(null);
const holdProgress = ref(0);
// Set only when a hold actually completes - consumed once by
// handleSessionTabClick to suppress the native click that still fires on
// mouseup after a long hold.
const sessionLongPressTriggered = ref(false);

let holdStartTime: number | null = null;
let holdRevealHandle: ReturnType<typeof setTimeout> | null = null;
let holdTimeoutHandle: ReturnType<typeof setTimeout> | null = null;
let holdRafHandle: number | null = null;

const holdDashOffset = computed(
  () => SESSION_HOLD_RING_CIRCUMFERENCE * (1 - holdProgress.value),
);

const currentUser = computed<tUser>(
  () => selectedUser.value[store.openedProject] ?? "root",
);

// v-model target for the restored radio-group markup - a plain ref/
// v-model pair (like the original user_picked) doesn't fit anymore since
// "current user" is now derived per-project state, not a single global
// ref, so this bridges the two: reads currentUser, writes through
// selectUser (which also ensures that track has a live session).
const radioUser = computed<tUser>({
  get: () => currentUser.value,
  set: (value) => selectUser(value),
});

const trackSessions = computed(() =>
  (sessions.value[store.openedProject] || []).filter(
    (s) => s.user === currentUser.value,
  ),
);

const activeSessionName = computed(
  () => activeSessionByUser.value[store.openedProject]?.[currentUser.value] ?? null,
);

const atSessionLimit = computed(
  () => (sessions.value[store.openedProject]?.length ?? 0) >= MAX_SESSIONS,
);

function isSessionPending(project_id: string, session: string): boolean {
  return pendingCommands.value[project_id]?.[session] ?? false;
}

function setSessionPending(project_id: string, session: string, pending: boolean) {
  if (!pendingCommands.value[project_id]) pendingCommands.value[project_id] = {};
  pendingCommands.value[project_id][session] = pending;
}

const isActiveSessionPending = computed(() => {
  const session = activeSessionName.value;
  return session ? isSessionPending(store.openedProject, session) : false;
});

const currentOutput = computed(() => {
  const session = activeSessionName.value;
  if (!session) return [];
  return store.cmd_outputs[store.openedProject]?.[session] ?? [];
});

function pointers(project_id: string) {
  if (!activeSessionByUser.value[project_id]) {
    activeSessionByUser.value[project_id] = { root: null, momos: null };
  }
  return activeSessionByUser.value[project_id];
}

function setActiveSession(name: string) {
  pointers(store.openedProject)[currentUser.value] = name;
}

// Backend session names carry a "root-"/"momos-" prefix (kali_user.py's
// create_session) purely to stay unique within the one shared console
// namespace both users' sessions live in - each user's own numbers still
// count from 1 independently. The tab only needs to show the number;
// which user it belongs to is already conveyed by which radio is
// selected.
function sessionLabel(session: tSession): string {
  const prefix = `${session.user}-`;
  return session.name.startsWith(prefix) ? session.name.slice(prefix.length) : session.name;
}

// Ensures the given track has a visible session - if it already has one
// (or one exists but wasn't marked active yet), just points at it;
// otherwise starts a brand new one. This is what makes selecting Root
// always land on a live session, and switching to Momos start one there
// too if it's the first visit.
function ensureTrackSession(project_id: string, user: tUser) {
  const active = pointers(project_id);
  if (active[user] && sessions.value[project_id]?.some((s) => s.name === active[user])) return;

  const existing = (sessions.value[project_id] || []).find((s) => s.user === user);
  if (existing) {
    active[user] = existing.name;
    return;
  }

  if ((sessions.value[project_id]?.length ?? 0) >= MAX_SESSIONS) return;
  createSession(user);
}

function selectUser(user: tUser) {
  const project_id = store.openedProject;
  selectedUser.value[project_id] = user;
  ensureTrackSession(project_id, user);
}

function createSession(user: tUser) {
  const message: CreateConsoleSessionMessage = {
    project_id: store.openedProject,
    type: "CreateConsoleSessionMessage",
    user,
  };
  ws_client.send_message(message);
}

function closeSession(name: string) {
  const message: CloseConsoleSessionMessage = {
    project_id: store.openedProject,
    type: "CloseConsoleSessionMessage",
    session: name,
  };
  ws_client.send_message(message);
}

function tickSessionHoldProgress() {
  if (holdingSession.value === null || holdStartTime === null) return;

  const elapsed = performance.now() - holdStartTime;
  holdProgress.value = Math.min(1, elapsed / SESSION_HOLD_DURATION_MS);

  if (holdProgress.value < 1) {
    holdRafHandle = requestAnimationFrame(tickSessionHoldProgress);
  }
}

function onSessionHoldStart(sessionName: string) {
  sessionLongPressTriggered.value = false;
  holdStartTime = performance.now();
  holdProgress.value = 0;

  // Revealing the ring is deferred - see SESSION_HOLD_REVEAL_DELAY_MS's
  // own comment in AgentRunButton.vue for why (every plain click would
  // otherwise flash it for a frame).
  holdRevealHandle = setTimeout(() => {
    holdRevealHandle = null;
    holdingSession.value = sessionName;
    holdRafHandle = requestAnimationFrame(tickSessionHoldProgress);
  }, SESSION_HOLD_REVEAL_DELAY_MS);

  holdTimeoutHandle = setTimeout(() => {
    holdTimeoutHandle = null;
    sessionLongPressTriggered.value = true;
    closeSession(sessionName);
    onSessionHoldEnd();
  }, SESSION_HOLD_DURATION_MS);
}

function onSessionHoldEnd() {
  if (
    holdRevealHandle === null &&
    holdTimeoutHandle === null &&
    holdRafHandle === null &&
    holdingSession.value === null
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

  holdingSession.value = null;
  holdProgress.value = 0;
  holdStartTime = null;
}

function handleSessionTabClick(sessionName: string) {
  if (sessionLongPressTriggered.value) {
    sessionLongPressTriggered.value = false;
    return;
  }
  setActiveSession(sessionName);
}

function sendCommand() {
  const project_id = store.openedProject;
  const session = activeSessionName.value;
  // The input/button are already disabled while pending - this guards the
  // same case against @keydown.enter firing from a keypress queued just
  // before Vue re-renders that disabled state.
  if (!session || isSessionPending(project_id, session)) return;

  const message: SendCommandMessage = {
    project_id,
    type: "SendCommandMessage",
    command: user_command.value,
    session,
  };

  ws_client.send_message(message);
  store.pushCmdLine(project_id, session, user_command.value, "user", currentUser.value);
  setSessionPending(project_id, session, true);
  user_command.value = "";
}

async function createNewKaliUser() {
  const project_id = store.openedProject;

  loading_dict.value[project_id] = true;
  delete stage_dict.value[project_id];

  const result = await createKaliUser({ path: { project_id } });

  if (!result.data) {
    console.error("Did not retrieve user_id");
    return;
  }

  // it only returns client_id, client is being initiated - socket will tell when it's done
}

const onKaliCreated: tCallback = (message) => {
  message = message as CreatedKaliUserMessage;
  const project_id = message.project_id;

  delete stage_dict.value[project_id];

  if (message.error) {
    console.error(message.error.message);
    toast.error(message.error.message ?? $t("console.connect_failed"), {
      position: toast.POSITION.TOP_CENTER,
    });
    loading_dict.value[project_id] = false;
    return;
  }

  client_dict.value[project_id] = message.client_id;
  loading_dict.value[project_id] = false;
  check_sessions(project_id);
};

const onKaliCreationStage: tCallback = (message) => {
  message = message as KaliCreationStageMessage;

  if (message.error) return;

  stage_dict.value[message.project_id] = message.stage;
};

const onConsoleOutput: tCallback = (message) => {
  message = message as ReceiveCommandOutputMessage;
  const project_id = message.project_id;

  setSessionPending(project_id, message.session, false);

  // A still-blocking foreground command (e.g. a `nc` listener) can get
  // its session force-closed - see kali_manager.py's _close_session -
  // while its own run_in_session call is still out there; that call's
  // eventual (error) result can then land here AFTER
  // ConsoleSessionClosedMessage already removed the tab. Nothing left to
  // show it on - drop it rather than reviving a dead session's output
  // list for a tab that's already gone.
  if (!(sessions.value[project_id] || []).some((s) => s.name === message.session)) {
    return;
  }

  if (message.error && message.error.message) {
    console.error(message.error.message);
    store.pushCmdLine(project_id, message.session, message.error.message, "error");
    return;
  }

  store.pushCmdLine(project_id, message.session, message.output, "cmd");
};

const onSessionCreated: tCallback = (message) => {
  message = message as ConsoleSessionCreatedMessage;
  const project_id = message.project_id;

  if (message.error) {
    toast.error(message.error.message ?? $t("console.connect_failed"), {
      position: toast.POSITION.TOP_CENTER,
    });
    return;
  }

  if (!sessions.value[project_id]) sessions.value[project_id] = [];
  sessions.value[project_id].push({ name: message.session, user: message.user });
  pointers(project_id)[message.user] = message.session;
  store.pushCmdLine(
    project_id,
    message.session,
    $t("console.session_initialized", { user: message.user }),
    "system",
  );
};

const onSessionClosed: tCallback = (message) => {
  message = message as ConsoleSessionClosedMessage;
  const project_id = message.project_id;

  const closed = (sessions.value[project_id] || []).find(
    (s) => s.name === message.session,
  );
  sessions.value[project_id] = (sessions.value[project_id] || []).filter(
    (s) => s.name !== message.session,
  );
  store.clearCmdLines(project_id, message.session);
  if (pendingCommands.value[project_id]) {
    delete pendingCommands.value[project_id][message.session];
  }

  if (closed && pointers(project_id)[closed.user] === message.session) {
    const remaining = sessions.value[project_id].find((s) => s.user === closed.user);
    pointers(project_id)[closed.user] = remaining?.name ?? null;
  }
};

// Hook callbacks are fresh closures every time this component's <script
// setup> runs (i.e. every mount) - without capturing and removing them on
// unmount, ws_client's hook_exists (a reference-equality check) never
// matches a previous mount's closure, so remounting stacks additional
// handlers that each independently re-append the same message, producing
// duplicate console output until the next full page reload.
const hook_handles: Array<{ delete: () => void } | undefined> = [];

const add_hooks = (project_id: string) => {
  if (!ws_client.hook_exists("CreatedKaliUserMessage", onKaliCreated))
    hook_handles.push(ws_client.add_hook("CreatedKaliUserMessage", onKaliCreated));

  if (!ws_client.hook_exists("KaliCreationStage", onKaliCreationStage))
    hook_handles.push(ws_client.add_hook("KaliCreationStage", onKaliCreationStage));

  if (!ws_client.hook_exists("ReceiveCommandOutputMessage", onConsoleOutput))
    hook_handles.push(ws_client.add_hook("ReceiveCommandOutputMessage", onConsoleOutput));

  if (!ws_client.hook_exists("ConsoleSessionCreatedMessage", onSessionCreated))
    hook_handles.push(ws_client.add_hook("ConsoleSessionCreatedMessage", onSessionCreated));

  if (!ws_client.hook_exists("ConsoleSessionClosedMessage", onSessionClosed))
    hook_handles.push(ws_client.add_hook("ConsoleSessionClosedMessage", onSessionClosed));
};

onUnmounted(() => {
  hook_handles.forEach((handle) => handle?.delete());

  if (holdRevealHandle !== null) clearTimeout(holdRevealHandle);
  if (holdTimeoutHandle !== null) clearTimeout(holdTimeoutHandle);
  if (holdRafHandle !== null) cancelAnimationFrame(holdRafHandle);
});

function set_ws(project_id: string) {
  add_hooks(project_id);
}

async function check_client(project_id: string) {
  checking_dict.value[project_id] = true;

  try {
    const result = await getProjectKaliClient({ path: { project_id } });

    if (result.response?.status === 404) {
      return;
    }

    if (result.data) {
      if (result.data.pending) {
        loading_dict.value[project_id] = true;
        return;
      }

      client_dict.value[project_id] = result.data.client_id;
      // Mirrors onKaliCreated's own post-confirmation check_sessions call -
      // without this, a project whose client this call JUST confirmed
      // (rather than one already cached) would only ever get the plain
      // session LISTING below, never the auto-create step check_sessions
      // itself gates on client_dict being set.
      check_sessions(project_id);
    }
  } finally {
    checking_dict.value[project_id] = false;
  }
}

async function check_sessions(project_id: string) {
  const result = await getConsoleSessions({ path: { project_id } });
  const found = result.data ?? [];
  sessions.value[project_id] = found;

  const active = pointers(project_id);
  for (const user of ["root", "momos"] as const) {
    const stillExists = active[user] && found.some((s) => s.name === active[user]);
    active[user] = stillExists ? active[user] : (found.find((s) => s.user === user)?.name ?? null);
  }

  if (!selectedUser.value[project_id]) selectedUser.value[project_id] = "root";
  // Auto-creating a session sends CreateConsoleSessionMessage, which only
  // reaches a hook if this project already has a confirmed active client -
  // check_sessions can run before that's known (e.g. right at mount, in
  // parallel with check_client's own REST call), and firing a create
  // request at that point would match no hook and be silently dropped.
  if (client_dict.value[project_id] !== undefined) {
    ensureTrackSession(project_id, selectedUser.value[project_id]);
  }
}

watch(
  () => store.openedProject,
  (newProject, oldProject) => {
    if (newProject !== oldProject) {
      user_command.value = "";
      set_ws(newProject);

      if (!client_dict.value[newProject]) {
        check_client(newProject);
      }
      check_sessions(newProject);
    }
  },
);

// Mirrors deleteProject's own cmd_outputs cleanup (momos_store.ts) for the
// per-project state that lives in this component instead of the store -
// without this, sessions/selectedUser/activeSessionByUser/pendingCommands
// would each keep a stale entry for the life of the page past a deleted
// project.
watch(
  () => store.projects.map((project) => project.id),
  (newIds, oldIds) => {
    const stillPresent = new Set(newIds);
    for (const id of oldIds ?? []) {
      if (stillPresent.has(id)) continue;
      delete sessions.value[id];
      delete selectedUser.value[id];
      delete activeSessionByUser.value[id];
      delete pendingCommands.value[id];
    }
  },
);

const terminalRef = ref<HTMLElement | null>(null);

// Watch for changes in the command outputs to trigger auto-scroll
watch(
  () => currentOutput.value,
  async () => {
    await nextTick();
    if (terminalRef.value) {
      terminalRef.value.scrollTop = terminalRef.value.scrollHeight;
    }
  },
  { deep: true },
);

set_ws(store.openedProject);
check_client(store.openedProject);
check_sessions(store.openedProject);
</script>

<style scoped lang="css">
.loader {
  margin: 10px;
}

.connecting {
  margin-top: auto;
  margin-bottom: 10px;
  width: 90%;

  align-self: center;
}

.empty-console {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-md);
}

.empty-console-icon {
  font-size: 40px;
  color: var(--text-gray-darker);
}

.empty-console-text {
  margin: 0;
  color: var(--text-gray-dark);
}

.connect-button {
  padding: var(--spacing-sm) var(--spacing-xl);
  font-size: 1rem;
}

.console-body {
  /* UserConsole's root gets a scoped "field" class from Overview.vue
     (fallthrough onto the root element - <UserConsole class="field" />),
     making the WHOLE card `flex: 1; min-height: 0` inside an 82vh-capped
     row. This wrapper needs the same treatment, or its children's total
     height (header/separator/terminal/tabs/input) can exceed what the
     card actually has room for and spill out past the card's own border
     instead of the terminal area giving up space for it - confirmed
     happening for real once the session-tabs row was added on top of the
     original fixed-height layout. */
  flex: 1;
  min-height: 0;
}

.terminal-output-screen {
  display: flex;
  flex-direction: column;
  /*justify-content: flex-end;*/

  width: 100%;
  box-sizing: border-box;
  background-color: var(--black);
  border-bottom: 2px solid var(--border-primary);

  font-family: monospace;
  font-size: 0.9rem;
  color: var(--text-white);

  padding: 10px var(--spacing-md) var(--spacing-md) var(--spacing-md);

  /* Was a fixed 30vh - the one flexible/shrinkable region in this card
     now, so the tabs row above doesn't have to steal space from
     something else or overflow the card - everything but this is fixed-
     size chrome (header, separator, tabs, input), this is what actually
     gives. scrollable-panel (already applied) provides the overflow-y
     that makes shrinking safe instead of just clipping content. */
  flex: 1;
  min-height: 0;
}

.system-message {
  color: var(--text-gray-dark);
  margin-bottom: var(--spacing-sm);
  font-style: italic;
}

.no-session-placeholder {
  /* Only meaningful for the lone "no sessions yet" placeholder - pushes
     it toward the bottom of the (otherwise empty) terminal panel, same
     as the input row below it. Not shared with the inline per-session
     "Session initialized..." line (also .system-message), which sits
     among ordinary terminal-line rows and must flow normally there. */
  margin-top: auto;
}

.error-message {
  color: var(--status-critical);
}

.command-line {
  color: var(--red-light);
  font-weight: bold;
}

.output-line {
  color: var(--text-gray-light);
}

.terminal-line {
  margin-bottom: 4px;
  white-space: pre-wrap;
  overflow-wrap: break-word;
}

.send-button {
  aspect-ratio: 1;
  width: 5%;

  font-size: x-large;
  margin: 5px;
}

.send-button-loader {
  /* Overrides .loader's own --size (meant for the full-panel "connecting"
     state above) down to fit inside this small, already-tiny button -
     and drops its 10px margin, which would otherwise push the button's
     own box out past its "aspect-ratio: 1" square. */
  --size: 0.2px;
  margin: 0;
}

.input-field {
  width: 100%;
}

.session-tabs {
  /* Same 5px inset as .terminal-input-group's own left margin below, so
     the tabs and the input field start at the exact same x position. */
  padding: 0 5px;
  flex-wrap: wrap;
}

.session-tab-button {
  padding: 2px 10px;
  min-width: 1.75rem;
  font-size: 0.85rem;
}

.session-tab-button.is-active {
  background-color: var(--active-bg);
  color: var(--text-white);
}

.session-tab-add {
  padding: 2px 10px;
  min-width: 1.75rem;
  font-size: 0.85rem;
}

.session-tab-add:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.session-tab-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

/* Same technique as AgentRunButton.vue's .hold-ring/.hold-ring-track/
   .hold-ring-fill (stroke-dasharray/dashoffset), scaled down to surround
   this component's smaller, pill-shaped tab button instead of a circular
   one. */
.session-hold-ring {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 44px;
  height: 44px;
  transform: translate(-50%, -50%) rotate(-90deg);
  pointer-events: none;
}

.session-hold-ring .hold-ring-track {
  stroke: var(--border-subtle);
}

.session-hold-ring .hold-ring-fill {
  stroke: var(--red-primary);
}

.session-tab-button--holding {
  color: var(--red-light);
}
</style>
