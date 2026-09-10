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
          v-model="user_picked"
          class="radio-input"
        />
        <label
          for="root"
          class="radio-label"
          style="
            border-right: none;
            border-top: none;
            border-bottom: none;
            width: 70px;
          "
          >{{ $t("console.root") }}</label
        >

        <!-- Momos option -->
        <input
          type="radio"
          id="momos"
          value="momos"
          v-model="user_picked"
          class="radio-input"
        />
        <label
          for="momos"
          class="radio-label"
          style="
            border-right: none;
            border-top: none;
            border-bottom: none;
            width: 70px;
          "
          >{{ $t("console.momos") }}</label
        >
      </div>
    </div>
    <div class="separator" />
    <div class="column" v-if="client_dict[store.openedProject] !== undefined">
      <div class="terminal-output-screen scrollable-panel" ref="terminalRef">
        <div class="system-message">
          {{ $t("console.session_initialized") }}
        </div>

        <div
          v-for="(line, idx) in store.cmd_outputs[store.openedProject]"
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
        </div>
      </div>

      <!-- Command input field -->
      <div class="row">
        <div class="terminal-input-group" style="margin: 5px; width: 100%">
          <input
            v-model="user_command"
            class="input-field"
            @keydown.enter="sendCommand"
          />
          <!-- Send button -->
          <button class="button border send-button" @click="sendCommand">
            >
          </button>
        </div>
      </div>
    </div>
    <div
      class="column full-height"
      v-else-if="loading_dict[store.openedProject] === true"
    >
      <div class="flex flex-center connecting border text-center">
        <span>{{ $t("console.connecting") }}</span> <span class="loader" />
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
import { nextTick, ref, watch } from "vue";
import {
  createKaliUser,
  getProjectKaliClient,
  type ReceiveCommandOutputMessage,
  type CreatedKaliUserMessage,
  type SendCommandMessage,
} from "@/api";

const ws_client = useWebSocketClient();
const store = useMomosStore();

const client_dict = ref<{ [project_id: string]: string }>({});
const loading_dict = ref<{ [project_id: string]: boolean }>({});
const checking_dict = ref<{ [project_id: string]: boolean }>({});

const user_picked = ref<"momos" | "root">("root");
const user_command = ref<string>("");

function sendCommand() {
  const message: SendCommandMessage = {
    project_id: store.openedProject,
    type: "SendCommandMessage",
    command: user_command.value,
    user: user_picked.value,
  };

  ws_client.send_message(message);
  store.pushCmdLine(
    store.openedProject,
    user_command.value,
    "user",
    user_picked.value,
  );
  user_command.value = "";
}

async function createNewKaliUser() {
  const project_id = store.openedProject;

  loading_dict.value[project_id] = true;

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

  if (message.error) {
    console.error(message.error.message);
    return;
  }

  client_dict.value[project_id] = message.client_id;
  loading_dict.value[project_id] = false;
};

const onConsoleOutput: tCallback = (message) => {
  message = message as ReceiveCommandOutputMessage;
  const project_id = message.project_id;

  if (message.error && message.error.message) {
    console.error(message.error.message);
    store.pushCmdLine(project_id, message.error.message, "error");
    return;
  }

  store.pushCmdLine(project_id, message.output, "cmd");
};

const add_hooks = (project_id: string) => {
  if (!ws_client.hook_exists("CreatedKaliUserMessage", onKaliCreated))
    ws_client.add_hook("CreatedKaliUserMessage", onKaliCreated);

  if (!ws_client.hook_exists("ReceiveCommandOutputMessage", onConsoleOutput))
    ws_client.add_hook("ReceiveCommandOutputMessage", onConsoleOutput);
};

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
    }
  } finally {
    checking_dict.value[project_id] = false;
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
    }
  },
);

const terminalRef = ref<HTMLElement | null>(null);

// Watch for changes in the command outputs to trigger auto-scroll
watch(
  () => store.cmd_outputs[store.openedProject],
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

.radio-label {
  padding: 0.5px;
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

  height: 240px;
}

.system-message {
  margin-top: auto;
  color: var(--text-gray-dark);
  margin-bottom: var(--spacing-sm);
  font-style: italic;
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

.input-field {
  width: 100%;
}
</style>
