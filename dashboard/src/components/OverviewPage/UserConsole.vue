<template>
  <div class="border field">
    <div class="row">
      <span class="text-red" style="padding-left: 10px">User Console</span>
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
          >Root</label
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
          >Momos</label
        >
      </div>
    </div>
    <div class="separator" />
    <div class="column" v-if="client_dict[store.openedProject] !== undefined">
      <div class="terminal-output-screen scrollable-panel" ref="terminalRef">
        <div class="system-message">
          Session initialized. Select privileges above.
        </div>

        <div
          v-for="(line, idx) in store.cmd_outputs[store.openedProject]"
          :key="idx"
          class="terminal-line"
        >
          <span class="prompt-prefix">></span> {{ line }}
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
        <span>Connecting to client: </span> <span class="loader" />
      </div>
    </div>

    <div class="column full-height" v-else>
      <button class="connecting button border" @click="createNewKaliUser">
        <h3>Connect to Kali</h3>
      </button>
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
import { LocalStoreKeys } from "@/types";
import {
  createKaliUser,
  kaliClientExists,
  type ReceiveCommandOutputMessage,
  type CreatedKaliUserMessage,
  type SendCommandMessage,
} from "@/api";

const ws_client = useWebSocketClient();
const store = useMomosStore();

const client_dict = ref<{ [project_id: string]: string }>({});
const loading_dict = ref<{ [project_id: string]: boolean }>({});

const user_picked = ref<"momos" | "root">("root");
const user_command = ref<string>("");

function sendCommand() {
  const message: SendCommandMessage = {
    type: "SendCommandMessage",
    command: user_command.value,
    user: user_picked.value,
  };

  ws_client.send_message(store.openedProject, message);
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

  localStorage.setItem(
    `${LocalStoreKeys.CLIENT_ID}-${project_id}`,
    result.data.client_id,
  );
}

const onKaliCreated: tCallback = (project_id, message) => {
  message = message as CreatedKaliUserMessage;

  if (message.error) {
    console.error(message.error.message);
    return;
  }

  client_dict.value[project_id] = message.client_id;
  loading_dict.value[project_id] = false;

  localStorage.setItem(
    `${LocalStoreKeys.CLIENT_ID}-${project_id}`,
    message.client_id,
  );
};

const onConsoleOutput: tCallback = (project_id, message) => {
  message = message as ReceiveCommandOutputMessage;

  if (message.error && message.error.message) {
    console.error(message.error.message);
    store.cmd_outputs[project_id]?.push(message.error.message);
    return;
  }

  if (!store.cmd_outputs[project_id]) store.cmd_outputs[project_id] = [];

  store.cmd_outputs[project_id].push(message.output);
};

const add_hooks = (project_id: string) => {
  if (
    !ws_client.hook_exists(project_id, "CreatedKaliUserMessage", onKaliCreated)
  )
    ws_client.add_hook(project_id, "CreatedKaliUserMessage", onKaliCreated);

  if (
    !ws_client.hook_exists(
      project_id,
      "ReceiveCommandOutputMessage",
      onConsoleOutput,
    )
  )
    ws_client.add_hook(
      project_id,
      "ReceiveCommandOutputMessage",
      onConsoleOutput,
    );
};

function set_ws(project_id: string) {
  add_hooks(project_id);

  if (
    !ws_client.isSocketActive(project_id) &&
    !ws_client.active_sockets[project_id]
  ) {
    ws_client.connect(project_id);
  }
}

async function check_client(project_id: string) {
  const client_id = localStorage.getItem(
    `${LocalStoreKeys.CLIENT_ID}-${project_id}`,
  );

  if (!client_id) return;

  const result = await kaliClientExists({ path: { client_id: client_id } });

  if (result.response?.status === 404) {
    console.info("Could not find client: ", client_id);

    localStorage.removeItem(`${LocalStoreKeys.CLIENT_ID}-${project_id}`);

    return;
  }

  if (result.data) {
    if (result.data.pending) {
      loading_dict.value[project_id] = true;
      return;
    }

    client_dict.value[project_id] = result.data.client_id;
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

.radio-label {
  padding: 0.5px;
}

.terminal-output-screen {
  display: flex;
  flex-direction: column;
  justify-content: flex-end;

  width: 100%;
  box-sizing: border-box;
  background-color: var(--black);
  border-bottom: 2px solid var(--border-primary);

  font-family: monospace;
  font-size: 0.9rem;
  color: var(--text-white);

  padding: 40px var(--spacing-md) var(--spacing-md) var(--spacing-md);

  height: 240px;
}

.system-message {
  color: var(--text-gray-dark);
  margin-bottom: var(--spacing-sm);
  font-style: italic;
}

.terminal-line {
  margin-bottom: 4px;
  word-break: break-all;
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
