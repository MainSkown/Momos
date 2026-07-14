<template>
  <div class="border field">
    <span class="text-red" style="padding-left: 10px">User Console</span>
    <div class="separator" />
    <div v-if="client_dict[store.openedProject] !== undefined">connected</div>
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
import { ref, watch } from "vue";
import { LocalStoreKeys } from "@/types";
import {
  createKaliUser,
  kaliClientExists,
  type ReceiveCommandOutputMessage,
  type CreatedKaliUserMessage,
} from "@/api";

const ws_client = useWebSocketClient();
const store = useMomosStore();

const client_dict = ref<{ [project_id: string]: string }>({});
const loading_dict = ref<{ [project_id: string]: boolean }>({});

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

  if (message.error) {
    console.error(message.error.message);
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

function set_ws(project_id: string){
    add_hooks(project_id);

      if(!ws_client.isSocketActive(project_id) && !ws_client.active_sockets[project_id]){
        ws_client.connect(project_id)
      }
}

async function check_client(project_id: string){
    const client_id = localStorage.getItem(`${LocalStoreKeys.CLIENT_ID}-${project_id}`)

    if(!client_id) return

    const result = await kaliClientExists({path: {client_id:client_id}})

    if(result.response?.status === 404){
        console.info("Could not find client: ", client_id)

        localStorage.removeItem(`${LocalStoreKeys.CLIENT_ID}-${project_id}`)

        return
    } 

    if(result.data){
        if(result.data.pending){
            loading_dict.value[project_id] = true
            return
        }

        client_dict.value[project_id] = result.data.client_id
    }
}

watch(
  () => store.openedProject,
  (newProject, oldProject) => {
    if (newProject !== oldProject) {
      set_ws(newProject)

      if(!client_dict.value[newProject]){
        check_client(newProject)
      }
    }
  },
);

set_ws(store.openedProject)
check_client(store.openedProject)

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
</style>
