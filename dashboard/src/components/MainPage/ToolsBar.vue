<template>
  <div class="tools-box border column" style="padding: 0; width: 15vw">
    <div class="header-text">{{ $t("tools.tools") }}</div>

    <div class="separator" />

    <div class="column full" style="margin-top: 5px">
      <button
        class="button no-border"
        :class="{ 'is-active': toolKey === t.key }"
        v-for="t in tools"
        style="justify-content: start; padding-left: 20px"
        @click="selectTool(t.key)"
      >
        <span class="settings-text">{{ $t(t.name) }}</span>
      </button>
    </div>

    <!-- User settings and stuff -->
    <div style="margin-top: auto">      
      <div v-if="store.download_queue.length > 0" style="margin: 5px">
        <div class="separator" />
        <!-- Queue status -->
        <div class="column">
          <!-- Updated row: Shows Model Name and the current Status text -->
          <div
            class="row"
            style="
              justify-content: space-between;
              align-items: center;
              margin: 5px;
            "
          >
            <span class="text-bold">{{
              getFirstInDownloadQueue()?.model_name
            }}</span>
            <span
              style="font-size: 0.9em; opacity: 0.8; text-transform: capitalize"
            >
              {{ getFirstInDownloadQueue()?.status }}
            </span>
          </div>

          <div class="row" style="justify-content: end">
            <span>
              {{ getDownloadTimeStats().elapsed }}/{{
                getDownloadTimeStats().total
              }}
            </span>
          </div>

          <div class="row gap-low" style="align-items: center">
            <progress
              :value="getFirstInDownloadQueue()?.last_progress?.completed ?? 0"
              :max="getFirstInDownloadQueue()?.last_progress?.total ?? 0"
            />
            <!-- Note: Ollama usually returns 'success' when finished, adding it alongside 'done' just in case -->
            <span
              v-if="
                getFirstInDownloadQueue()?.status !== 'done' &&
                getFirstInDownloadQueue()?.status !== 'success'
              "
            >
              {{
                toGBHelper(
                  getFirstInDownloadQueue()?.last_progress?.completed ?? 0,
                )
              }}/{{
                toGBHelper(
                  getFirstInDownloadQueue()?.last_progress?.total ?? 0,
                )
              }}GB
            </span>
            <span v-else class="text-active material-icons-outlined"
              >task_alt</span
            >
          </div>
        </div>
      </div>
      <!-- Project Config summary -->
      <div class="separator" />

      <span class="text-gray config-summary-label">{{
        $t("tools.config_summary")
      }}</span>

      <div class="row gap-low options">
        <span>{{ $t("models.base_model") }}:</span>
        <span
          class="text-bold truncate-text model-value"
          :title="project_settings?.base_model_name ?? undefined"
          >{{
            project_settings?.base_model_name || $t("models.none_selected")
          }}</span
        >
      </div>

      <div class="row gap-low options">
        <span>{{ $t("models.parsing_model") }}:</span>
        <span
          class="text-bold truncate-text model-value"
          :title="project_settings?.parsing_model_name ?? undefined"
          >{{
            project_settings?.parsing_model_name || $t("models.none_selected")
          }}</span
        >
      </div>

      <div class="row gap-low options">
        <span>{{ $t("tools.kali_instance") }}:</span>
        <span class="text-bold model-value" :class="kaliStatusClass">{{
          kaliStatusText
        }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { tools } from "../tools";
import { useMomosStore } from "@/store/momos_store.ts";
import { useI18n } from "vue-i18n";
import {
  getProjectKaliStatus,
  getProjectSettings,
  type KaliContainerActiveMessage,
  type KaliCreationStageMessage,
} from "@/api";
import { useWebSocketClient, type tCallback } from "@/websockets/websocket_client";

const store = useMomosStore();
const { t: $t } = useI18n();
const ws_client = useWebSocketClient();

const toolKey = defineModel<string>();

function getFirstInDownloadQueue() {
  if (store.download_queue.length === 0) return null;
  return store.download_queue[0];
}

function toGBHelper(bytes: number) {
  const toGB = 1024 ** 3;

  return (bytes / toGB).toFixed(1);
}

function calculateEstimatedDownloadTime(
  time_start: number,
  time_now: number,
  completed: number,
  total_number: number,
) {
  if (completed === 0 || completed >= total_number) {
    return 0;
  }

  const elapsed_time = time_now - time_start;

  // Prevent division by zero
  if (elapsed_time <= 0) {
    return 0;
  }

  // Calculate speed (bytes per millisecond)
  const speed = completed / elapsed_time;

  // Calculate remaining bytes
  const remaining_bytes = total_number - completed;

  // Calculate remaining time in milliseconds
  const remaining_time_ms = remaining_bytes / speed;

  return Math.max(0, Math.round(remaining_time_ms));
}

function formatMsToHoursMinutes(ms: number): string {
  const pad = (n: number) => n.toString().padStart(2, "0");

  if (!ms || ms <= 0) {
    return $t("time.hours_minutes", { hours: 0, minutes: "00" });
  }

  const total_seconds = Math.floor(ms / 1000);
  const total_minutes = Math.floor(total_seconds / 60);

  // If it's less than a minute, show seconds so it doesn't look stuck at 0h 00m
  if (total_minutes === 0) {
    return `${total_seconds}s`;
  }

  const hours = Math.floor(total_minutes / 60);
  const minutes = total_minutes % 60;

  return $t("time.hours_minutes", {
    hours: hours,
    minutes: pad(minutes),
  });
}

function getDownloadTimeStats() {
  const q = getFirstInDownloadQueue();

  if (
    !q ||
    q.last_progress?.completed == null ||
    q.last_progress?.total == null
  ) {
    const zeroTime = formatMsToHoursMinutes(0);
    return { elapsed: zeroTime, total: zeroTime, remaining: zeroTime };
  }

  const time_now = q.last_update_time || Date.now();
  const elapsed_ms = Math.max(0, time_now - q.download_start);

  const remaining_ms = calculateEstimatedDownloadTime(
    q.download_start,
    time_now,
    q.last_progress.completed,
    q.last_progress.total,
  );

  const total_estimated_ms = elapsed_ms + remaining_ms;

  return {
    elapsed: formatMsToHoursMinutes(elapsed_ms),
    total: formatMsToHoursMinutes(total_estimated_ms),
    remaining: formatMsToHoursMinutes(remaining_ms),
  };
}

const selectTool = (key: string) => {
  toolKey.value = key;
};

// Read from the shared store instead of a private local copy, so a save
// made elsewhere (ProjectSettingsPage.vue) is reflected here immediately -
// loadProjectSettings below still fetches once per project to prime the
// store the first time this project's settings are seen.
const project_settings = computed(() =>
  store.getProjectSettings(store.openedProject),
);
const kaliStatus = ref<"active" | "pending" | "inactive">("inactive");

const kaliStatusText = computed(() => {
  if (kaliStatus.value === "active") return $t("tools.active");
  if (kaliStatus.value === "pending") return $t("tools.connecting");
  return $t("tools.inactive");
});

const kaliStatusClass = computed(() => {
  if (kaliStatus.value === "active") return "text-active";
  if (kaliStatus.value === "pending") return "text-gray";
  return "text-inactive";
});

async function loadProjectSettings(project_id: string) {
  if (!project_id) return;

  const result = await getProjectSettings({ path: { project_id } });
  if (result.data) store.setProjectSettings(project_id, result.data);
}

async function loadKaliStatus(project_id: string) {
  if (!project_id) {
    kaliStatus.value = "inactive";
    return;
  }

  const result = await getProjectKaliStatus({ path: { project_id } });

  if (!result.data) {
    kaliStatus.value = "inactive";
    return;
  }

  kaliStatus.value = result.data.building
    ? "pending"
    : result.data.active
      ? "active"
      : "inactive";
}

// Reflects the container-level KaliRegistry (via KaliContainerActive/
// KaliCreationStage), not just the client/session-level concept
// CreatedKaliUserMessage tracks - so this stays accurate whether the
// container was started by an explicit console connect or by an agent run.
const onKaliContainerActive: tCallback = (message) => {
  const active = message as KaliContainerActiveMessage;

  if (active.error || active.project_id !== store.openedProject) return;

  kaliStatus.value = "active";
};

const onKaliCreationStage: tCallback = (message) => {
  const stageMessage = message as KaliCreationStageMessage;

  if (stageMessage.error || stageMessage.project_id !== store.openedProject) return;

  kaliStatus.value = "pending";
};

onMounted(() => {
  loadProjectSettings(store.openedProject);
  loadKaliStatus(store.openedProject);

  if (!ws_client.hook_exists("KaliContainerActive", onKaliContainerActive))
    ws_client.add_hook("KaliContainerActive", onKaliContainerActive);

  if (!ws_client.hook_exists("KaliCreationStage", onKaliCreationStage))
    ws_client.add_hook("KaliCreationStage", onKaliCreationStage);
});

watch(
  () => store.openedProject,
  (newProject) => {
    loadProjectSettings(newProject);
    loadKaliStatus(newProject);
  },
);
</script>

<style scoped lang="css">
.tools-box{
  height: 86vh;
}

.options {
  margin: 10px;
}

.model-value {
  flex: 1;
  min-width: 0;
  text-align: right;
}

.config-summary-label {
  margin: 10px 10px 0;
  font-size: 0.8rem;
  text-transform: uppercase;
}
</style>
