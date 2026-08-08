<template>
  <div class="border column" style="padding: 0; height: 720px; width: 15vw">
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

      <div class="separator" />

      <div class="row flex-center gap-low options">
        <span>Model:</span>

        <select v-model="selectedModel" class="input-field full-width">
          <option>ChatGPT</option>
          <option>Gemini</option>
          <option>Big Boy AI</option>
        </select>
      </div>

      <div class="row gap-low options">
        <span>Kali Instance:</span>
        <span class="text-inactive text-bold">inactive</span>
      </div>

      <button
        class="no-border button full-width border-top"
        @click="showSettings = true"
      >
        <span class="material-icons-outlined"> settings </span>
      </button>
    </div>
  </div>

  <SettingsDialog v-model="showSettings" />
</template>

<script setup lang="ts">
import { ref } from "vue";
import { tools } from "../tools";
import SettingsDialog from "../Settings/SettingsDialog.vue";
import { useMomosStore } from "@/store/momos_store.ts";
import { useI18n } from "vue-i18n";

const store = useMomosStore();
const { t: $t } = useI18n();

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

const selectedModel = ref<string>("");
const showSettings = ref<boolean>(false);
</script>

<style scoped lang="css">
.options {
  margin: 10px;
}
</style>
