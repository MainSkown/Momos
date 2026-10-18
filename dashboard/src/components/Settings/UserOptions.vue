<template>
  <div class="column gap-mid full-width user-options scrollable-panel">
    <span class="save-status-text" :class="saveStatusClass">{{ saveStatusText }}</span>

    <span v-if="loadError" class="text-red">{{ $t("settings.load_error") }}</span>

    <div class="border settings-card column">
      <span class="text-red settings-card-title">{{ $t("settings.section_notifications") }}</span>
      <div class="separator" />

      <div class="column gap-low settings-card-body">
        <div class="field-group">
          <label class="text-bold">{{ $t("settings.notify_agent_finished_label") }}</label>
          <div class="row gap-low checkbox-row">
            <input
              type="checkbox"
              class="checkbox-input"
              :checked="user_settings?.notify_agent_finished ?? false"
              :disabled="controlsDisabled"
              @change="onToggleNotify('notify_agent_finished', $event)"
            />
            <span class="text-gray">{{ $t("settings.notify_agent_finished_desc") }}</span>
          </div>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.notify_vulnerability_found_label") }}</label>
          <div class="row gap-low checkbox-row">
            <input
              type="checkbox"
              class="checkbox-input"
              :checked="user_settings?.notify_vulnerability_found ?? false"
              :disabled="controlsDisabled"
              @change="onToggleNotify('notify_vulnerability_found', $event)"
            />
            <span class="text-gray">{{ $t("settings.notify_vulnerability_found_desc") }}</span>
          </div>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.notify_agent_paused_label") }}</label>
          <div class="row gap-low checkbox-row">
            <input
              type="checkbox"
              class="checkbox-input"
              :checked="user_settings?.notify_agent_paused ?? false"
              :disabled="controlsDisabled"
              @change="onToggleNotify('notify_agent_paused', $event)"
            />
            <span class="text-gray">{{ $t("settings.notify_agent_paused_desc") }}</span>
          </div>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.notify_agent_error_label") }}</label>
          <div class="row gap-low checkbox-row">
            <input
              type="checkbox"
              class="checkbox-input"
              :checked="user_settings?.notify_agent_error ?? false"
              :disabled="controlsDisabled"
              @change="onToggleNotify('notify_agent_error', $event)"
            />
            <span class="text-gray">{{ $t("settings.notify_agent_error_desc") }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="border settings-card column">
      <span class="text-red settings-card-title">{{ $t("settings.section_appearance") }}</span>
      <div class="separator" />

      <div class="row gap-low settings-card-body accent-swatches">
        <button
          v-for="preset in ACCENT_PRESETS"
          :key="preset"
          type="button"
          class="button border accent-swatch"
          :class="{ 'is-active': user_settings?.accent_color === preset }"
          :disabled="controlsDisabled"
          @click="selectAccent(preset)"
        >
          <span class="accent-swatch-dot" :style="{ backgroundColor: ACCENT_HEX[preset] }" />
          <span>{{ $t(`settings.accent_${preset}`) }}</span>
        </button>
      </div>
    </div>

    <div class="border settings-card column">
      <span class="text-red settings-card-title">{{ $t("settings.section_performance") }}</span>
      <div class="separator" />

      <div class="column gap-low settings-card-body">
        <div class="field-group">
          <label class="text-bold">{{ $t("settings.global_max_concurrent_agents_label") }}</label>
          <span class="text-gray">{{ $t("settings.global_max_concurrent_agents_desc") }}</span>
          <input
            v-model.number="capModel"
            type="number"
            min="1"
            inputmode="numeric"
            class="input-field border full-width"
            :disabled="controlsDisabled"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { getUserSettings, updateUserSettings } from "@/api";
import type { UserSettings } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import { requestNotificationPermission } from "@/composables/useNotifications";
import { ACCENT_PRESETS, applyAccent, type AccentPreset } from "@/composables/useAccentTheme";

const store = useMomosStore();
const { t } = useI18n();

const user_settings = ref<UserSettings | null>(null);
const loadError = ref(false);
const saveStatus = ref<"saved" | "saving" | "error">("saved");

// Mirrors useAccentTheme/main.css's own per-preset values (see its
// :root[data-accent="..."] blocks) - a swatch for a preset that ISN'T the
// currently active one must still render in that preset's own color, which
// a CSS variable keyed off the live data-accent attribute can't express.
const ACCENT_HEX: Record<AccentPreset, string> = {
  red: "#dc2626",
  blue: "#2563eb",
  green: "#16a34a",
  purple: "#9333ea",
  orange: "#ea580c",
};

const controlsDisabled = computed(
  () => loadError.value || user_settings.value === null,
);

const capModel = computed<number | undefined>({
  get: () => user_settings.value?.global_max_concurrent_agents,
  set: (value) => {
    if (user_settings.value === null) return;
    user_settings.value.global_max_concurrent_agents = value;
  },
});

type NotifyKey =
  | "notify_agent_finished"
  | "notify_vulnerability_found"
  | "notify_agent_paused"
  | "notify_agent_error";

async function onToggleNotify(key: NotifyKey, event: Event) {
  if (user_settings.value === null) return;
  const checkbox = event.target as HTMLInputElement;
  const turningOn = checkbox.checked;

  if (!turningOn) {
    user_settings.value[key] = false;
    return;
  }

  const result = await requestNotificationPermission();
  if (result === "granted") {
    user_settings.value[key] = true;
    return;
  }

  // The underlying ref was never set to true, so there's nothing to revert
  // there - only the checkbox's own DOM state needs snapping back, since
  // its :checked is bound manually (not via v-model) precisely for this.
  checkbox.checked = false;
  toast.error(
    t(
      result === "unsupported"
        ? "settings.notifications_unsupported"
        : "settings.notifications_denied",
    ),
  );
}

function selectAccent(preset: AccentPreset) {
  if (user_settings.value === null) return;
  user_settings.value.accent_color = preset;
  applyAccent(preset);
}

const AUTOSAVE_DEBOUNCE_MS = 800;
// A singleton pending save, unlike ProjectSettingsPage's per-project Map -
// this component only ever edits one (the current user's) settings object,
// so there's never more than one save in flight to keep separate.
let pendingAutosave: { timer: ReturnType<typeof setTimeout>; settings: UserSettings } | null =
  null;
// Set right before a freshly-loaded (or reverted) object is assigned into
// user_settings - without this the deep watch below would treat that
// assignment as a user edit and queue a redundant/incorrect save.
let suppressNextAutosave = false;
let lastSavedSnapshot: UserSettings | null = null;

watch(
  user_settings,
  () => {
    if (suppressNextAutosave) {
      suppressNextAutosave = false;
      return;
    }
    if (user_settings.value === null) return;

    const settingsSnapshot: UserSettings = { ...user_settings.value };

    if (pendingAutosave) clearTimeout(pendingAutosave.timer);

    const timer = setTimeout(() => {
      pendingAutosave = null;
      saveSettings(settingsSnapshot);
    }, AUTOSAVE_DEBOUNCE_MS);
    pendingAutosave = { timer, settings: settingsSnapshot };
  },
  { deep: true },
);

onUnmounted(() => {
  if (pendingAutosave) {
    clearTimeout(pendingAutosave.timer);
    saveSettings(pendingAutosave.settings);
    pendingAutosave = null;
  }
});

async function saveSettings(settings: UserSettings) {
  saveStatus.value = "saving";

  try {
    const result = await updateUserSettings({ body: settings });

    if (result.error) {
      console.error("Failed to update user settings:", result.error);
      revertToLastSaved();
      return;
    }

    saveStatus.value = "saved";
    lastSavedSnapshot = { ...settings };
    store.setUserSettings(settings);
  } catch (error) {
    console.error("Failed to update user settings:", error);
    revertToLastSaved();
  }
}

function revertToLastSaved() {
  saveStatus.value = "error";
  toast.error(t("settings.autosave_error"));

  if (lastSavedSnapshot !== null) {
    suppressNextAutosave = true;
    user_settings.value = { ...lastSavedSnapshot };
  }
}

const saveStatusText = computed(() => {
  switch (saveStatus.value) {
    case "saving":
      return t("settings.autosave_saving");
    case "error":
      return t("settings.autosave_error");
    default:
      return t("settings.autosave_saved");
  }
});

const saveStatusClass = computed(() =>
  saveStatus.value === "error" ? "text-red" : "text-gray",
);

onMounted(async () => {
  const result = await getUserSettings();

  if (result.error || result.data === undefined) {
    loadError.value = true;
    return;
  }

  store.setUserSettings(result.data);
  lastSavedSnapshot = { ...result.data };
  suppressNextAutosave = true;
  user_settings.value = result.data;
});
</script>

<style scoped lang="css">
/* Same "titled card" chrome as ProjectSettingsPage.vue's own
   .settings-card/.settings-card-title/.settings-card-body/.field-group -
   copied rather than imported across components (they're scoped there). */
.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

/* .flex-center (main.css) also centers its row horizontally, which pushes
   a checkbox away from the left edge instead of just centering it
   vertically against its description text - this keeps the vertical
   centering without the horizontal one. */
.checkbox-row {
  display: flex;
  align-items: center;
}

.settings-card {
  width: 100%;
  padding-bottom: var(--spacing-md);
}

.settings-card-title {
  padding: var(--spacing-sm) var(--spacing-md) 0;
}

.settings-card-body {
  padding: var(--spacing-md) var(--spacing-md) 0;
}

.user-options {
  max-width: 700px;
  max-height: 75vh;
  padding-right: var(--spacing-sm);
}

.save-status-text {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  white-space: nowrap;
}

.accent-swatches {
  flex-wrap: wrap;
}

.accent-swatch {
  flex-direction: column;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
}

/* A sharp (not rounded) square, matching the app's --radius: 0 corners
   elsewhere, rather than the rounded "color dot" convention this UI
   otherwise avoids. */
.accent-swatch-dot {
  width: 1rem;
  height: 1rem;
  border: 1px solid var(--border-primary);
}

.user-options input[type="number"]::-webkit-outer-spin-button,
.user-options input[type="number"]::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}

.user-options input[type="number"] {
  -moz-appearance: textfield;
}
</style>
