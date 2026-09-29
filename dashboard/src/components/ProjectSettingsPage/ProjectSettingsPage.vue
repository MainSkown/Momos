<template>
  <div
    v-if="project_settings !== null"
    class="settings-wrapper column gap-low full-width"
  >
    <div class="row settings-columns full-width gap-mid">
      <div class="settings-left column gap-low">
        <div class="field-group">
          <label class="text-bold">{{ $t("settings.should_interrupt") }}</label>
          <div class="row gap-low flex-center">
            <input
              v-model="project_settings.should_interrupt"
              class="checkbox-input"
              type="checkbox"
            />
            <span class="text-gray">{{ $t("settings.enable_interruption") }}</span>
          </div>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.choose_tools") }}</label>
          <button
            type="button"
            class="button border full-width model-select-button"
            :disabled="isScanRunning"
            @click="showToolsDialog = true"
          >
            {{ $t("settings.choose_tools") }}
          </button>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("models.base_model") }}</label>
          <button
            type="button"
            class="button border full-width model-select-button"
            :disabled="isScanRunning"
            @click="showBaseModelDialog = true"
          >
            {{ project_settings.base_model_name || $t("models.select_model") }}
          </button>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.max_context_window") }}</label>
          <input
            v-model="maxContextWindowInput"
            @blur="handleMaxContextWindowBlur"
            type="number"
            min="1"
            inputmode="numeric"
            :placeholder="$t('settings.max_context_window_placeholder')"
            class="input-field border full-width"
            :disabled="isScanRunning"
          />
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("models.parsing_model") }}</label>
          <button
            type="button"
            class="button border full-width model-select-button"
            :disabled="isScanRunning"
            @click="showParsingModelDialog = true"
          >
            {{ project_settings.parsing_model_name || $t("models.select_model") }}
          </button>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.allow_shell") }}</label>
          <div class="row gap-low flex-center">
            <Tooltip :message="$t('settings.allow_shell_tooltip')">
              <input
                v-model="project_settings.allow_shell"
                class="checkbox-input"
                type="checkbox"
                @change="onAllowShellChanged"
              />
            </Tooltip>
            <span class="text-gray">{{ $t("settings.enable_allow_shell") }}</span>
          </div>
        </div>

        <div class="field-group">
          <label class="text-bold">{{ $t("settings.allow_install_packages") }}</label>
          <div class="row gap-low flex-center">
            <input
              v-model="project_settings.allow_install_packages"
              class="checkbox-input"
              type="checkbox"
              :disabled="!project_settings.allow_shell"
            />
            <span class="text-gray">{{ $t("settings.enable_allow_install_packages") }}</span>
          </div>
        </div>

        <div class="column gap-low full-width">
          <button
            @click="showDeleteDialog = true"
            class="button border delete-button full-width"
            :disabled="isDeleting"
          >
            {{ isDeleting ? $t("project.deleting") : $t("project.delete") }}
          </button>

          <button
            @click="update_settings"
            class="button border save-button full-width"
            :disabled="isSaving"
          >
            {{ isSaving ? $t("project.saving") : $t("project.save_settings") }}
          </button>
        </div>
      </div>

      <div class="settings-right column gap-low">
        <label class="text-bold">{{ $t("settings.starting_prompt") }}</label>

        <MdEditor
          v-model="project_settings.starting_prompt"
          language="en-US"
          :toolbars-exclude="['github']"
          theme="dark"
        />

        <div class="prompt-legend">
          <span class="text-bold">{{ $t("settings.available_placeholders") }}</span>
          <div class="legend-list">
            <div
              v-for="item in promptPlaceholders"
              :key="item.placeholder"
              class="legend-item"
            >
              <code class="legend-placeholder">{{ item.placeholder }}</code>
              <span class="text-gray">{{ item.description }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row full-width save-row"></div>
  </div>

  <Dialog
    v-model:visible="showDeleteDialog"
    :title="$t('project.delete')"
    :no-close-button="true"
  >
    <span class="text-center flex-center" style="margin-bottom: 20px"
      >{{ $t("project.delete_confirm") }}</span
    >
    <div class="row flex-center gap-high" style="padding-inline: 10px">
      <button
        class="button border"
        style="flex-grow: 1"
        @click="confirmDeleteProject"
      >
        <span>{{ $t("universal.yes") }}</span>
      </button>
      <button
        class="button border"
        style="flex-grow: 1"
        @click="showDeleteDialog = false"
      >
        <span>{{ $t("universal.no") }}</span>
      </button>
    </div>
  </Dialog>

  <ModelPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showBaseModelDialog"
    :title="$t('models.select_base_model')"
    :selected-model-name="project_settings.base_model_name"
    @select="onBaseModelSelected"
  />

  <ModelPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showParsingModelDialog"
    :title="$t('models.select_parsing_model')"
    :selected-model-name="project_settings.parsing_model_name"
    @select="onParsingModelSelected"
  />

  <ToolsPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showToolsDialog"
    v-model:enabled-tools="project_settings.enabled_tools"
  />
</template>

<script setup lang="ts">
import { getProjectSettings, updateProjectSettings } from "@/api";
import { computed, onMounted, ref, watch } from "vue";
import { type OllamaModelData, type ProjectSettings } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import "@/assets/md-editor.css";

import { MdEditor } from "md-editor-v3";
import Dialog from "@/components/reusable/Dialog.vue";
import Tooltip from "@/components/reusable/Tooltip.vue";
import ModelPickerDialog from "./ModelPickerDialog.vue";
import ToolsPickerDialog from "./ToolsPickerDialog.vue";

const store = useMomosStore();
const { t } = useI18n();
const project_settings = ref<ProjectSettings | null>(null);
const isSaving = ref(false);
const isDeleting = ref(false);
const showDeleteDialog = ref(false);
const showBaseModelDialog = ref(false);
const showParsingModelDialog = ref(false);
const showToolsDialog = ref(false);
const maxContextWindowInput = ref<string>("");

// Mirrors TargetSettingsDialog.vue's durationInput/handleDurationBlur idea
// for a nullable numeric field - a plain v-model.number on max_context_window
// directly can't distinguish "cleared" from "0", so it's tracked as its own
// string ref and reconciled on blur instead. project_settings itself
// reloads in place (this page isn't remounted per project - see
// load_settings/the openedProject watcher below), so this needs its own
// watcher to re-sync whenever a different project's settings load in.
watch(
  () => project_settings.value?.max_context_window,
  (value) => {
    maxContextWindowInput.value = value != null ? String(value) : "";
  },
  { immediate: true },
);

function handleMaxContextWindowBlur() {
  if (project_settings.value === null) return;

  const trimmed = maxContextWindowInput.value.trim();
  if (!trimmed) {
    project_settings.value.max_context_window = null;
    return;
  }

  const parsed = Number(trimmed);
  if (Number.isFinite(parsed) && parsed > 0) {
    project_settings.value.max_context_window = Math.floor(parsed);
  }

  // Re-format the field from the canonical value - clears out anything
  // that didn't parse (e.g. a negative number/garbage) back to whatever
  // was last actually saved to project_settings.
  maxContextWindowInput.value =
    project_settings.value.max_context_window != null
      ? String(project_settings.value.max_context_window)
      : "";
}

const isScanRunning = computed(
  () => store.getRunningTarget(store.openedProject) !== null,
);

const promptPlaceholders = [
  { placeholder: "{{name}}", description: t("project.placeholder_name") },
  { placeholder: "{{description}}", description: t("project.placeholder_description") },
  { placeholder: "{{ipv4}}", description: t("project.placeholder_ipv4") },
  { placeholder: "{{ipv6}}", description: t("project.placeholder_ipv6") },
  { placeholder: "{{ports}}", description: t("project.placeholder_ports") },
];

async function load_settings(projectID: string) {
  if (projectID.length === 0) {
    project_settings.value = null;
    return;
  }

  const result = await getProjectSettings({
    path: { project_id: projectID },
  });

  if (result.error) {
    console.error("Failed to fetch settings:", result.error);
    project_settings.value = null;
    return;
  }

  project_settings.value = result.data;
  if (result.data) store.setProjectSettings(projectID, result.data);
}

async function update_settings() {
  if (project_settings.value !== null) {
    isSaving.value = true;

    try {
      const result = await updateProjectSettings({
        body: project_settings.value,
        path: { project_id: store.openedProject },
      });

      if (result.error) {
        console.error("Failed to update settings:", result.error);
        toast.error(t("notify.project_settings_save_failed"));
        return;
      }

      toast.success(t("notify.project_settings_saved"));
      store.setProjectSettings(store.openedProject, project_settings.value);
    } finally {
      isSaving.value = false;
    }
  }
}

function onBaseModelSelected(model: OllamaModelData) {
  if (project_settings.value !== null) {
    project_settings.value.base_model_name = model.name;
  }
}

function onParsingModelSelected(model: OllamaModelData) {
  if (project_settings.value !== null) {
    project_settings.value.parsing_model_name = model.name;
  }
}

// Mirrors the backend's own rule (project_router.py's update_project_settings):
// allow_install_packages only makes sense with allow_shell also on - there'd
// be nothing to do with a newly installed package without shell access to
// it. Uncheck it here too so a save never fails on the resulting 400.
function onAllowShellChanged() {
  if (project_settings.value !== null && !project_settings.value.allow_shell) {
    project_settings.value.allow_install_packages = false;
  }
}

async function confirmDeleteProject() {
  isDeleting.value = true;

  try {
    await store.deleteProject(store.openedProject);
    showDeleteDialog.value = false;
    toast.success(t("notify.project_deleted"));
    await load_settings(store.openedProject);
  } catch (error) {
    console.error("Failed to delete project:", error);
    toast.error(t("notify.project_delete_failed"));
  } finally {
    isDeleting.value = false;
  }
}

onMounted(async () => {
  await load_settings(store.openedProject);
  store.loadRunningTarget(store.openedProject);
});

watch(
  () => store.openedProject,
  async (projectID) => {
    await load_settings(projectID);
    store.loadRunningTarget(projectID);
  },
);
</script>

<style scoped>
.settings-wrapper {
  width: 98.5%;
  height: 82vh;
  padding: 1rem;
  box-sizing: border-box;
  overflow-y: auto;
}

.settings-columns {
  display: flex;
  flex-direction: row;
  align-items: flex-start;
  justify-content: space-between;
}

.settings-left {
  flex: 0 0 14%;
  min-width: 220px;
}

.settings-right {
  flex: 1 1 86%;
  min-width: 0;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.save-row {
  justify-content: flex-end;
}

.save-button {
  padding: 0.6rem 1.2rem;
  min-width: 180px;
}

.delete-button {
  padding: 0.6rem 1.2rem;
  min-width: 180px;
}

.save-button:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.delete-button:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.model-select-button {
  justify-content: flex-start;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  /* A bare <button> gets the browser's own UA padding instead of
     .input-field's explicit --spacing-sm/--spacing-md - without this,
     every button in .settings-left renders shorter than the inputs next
     to it. */
  padding: var(--spacing-sm) var(--spacing-md);
}

/* Chrome/Safari/Edge's number-input step arrows - not useful for a value
   like context window nobody increments one at a time, and removing them
   avoids the extra width they'd otherwise reserve next to max-context's
   input-field. */
.settings-left input[type="number"]::-webkit-outer-spin-button,
.settings-left input[type="number"]::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}

.settings-left input[type="number"] {
  -moz-appearance: textfield;
}

.prompt-legend {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.legend-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem 1.2rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
}

.legend-placeholder {
  padding: 2px 6px;
  border: 1px solid var(--border-primary);
  border-radius: 4px;
  font-size: 0.8rem;
  white-space: nowrap;
}
</style>
