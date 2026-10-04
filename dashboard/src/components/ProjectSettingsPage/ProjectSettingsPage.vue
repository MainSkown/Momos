<template>
  <Teleport v-if="project_settings !== null" to="#context-header-extra">
    <span class="save-status-text" :class="saveStatusClass">{{ saveStatusText }}</span>
  </Teleport>

  <div
    v-if="project_settings !== null"
    class="settings-wrapper column gap-low full-width scrollable-panel"
  >
    <div class="settings-left column gap-mid full-width">
      <div class="row gap-mid settings-cards-row">
        <div class="column gap-mid settings-column-left">
          <div class="border settings-card column">
            <span class="text-red settings-card-title">{{ $t("settings.section_pipeline") }}</span>
            <div class="separator" />

            <div class="column gap-low settings-card-body">
              <div class="field-group">
                <label class="text-bold">{{ $t("settings.pipeline_mode") }}</label>
                <div class="radio-group full-width pipeline-mode-group">
                  <input
                    id="pipeline-mode-multi"
                    type="radio"
                    value="multi_agent"
                    v-model="project_settings.pipeline_mode"
                    class="radio-input"
                    :disabled="isScanRunning"
                  />
                  <label for="pipeline-mode-multi" class="radio-label">
                    {{ $t("settings.pipeline_mode_multi_agent") }}
                  </label>

                  <input
                    id="pipeline-mode-single"
                    type="radio"
                    value="single_agent"
                    v-model="project_settings.pipeline_mode"
                    class="radio-input"
                    :disabled="isScanRunning"
                  />
                  <label for="pipeline-mode-single" class="radio-label">
                    {{ $t("settings.pipeline_mode_single_agent") }}
                  </label>
                </div>
              </div>
            </div>
          </div>

          <div class="border settings-card column">
            <span class="text-red settings-card-title">{{ $t("settings.section_behavior") }}</span>
            <div class="separator" />

            <div class="column gap-low settings-card-body">
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
            </div>
          </div>

          <div class="border-red settings-card column">
            <span class="text-red settings-card-title">{{ $t("settings.section_danger_zone") }}</span>
            <div class="separator" />

            <div class="column gap-low settings-card-body">
              <button
                @click="showDeleteDialog = true"
                class="button border delete-button full-width"
                :disabled="isDeleting"
              >
                {{ isDeleting ? $t("project.deleting") : $t("project.delete") }}
              </button>
            </div>
          </div>
        </div>

        <div class="column gap-mid settings-column-right">
          <div class="border settings-card column">
            <span class="text-red settings-card-title">{{ $t("settings.section_models") }}</span>
            <div class="separator" />

            <div class="models-grid settings-card-body">
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

              <div v-if="isMultiAgent" class="field-group">
                <label class="text-bold">{{ $t("settings.max_concurrent_agents") }}</label>
                <input
                  v-model.number="project_settings.max_concurrent_agents"
                  type="number"
                  min="1"
                  inputmode="numeric"
                  class="input-field border full-width"
                  :disabled="isScanRunning"
                />
              </div>

              <template v-if="isMultiAgent">
                <div class="separator models-grid-full-row" />

                <div class="field-group">
                  <label class="text-bold">{{ $t("models.orchestrator_model") }}</label>
                  <div class="row gap-low">
                    <button
                      type="button"
                      class="button border full-width model-select-button"
                      :disabled="isScanRunning"
                      @click="showOrchestratorModelDialog = true"
                    >
                      {{ roleModelButtonLabel(project_settings.orchestrator_model_name) }}
                    </button>
                    <button
                      v-if="project_settings.orchestrator_model_name"
                      type="button"
                      class="button border"
                      :disabled="isScanRunning"
                      :title="$t('models.use_base_model')"
                      @click="project_settings.orchestrator_model_name = ''"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div class="field-group">
                  <label class="text-bold">{{ $t("models.scouting_model") }}</label>
                  <div class="row gap-low">
                    <button
                      type="button"
                      class="button border full-width model-select-button"
                      :disabled="isScanRunning"
                      @click="showScoutingModelDialog = true"
                    >
                      {{ roleModelButtonLabel(project_settings.scouting_model_name) }}
                    </button>
                    <button
                      v-if="project_settings.scouting_model_name"
                      type="button"
                      class="button border"
                      :disabled="isScanRunning"
                      :title="$t('models.use_base_model')"
                      @click="project_settings.scouting_model_name = ''"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div class="field-group">
                  <label class="text-bold">{{ $t("models.pentesting_model") }}</label>
                  <div class="row gap-low">
                    <button
                      type="button"
                      class="button border full-width model-select-button"
                      :disabled="isScanRunning"
                      @click="showPentestingModelDialog = true"
                    >
                      {{ roleModelButtonLabel(project_settings.pentesting_model_name) }}
                    </button>
                    <button
                      v-if="project_settings.pentesting_model_name"
                      type="button"
                      class="button border"
                      :disabled="isScanRunning"
                      :title="$t('models.use_base_model')"
                      @click="project_settings.pentesting_model_name = ''"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div class="field-group">
                  <label class="text-bold">{{ $t("models.reporting_model") }}</label>
                  <div class="row gap-low">
                    <button
                      type="button"
                      class="button border full-width model-select-button"
                      :disabled="isScanRunning"
                      @click="showReportingModelDialog = true"
                    >
                      {{ roleModelButtonLabel(project_settings.reporting_model_name) }}
                    </button>
                    <button
                      v-if="project_settings.reporting_model_name"
                      type="button"
                      class="button border"
                      :disabled="isScanRunning"
                      :title="$t('models.use_base_model')"
                      @click="project_settings.reporting_model_name = ''"
                    >
                      ✕
                    </button>
                  </div>
                </div>

              </template>

              <button
                type="button"
                class="button border full-width models-grid-full-row"
                @click="showPromptDialog = true"
              >
                {{ $t("settings.edit_prompt") }}
              </button>
            </div>
          </div>
        </div>
      </div>

    </div>
  </div>

  <Dialog
    v-if="project_settings !== null"
    v-model:visible="showPromptDialog"
    :title="promptDialogTitle"
  >
    <div class="column gap-low prompt-dialog-body scrollable-panel">
      <div v-if="!isMultiAgent" class="column gap-low">
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

      <div v-else class="column gap-low">
        <div class="radio-group full-width prompt-tabs-group">
          <template v-for="tab in promptTabs" :key="tab.id">
            <input
              :id="'prompt-tab-' + tab.id"
              type="radio"
              :value="tab.id"
              v-model="activePromptTab"
              class="radio-input"
            />
            <label :for="'prompt-tab-' + tab.id" class="radio-label">
              {{ tab.label }}
            </label>
          </template>
        </div>

        <MdEditor
          v-model="activePromptText"
          language="en-US"
          :toolbars-exclude="['github']"
          theme="dark"
        />

        <div class="prompt-legend">
          <span class="text-bold">{{ $t("settings.available_placeholders") }}</span>
          <div class="legend-list">
            <div
              v-for="item in activePromptPlaceholders"
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
  </Dialog>

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

  <ModelPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showOrchestratorModelDialog"
    :title="$t('models.select_orchestrator_model')"
    :selected-model-name="project_settings.orchestrator_model_name"
    @select="onOrchestratorModelSelected"
  />

  <ModelPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showScoutingModelDialog"
    :title="$t('models.select_scouting_model')"
    :selected-model-name="project_settings.scouting_model_name"
    @select="onScoutingModelSelected"
  />

  <ModelPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showPentestingModelDialog"
    :title="$t('models.select_pentesting_model')"
    :selected-model-name="project_settings.pentesting_model_name"
    @select="onPentestingModelSelected"
  />

  <ModelPickerDialog
    v-if="project_settings !== null"
    v-model:visible="showReportingModelDialog"
    :title="$t('models.select_reporting_model')"
    :selected-model-name="project_settings.reporting_model_name"
    @select="onReportingModelSelected"
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
const saveStatus = ref<"saved" | "saving" | "error">("saved");
const isDeleting = ref(false);
const showDeleteDialog = ref(false);
const showBaseModelDialog = ref(false);
const showParsingModelDialog = ref(false);
const showOrchestratorModelDialog = ref(false);
const showScoutingModelDialog = ref(false);
const showPentestingModelDialog = ref(false);
const showReportingModelDialog = ref(false);
const showToolsDialog = ref(false);
const showPromptDialog = ref(false);
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

const AUTOSAVE_DEBOUNCE_MS = 800;
let autosaveTimer: ReturnType<typeof setTimeout> | null = null;
// Set right before load_settings() assigns a freshly-fetched object into
// project_settings - without this, the deep watch below would see that
// assignment as "the user changed something" and immediately queue a
// redundant save of the exact same data that was just loaded.
let suppressNextAutosave = false;

watch(
  project_settings,
  () => {
    if (suppressNextAutosave) {
      suppressNextAutosave = false;
      return;
    }
    if (project_settings.value === null) return;

    // Captured now, not read inside the timeout - if the user switches
    // projects while this is still pending (store.openedProject changes,
    // project_settings gets reloaded into a new object for it),
    // the closure below must still keep targeting THIS project/object,
    // not whatever becomes current by the time the timer actually fires.
    const projectID = store.openedProject;
    const settingsSnapshot = project_settings.value;

    if (autosaveTimer) clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(() => {
      autosaveTimer = null;
      saveSettings(projectID, settingsSnapshot);
    }, AUTOSAVE_DEBOUNCE_MS);
  },
  { deep: true },
);

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

const isMultiAgent = computed(
  () => project_settings.value?.pipeline_mode === "multi_agent",
);

const promptDialogTitle = computed(() =>
  isMultiAgent.value ? t("settings.pipeline_prompts_title") : t("settings.starting_prompt"),
);

// A role's own model field is empty by design when it should fall back to
// base_model_name at run time (see agent_tools.build_*_agent_tools on the
// backend) - the button says so explicitly rather than looking the same
// as an unset base model.
function roleModelButtonLabel(roleModelName: string | null | undefined): string {
  if (roleModelName) return roleModelName;
  const base = project_settings.value?.base_model_name;
  return base ? t("models.using_base_model", { model: base }) : t("models.select_model");
}

type PromptTabId = "orchestrator" | "scouting" | "pentesting" | "reporting";
const activePromptTab = ref<PromptTabId>("orchestrator");
const promptTabs: { id: PromptTabId; label: string }[] = [
  { id: "orchestrator", label: t("settings.orchestrator_prompt_tab") },
  { id: "scouting", label: t("settings.scouting_prompt_tab") },
  { id: "pentesting", label: t("settings.pentesting_prompt_tab") },
  { id: "reporting", label: t("settings.reporting_prompt_tab") },
];

// One MdEditor instance shared across all 4 role prompts (rather than 4
// mounted editors, 3 of them always hidden) - this computed proxies
// through to whichever field activePromptTab currently points at.
const activePromptText = computed<string>({
  get() {
    if (project_settings.value === null) return "";
    switch (activePromptTab.value) {
      case "orchestrator":
        return project_settings.value.orchestrator_starting_prompt ?? "";
      case "scouting":
        return project_settings.value.scouting_starting_prompt ?? "";
      case "pentesting":
        return project_settings.value.pentesting_starting_prompt ?? "";
      case "reporting":
        return project_settings.value.reporting_starting_prompt ?? "";
    }
  },
  set(value) {
    if (project_settings.value === null) return;
    switch (activePromptTab.value) {
      case "orchestrator":
        project_settings.value.orchestrator_starting_prompt = value;
        break;
      case "scouting":
        project_settings.value.scouting_starting_prompt = value;
        break;
      case "pentesting":
        project_settings.value.pentesting_starting_prompt = value;
        break;
      case "reporting":
        project_settings.value.reporting_starting_prompt = value;
        break;
    }
  },
});

const promptPlaceholders = [
  { placeholder: "{{name}}", description: t("project.placeholder_name") },
  { placeholder: "{{description}}", description: t("project.placeholder_description") },
  { placeholder: "{{ipv4}}", description: t("project.placeholder_ipv4") },
  { placeholder: "{{ipv6}}", description: t("project.placeholder_ipv6") },
  { placeholder: "{{ports}}", description: t("project.placeholder_ports") },
];

// pentesting_starting_prompt is the only role template that also supports
// {{attack_vector}} (the assigned vector's description) - see
// pentesting_starting_prompt in the backend's project_scheme.py.
const activePromptPlaceholders = computed(() =>
  activePromptTab.value === "pentesting"
    ? [
        ...promptPlaceholders,
        { placeholder: "{{attack_vector}}", description: t("project.placeholder_attack_vector") },
      ]
    : promptPlaceholders,
);

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

  suppressNextAutosave = true;
  project_settings.value = result.data;
  if (result.data) store.setProjectSettings(projectID, result.data);
}

// Autosave only (see the deep watch above) - no manual Save button, so
// this is never called directly from the template. Status is reported
// inline via saveStatus/saveStatusText (teleported into the page title
// row - see the template) rather than a toast, which would fire on every
// debounced autosave and quickly become noise. Takes projectID/settings
// as explicit args rather than reading store.openedProject/project_settings
// itself - see the watcher above for why (a project switch mid-debounce
// must not retarget an already-scheduled save).
async function saveSettings(projectID: string, settings: ProjectSettings) {
  saveStatus.value = "saving";

  try {
    const result = await updateProjectSettings({
      body: settings,
      path: { project_id: projectID },
    });

    if (result.error) {
      console.error("Failed to update settings:", result.error);
      saveStatus.value = "error";
      return;
    }

    saveStatus.value = "saved";
    store.setProjectSettings(projectID, settings);
  } catch (error) {
    console.error("Failed to update settings:", error);
    saveStatus.value = "error";
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

function onOrchestratorModelSelected(model: OllamaModelData) {
  if (project_settings.value !== null) {
    project_settings.value.orchestrator_model_name = model.name;
  }
}

function onScoutingModelSelected(model: OllamaModelData) {
  if (project_settings.value !== null) {
    project_settings.value.scouting_model_name = model.name;
  }
}

function onPentestingModelSelected(model: OllamaModelData) {
  if (project_settings.value !== null) {
    project_settings.value.pentesting_model_name = model.name;
  }
}

function onReportingModelSelected(model: OllamaModelData) {
  if (project_settings.value !== null) {
    project_settings.value.reporting_model_name = model.name;
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

.settings-left {
  max-width: 1100px;
}

/* The prompt editor moved into an on-demand Dialog (see showPromptDialog) -
   not used often enough to justify permanently reserving a whole second
   column for it, so the cards below get to use the freed width instead.
   Pipeline+Behavior stack into one narrower column; Models (the card with
   the most fields, especially in Multi Agent mode) gets its own wider one
   and lays its fields out two-per-row (.models-grid below) - both of
   which keep it from towering over its neighbor instead of just
   stretching something to paper over the difference. */
.settings-cards-row {
  flex-wrap: wrap;
  align-items: flex-start;
}

.settings-column-left {
  flex: 1 1 320px;
}

.settings-column-right {
  flex: 1 1 560px;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

/* Groups related fields into a titled panel - same card chrome
   Overview's own cards use (.border + a .text-red title + .separator),
   reused here instead of inventing a new "settings section" look. */
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

/* Models has by far the most fields (especially in Multi Agent mode) -
   two per row instead of one keeps it growing sideways into the wider
   .settings-column-right rather than stacking tall, matching
   Pipeline+Behavior's combined height on the left instead of dwarfing
   it. */
.models-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md) var(--spacing-lg);
  padding: var(--spacing-md) var(--spacing-md) 0;
}

.models-grid-full-row {
  grid-column: 1 / -1;
}


/* Same sizing ModelPickerDialog.vue's own .model-picker-body uses for its
   big dialog body. */
.prompt-dialog-body {
  width: 85vw;
  max-height: 80vh;
}

.delete-button {
  padding: 0.6rem 1.2rem;
  min-width: 180px;
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

/* Same technique VulnerabilityEditDialog.vue's .severity-group already
   uses to stretch a .radio-group's pills evenly across its container,
   instead of leaving them sized to content with empty space after. */
.prompt-tabs-group .radio-label {
  flex: 1;
}

/* "Multi Agent"/"Single Agent" side by side (the default .radio-group row
   direction) left each pill too narrow and wrapped its label onto two
   lines inside the Pipeline card's own width. Stacked instead, each
   option gets the card's full width. */
.pipeline-mode-group {
  flex-direction: column;
}

.pipeline-mode-group .radio-label {
  width: 100%;
  margin-right: 0;
  margin-bottom: -2px;
}

.pipeline-mode-group .radio-label:last-of-type {
  margin-bottom: 0;
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

/* Teleported into ContextView's title row (#context-header-extra) - see
   the Teleport at the top of this template. Rendered here, not there,
   since this component owns the autosave state it reflects. */
.save-status-text {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  white-space: nowrap;
}
</style>
