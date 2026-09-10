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
          <label class="text-bold">{{ $t("models.base_model") }}</label>
          <button
            type="button"
            class="button border full-width model-select-button"
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
            @click="showParsingModelDialog = true"
          >
            {{ project_settings.parsing_model_name || $t("models.select_model") }}
          </button>
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
</template>

<script setup lang="ts">
import { getProjectSettings, updateProjectSettings } from "@/api";
import { onMounted, ref, watch } from "vue";
import { type OllamaModelData, type ProjectSettings } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import { useI18n } from "vue-i18n";
import "@/assets/md-editor.css";

import { MdEditor } from "md-editor-v3";
import Dialog from "@/components/reusable/Dialog.vue";
import ModelPickerDialog from "./ModelPickerDialog.vue";

const store = useMomosStore();
const { t } = useI18n();
const project_settings = ref<ProjectSettings | null>(null);
const isSaving = ref(false);
const isDeleting = ref(false);
const showDeleteDialog = ref(false);
const showBaseModelDialog = ref(false);
const showParsingModelDialog = ref(false);

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
        return;
      }

      console.log("Settings updated successfully");
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

async function confirmDeleteProject() {
  isDeleting.value = true;

  try {
    await store.deleteProject(store.openedProject);
    showDeleteDialog.value = false;
    await load_settings(store.openedProject);
  } catch (error) {
    console.error("Failed to delete project:", error);
  } finally {
    isDeleting.value = false;
  }
}

onMounted(async () => {
  await load_settings(store.openedProject);
});

watch(
  () => store.openedProject,
  async (projectID) => {
    await load_settings(projectID);
  },
);
</script>

<style scoped>
.settings-wrapper {
  width: 98.5%;
  padding: 1rem;
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
