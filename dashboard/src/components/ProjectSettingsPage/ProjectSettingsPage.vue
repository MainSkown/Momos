<template>
  <div
    v-if="project_settings !== null"
    class="settings-wrapper column gap-low full-width"
  >
    <div class="row settings-columns full-width gap-mid">
      <div class="settings-left column gap-low">
        <div class="field-group">
          <label class="text-bold">Should Interrupt</label>
          <div class="row gap-low flex-center">
            <input
              v-model="project_settings.should_interrupt"
              class="checkbox-input"
              type="checkbox"
            />
            <span class="text-gray">Enable interruption handling</span>
          </div>
        </div>

        <div class="field-group">
          <label class="text-bold">Base Model</label>
          <select
            v-model="project_settings.base_model_name"
            class="input-field border full-width"
          >
            <option value="TODO">TODO</option>
          </select>
        </div>

        <div class="field-group">
          <label class="text-bold">Parsing Model</label>
          <select
            v-model="project_settings.parsing_model_name"
            class="input-field border full-width"
          >
            <option value="TODO">TODO</option>
          </select>
        </div>

        <div class="row gap-low action-row">
          <button
            @click="showDeleteDialog = true"
            class="button border delete-button"
            :disabled="isDeleting"
          >
            {{ isDeleting ? "Deleting..." : "Delete Project" }}
          </button>

          <button
            @click="update_settings"
            class="button border save-button"
            :disabled="isSaving"
          >
            {{ isSaving ? "Saving..." : "Save Settings" }}
          </button>
        </div>
      </div>

      <div class="settings-right column gap-low">
        <label class="text-bold">Starting Prompt</label>

        <MdEditor
          v-model="project_settings.starting_prompt"
          language="en-US"
          :toolbars-exclude="['github']"
          theme="dark"
        />
      </div>
    </div>

    <div class="row full-width save-row"></div>
  </div>

  <Dialog
    v-model:visible="showDeleteDialog"
    :title="'Delete Project'"
    :no-close-button="true"
  >
    <span class="text-center flex-center" style="margin-bottom: 20px"
      >Are you sure you want to delete this project?</span
    >
    <div class="row flex-center gap-high" style="padding-inline: 10px">
      <button
        class="button border"
        style="flex-grow: 1"
        @click="confirmDeleteProject"
      >
        <span>Yes</span>
      </button>
      <button
        class="button border"
        style="flex-grow: 1"
        @click="showDeleteDialog = false"
      >
        <span>No</span>
      </button>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { getProjectSettings, updateProjectSettings } from "@/api";
import { onMounted, ref, watch } from "vue";
import { type ProjectSettings } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import "@/assets/md-editor.css";

import { MdEditor } from "md-editor-v3";
import Dialog from "@/components/reusable/Dialog.vue";

const store = useMomosStore();
const project_settings = ref<ProjectSettings | null>(null);
const isSaving = ref(false);
const isDeleting = ref(false);
const showDeleteDialog = ref(false);

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

  if (project_settings.value.base_model_name.length === 0) {
    project_settings.value.base_model_name = "TODO";
  }

  if (project_settings.value.parsing_model_name.length === 0) {
    project_settings.value.parsing_model_name = "TODO";
  }
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

.action-row {
  flex-wrap: wrap;
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
</style>
