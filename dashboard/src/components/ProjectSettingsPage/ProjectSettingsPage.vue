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

        <button
          @click="update_settings"
          class="button border save-button"
          :disabled="isSaving"
        >
          {{ isSaving ? "Saving..." : "Save Settings" }}
        </button>
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
</template>

<script setup lang="ts">
import { getProjectSettings, updateProjectSettings } from "@/api";
import { onMounted, ref } from "vue";
import { type ProjectSettings } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import "@/assets/md-editor.css";

import { MdEditor } from "md-editor-v3";

const store = useMomosStore();
const project_settings = ref<ProjectSettings | null>(null);
const isSaving = ref(false);

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

onMounted(async () => {
  const result = await getProjectSettings({
    path: { project_id: store.openedProject },
  });

  if (result.error) {
    console.error("Failed to fetch settings:", result.error);
    return;
  }

  project_settings.value = result.data;

  if (project_settings.value.base_model_name.length === 0) {
    project_settings.value.base_model_name = "TODO";
  }

  if (project_settings.value.parsing_model_name.length === 0) {
    project_settings.value.parsing_model_name = "TODO";
  }
});
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

.save-button:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}
</style>
