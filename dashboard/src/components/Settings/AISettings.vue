<template>
  <div class="full-width">
    <!-- Searchable -->
    <div>
      <input class="input-field border" />
    </div>
    <div class="scrollable-panel" style="max-height: 75vh;">
      <!-- Installed -->
      <div v-if="installed_models.length > 0">
        <div class="family-name">Installed</div>
        <div class="separator" />
        <div class="suggestions-list">
          <AIBox
            v-for="model in installed_models"
            :key="model.name"
            :model="model"
            :installed="true"
          />
        </div>
      </div>
      <!-- Suggestions -->
      <div>
        <div
          v-for="(models, family) in getModelsByFamily()"
          :key="family"
          class="family-section"
        >
          <div class="separator" />
          <div class="family-name">{{ family }}</div>
          <div class="separator" />
          <div class="suggestions-list">
            <AIBox
              v-for="model in models.sort(
                (a, b) => a.parameters_size_b - b.parameters_size_b,
              )"
              :key="model.name"
              :model="model"
              :installed="false"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  downloadOllamaModel,
  getDownloadableModels,
  getModelsList,
  type OllamaModelData,
} from "@/api";
import { onMounted, ref } from "vue";
import AIBox from "./AIBox.vue";

const downloadable_models = ref<OllamaModelData[]>([]);
const installed_models = ref<OllamaModelData[]>([]);

function installModel(name: string) {
  const result = downloadOllamaModel({ body: { model_name: name } });
}

function getModelsByFamily(): Record<string, OllamaModelData[]> {
  const result: Record<string, OllamaModelData[]> = {};
  downloadable_models.value.forEach((m) => {
    if (result[m.family] === undefined) {
      result[m.family] = [];
    }

    result[m.family]?.push(m);
  });

  return result;
}

async function getInstalledModels(): Promise<OllamaModelData[]> {
  const result = await getModelsList();

  if (result.error) {
    console.error(result.error);
    return [];
  }

  if (result.data === undefined) {
    console.error("Function getModelsList returned empty without server error");
    return [];
  }

  return result.data.models;
}

onMounted(async () => {
  // Get downloadable models
  const result = await getDownloadableModels();
  if (result.error) {
    console.error(result.error);
    return;
  }

  if (result.data === undefined) {
    console.error(
      "Function getDownloadableModels returned empty without server error",
    );
    return;
  }

  downloadable_models.value = result.data.models;

  // Get installed models
  installed_models.value = await getInstalledModels();
});
</script>

<style lang="css" scoped>
.separator {
  margin-bottom: 5px;
  margin-top: 5px;
}

.family-section {
  margin-bottom: 12px;
}

.family-name {
  margin-top: 4px;
  margin-bottom: 4px;
  font-weight: 600;
}

.suggestions-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
</style>
