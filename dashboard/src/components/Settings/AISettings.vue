<template>
  <div class="full-width">
    <!-- Searchable -->
    <div>
      <input class="input-field border" />
    </div>
    <div class="scrollable-panel" style="max-height: 75vh">
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
            @deleted="refreshInstalledModels"
          />
        </div>
      </div>
      <!-- Suggestions -->
      <div>
        <!-- Recommended -->
        <div class="separator" />
        <div class="row full-width">
          <!-- Agent -->
          <div class="family-section full-width">
            <div class="family-name border-right">Recommended agent models</div>
            <div class="separator" />
            <div
              class="suggestions-list border-right"
              style="padding-right: 10px"
            >
              <AIBox
                v-for="model in getRecommendedAgentModels().sort(
                  (a, b) => a.parameters_size_b - b.parameters_size_b,
                )"
                :key="model.name"
                :model="model"
                :installed="isInstalled(model.name)"
                @download-finished="refreshInstalledModels"
              />
            </div>
          </div>
          <!-- Parsing -->
          <div class="family-section full-width" style="padding-left: 10px;">
            <div class="family-name">
              Recommended parsing models
            </div>
            <div class="separator" />
            <div class="suggestions-list">
              <AIBox
                v-for="model in getRecommendedParsingModels().sort(
                  (a, b) => a.parameters_size_b - b.parameters_size_b,
                )"
                :key="model.name"
                :model="model"
                :installed="isInstalled(model.name)"
                @download-finished="refreshInstalledModels"
              />
            </div>
          </div>
        </div>
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
              :installed="isInstalled(model.name)"
              @download-finished="refreshInstalledModels"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue";
import { aiModelsManager } from "../tools";
import AIBox from "./AIBox.vue";

const installed_models = aiModelsManager.installed_models;

async function refreshInstalledModels() {
  await aiModelsManager.refreshInstalledModels();
}

function getRecommendedAgentModels() {
  return aiModelsManager.getRecommendedAgentModels();
}

function getRecommendedParsingModels() {
  return aiModelsManager.getRecommendedParsingModels();
}

function getModelsByFamily() {
  return aiModelsManager.getModelsByFamily();
}

function isInstalled(modelName: string): boolean {
  return aiModelsManager.isInstalled(modelName);
}

onMounted(async () => {
  await aiModelsManager.initialize();
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
