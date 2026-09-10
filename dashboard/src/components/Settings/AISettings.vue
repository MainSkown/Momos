<template>
  <div class="full-width">
    <!-- Searchable -->
    <div>
      <input class="input-field border" />
    </div>
    <div class="scrollable-panel" style="max-height: 75vh">
      <!-- Installed -->
      <div v-if="installed_models.length > 0">
        <div class="family-name">{{ $t("models.installed") }}</div>
        <div class="separator" />
        <div class="suggestions-list">
          <AIBox
            v-for="model in installed_models"
            :key="model.name"
            :model="model"
            :installed="true"
            :selected="isSelected(model.name)"
            @deleted="refreshInstalledModels"
            @select="onSelect(model)"
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
            <div class="family-name border-right">{{ $t("models.recommended_agent") }}</div>
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
                :selected="isSelected(model.name)"
                @download-finished="refreshInstalledModels"
                @select="onSelect(model)"
              />
            </div>
          </div>
          <!-- Parsing -->
          <div class="family-section full-width" style="padding-left: 10px;">
            <div class="family-name">
              {{ $t("models.recommended_parsing") }}
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
                :selected="isSelected(model.name)"
                @download-finished="refreshInstalledModels"
                @select="onSelect(model)"
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
              :selected="isSelected(model.name)"
              @download-finished="refreshInstalledModels"
              @select="onSelect(model)"
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
import { type OllamaModelData } from "@/api/types.gen";

const props = withDefaults(
  defineProps<{
    selectable?: boolean;
    selectedModelName?: string | null;
  }>(),
  {
    selectable: false,
    selectedModelName: null,
  },
);

const emits = defineEmits<{
  select: [model: OllamaModelData];
}>();

const installed_models = aiModelsManager.installed_models;

function onSelect(model: OllamaModelData) {
  if (props.selectable) {
    emits("select", model);
  }
}

function isSelected(modelName: string): boolean {
  return props.selectable && props.selectedModelName === modelName;
}

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
