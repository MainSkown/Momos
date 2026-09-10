<template>
  <Dialog v-model:visible="show_add_project">
    <template v-slot:title>
      <h3 class="no-margin">{{ $t("project.create_new") }}</h3>
    </template>
    <div class="column project-dialog-body" style="gap: 10px">
      <div class="input-wrapper">
        <label class="floating-label">{{ $t("project.name") }}</label>
        <input
          class="input-field border"
          :placeholder="$t('project.enter_name')"
          v-model="projects_name"
        />
      </div>
      <div class="separator" />
      <!-- Agent models -->
      <span class="text-bold">{{ $t("models.recommended_agent") }}</span>
      <div class="separator" />
      <div class="suggestions-list">
        <div
          v-for="model in getRecommendedAgentModels().sort(
            (a, b) => a.parameters_size_b - b.parameters_size_b,
          )"
          :key="model.name"
          class="model-entry"
        >
          <AIBox
            :model="model"
            :installed="isInstalled(model.name)"
            :selected="selected_agent_model_name === model.name"
            @select="selected_agent_model_name = model.name"
            @download-finished="refreshInstalledModels"
            @deleted="refreshInstalledModels"
          />
        </div>
      </div>
      <button
        v-if="extraInstalledAgentModels.length > 0"
        type="button"
        class="button border expand-installed-button full-width"
        @click="show_installed_agent_models = !show_installed_agent_models"
      >
        <span class="material-icons-outlined">
          {{ show_installed_agent_models ? "expand_less" : "expand_more" }}
        </span>
        <span>{{
          show_installed_agent_models
            ? $t("models.hide_installed")
            : $t("models.show_installed")
        }}</span>
      </button>
      <div v-if="show_installed_agent_models" class="suggestions-list">
        <div
          v-for="model in extraInstalledAgentModels"
          :key="model.name"
          class="model-entry"
        >
          <AIBox
            :model="model"
            :installed="true"
            :selected="selected_agent_model_name === model.name"
            @select="selected_agent_model_name = model.name"
            @download-finished="refreshInstalledModels"
            @deleted="refreshInstalledModels"
          />
        </div>
      </div>
      <!-- Parsing models -->
      <div class="separator" />
      <span class="text-bold">{{ $t("models.recommended_parsing") }}</span>
      <div class="separator" />
      <div class="suggestions-list">
        <div
          v-for="model in getRecommendedParsingModels().sort(
            (a, b) => a.parameters_size_b - b.parameters_size_b,
          )"
          :key="model.name"
          class="model-entry"
        >
          <AIBox
            :model="model"
            :installed="isInstalled(model.name)"
            :selected="selected_parsing_model_name === model.name"
            @select="selected_parsing_model_name = model.name"
            @download-finished="refreshInstalledModels"
            @deleted="refreshInstalledModels"
          />
        </div>
      </div>
      <button
        v-if="extraInstalledParsingModels.length > 0"
        type="button"
        class="button border expand-installed-button full-width"
        @click="show_installed_parsing_models = !show_installed_parsing_models"
      >
        <span class="material-icons-outlined">
          {{ show_installed_parsing_models ? "expand_less" : "expand_more" }}
        </span>
        <span>{{
          show_installed_parsing_models
            ? $t("models.hide_installed")
            : $t("models.show_installed")
        }}</span>
      </button>
      <div v-if="show_installed_parsing_models" class="suggestions-list">
        <div
          v-for="model in extraInstalledParsingModels"
          :key="model.name"
          class="model-entry"
        >
          <AIBox
            :model="model"
            :installed="true"
            :selected="selected_parsing_model_name === model.name"
            @select="selected_parsing_model_name = model.name"
            @download-finished="refreshInstalledModels"
            @deleted="refreshInstalledModels"
          />
        </div>
      </div>
      <button class="button border" :disabled="!canCreateProject" @click="add_Project">
        {{ $t("universal.add") }}
      </button>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import Dialog from "@/components/reusable/Dialog.vue";
import { useMomosStore } from "@/store/momos_store";
import { computed, onMounted, ref } from "vue";
import { toast } from "vue3-toastify";
import { useI18n } from "vue-i18n";
import { aiModelsManager } from "../tools";
import AIBox from "@/components/Settings/AIBox.vue";

const show_add_project = defineModel({ type: Boolean, default: false });

const store = useMomosStore();
const { t } = useI18n();

const projects_name = ref<string>("");
const selected_agent_model_name = ref<string>("");
const selected_parsing_model_name = ref<string>("");
const show_installed_agent_models = ref<boolean>(false);
const show_installed_parsing_models = ref<boolean>(false);

const canCreateProject = computed(() => {
  return (
    projects_name.value.trim().length > 0 &&
    selected_agent_model_name.value.length > 0 &&
    selected_parsing_model_name.value.length > 0 &&
    isInstalled(selected_agent_model_name.value) &&
    isInstalled(selected_parsing_model_name.value)
  );
});

const extraInstalledAgentModels = computed(() => {
  const recommendedNames = new Set(
    getRecommendedAgentModels().map((m) => m.name),
  );
  return aiModelsManager.installed_models.value.filter(
    (m) => !recommendedNames.has(m.name),
  );
});

const extraInstalledParsingModels = computed(() => {
  const recommendedNames = new Set(
    getRecommendedParsingModels().map((m) => m.name),
  );
  return aiModelsManager.installed_models.value.filter(
    (m) => !recommendedNames.has(m.name),
  );
});

function getRecommendedAgentModels() {
  return aiModelsManager.getRecommendedAgentModels();
}

function getRecommendedParsingModels() {
  return aiModelsManager.getRecommendedParsingModels();
}

function isInstalled(modelName: string): boolean {
  return aiModelsManager.isInstalled(modelName);
}

async function refreshInstalledModels() {
  await aiModelsManager.refreshInstalledModels();
}

async function add_Project() {
  if (projects_name.value.trim().length === 0) {
    toast.error(t("notify.name_empty"));
    return;
  }

  if (selected_agent_model_name.value.length === 0) {
    toast.error(t("notify.agent_model_required"));
    return;
  }

  if (selected_parsing_model_name.value.length === 0) {
    toast.error(t("notify.parsing_model_required"));
    return;
  }

  if (!isInstalled(selected_agent_model_name.value)) {
    toast.error(t("notify.agent_model_not_downloaded"));
    return;
  }

  if (!isInstalled(selected_parsing_model_name.value)) {
    toast.error(t("notify.parsing_model_not_downloaded"));
    return;
  }

  try {
    await store.addProject(
      projects_name.value.trim(),
      selected_agent_model_name.value,
      selected_parsing_model_name.value,
    );
  } catch (error) {
    console.error(error);
    toast.error(t("notify.could_not_create_project"));
    return;
  }

  projects_name.value = "";
  selected_agent_model_name.value = "";
  selected_parsing_model_name.value = "";
  show_installed_agent_models.value = false;
  show_installed_parsing_models.value = false;
  show_add_project.value = false;
}

onMounted(async () => {
  await aiModelsManager.initialize();
});
</script>

<style scoped lang="css">
.project-dialog-body {
  max-width: calc(100vw - 120px);
}

.suggestions-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.model-entry {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.expand-installed-button {
  align-self: flex-start;
  display: flex;
  align-items: center;
  gap: 4px;
}
</style>
