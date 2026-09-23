<template>
  <div class="main-page gap-low">
    <ProjectBar class="project-bar"/>
    <div class="row gap-low" v-if="store.getProjects.length > 0">
      <ToolsBar class="tool-bar" v-model="currentTool" />
      <ContextView class="context-view" :title="currentToolLabel">
        <Overview v-if="currentTool == TOOLS_KEYS.OVERVIEW" />
        <Vulnerabilities v-if="currentTool == TOOLS_KEYS.VULNERABILITIES" />
        <ProjectSettingsPage v-if="currentTool == TOOLS_KEYS.PROJECT_CONFIGURATION" />
      </ContextView>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useMomosStore } from "@/store/momos_store.ts";
import ContextView from "./MainPage/ContextView.vue";
import ProjectBar from "./MainPage/ProjectBar.vue";
import ToolsBar from "./MainPage/ToolsBar.vue";
import Overview from "./OverviewPage/Overview.vue";
import { tools, TOOLS_KEYS } from "./tools.ts";
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import ProjectSettingsPage from "./ProjectSettingsPage/ProjectSettingsPage.vue";
import Vulnerabilities from "./Vulnerabilities/Vulnerabilities.vue";

const store = useMomosStore()
const { t: $t } = useI18n();

onMounted(async () => {
  try{
    await store.reloadProjects();
    await store.loadQueue();
  } catch (err){
    console.log("Something went wrong when reloading projects or queue:", err)
  }
})

const currentTool = ref<string>(tools[0] !== undefined ? tools[0].key : '');

const currentToolLabel = computed(() => {
  const tool = tools.find((t) => t.key === currentTool.value);
  return tool ? $t(tool.name) : $t("context_window.context_window");
});
</script>

<style lang="css">
.project-bar {
  margin-bottom: 5px;
}

.main-page {
  width: auto;
  display: flex;
  flex-direction: column;
}

.tool-bar {
  width: 15%;
}

.context-view {
  width: 85%;
}
</style>
