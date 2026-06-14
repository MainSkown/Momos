<template>
  <div class="main-page">
    <ProjectBar class="project-bar" v-model="currentProject"/>
    <div class="row gap-low">
      <ToolsBar class="tool-bar" v-model="currentTool" />
      <ContextView class="context-view"> 
        <Overview v-if="currentTool == tools.find(t => t.name == 'Overview')?.id" />
      </ContextView>
    </div>
  </div>
</template>

<script setup lang="ts">
import ContextView from "./MainPage/ContextView.vue";
import ProjectBar from "./MainPage/ProjectBar.vue";
import ToolsBar from "./MainPage/ToolsBar.vue";
import Overview from "./OverviewPage/Overview.vue";
import { tools } from "./tools.ts";
import { ref } from "vue";

const currentProject = ref<string>('123')
const currentTool = ref<number>(tools[0] !== undefined ? tools[0].id : 1);
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
  flex-grow: 1;
}

.context-view {
  flex-grow: 8;
}
</style>
