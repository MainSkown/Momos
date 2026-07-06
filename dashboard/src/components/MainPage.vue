<template>
  <div class="main-page gap-low">
    <ProjectBar class="project-bar"/>
    <div class="row gap-low" v-if="store.getProjects.length > 0">
      <ToolsBar class="tool-bar" v-model="currentTool" />
      <ContextView class="context-view"> 
        <Overview v-if="currentTool == 'overview'" />
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
import { tools } from "./tools.ts";
import { onMounted, ref } from "vue";

const store = useMomosStore()

onMounted(async () => {
  try{
    await store.reloadProjects();
  } catch (err){
    console.log("Something went wrong when reloading projects:", err)
  }
})

const currentTool = ref<string>(tools[0] !== undefined ? tools[0].key : '');
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
