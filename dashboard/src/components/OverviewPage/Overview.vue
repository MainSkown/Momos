<template>
  <div class="column layout-container">
    
    <!-- First row -->
    <!-- Removed full-width because flex layout will handle it cleanly -->
    <div class="row">
      <!-- Targets -->
      <Targets class="field" />      

      <!-- Summary -->
      <div class="border field">
        <span class="text-red" style="padding-left: 10px">{{ $t("overview.summary") }}</span>
        <div class="separator" />
      </div>
    </div>

    <!-- Second row -->
    <div class="row">
      <!-- User Console-->
       <UserConsole class="field"/>
      <!-- Agent Logs -->
      <AgentLogs class="field" />
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import Targets from "./Targets.vue";
import UserConsole from "./UserConsole.vue";
import AgentLogs from "./AgentLogs.vue";

const target = ref<string>();
</script>

<style scoped lang="css">
.layout-container {
  height: calc(100% - 40px); 
  
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
}

.row {
  display: flex;
  justify-content: space-evenly;
  flex: 1; 
  min-height: 0;
}

.field {
  flex: 1;
  margin: 5px;
  min-height: 0; 
  
  display: flex;
  flex-direction: column;
}
</style>