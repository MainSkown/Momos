<template>
  <div class="column layout-container">
    
    <!-- First row -->
    <!-- Removed full-width because flex layout will handle it cleanly -->
    <div class="row">
      <!-- Targets -->
      <Targets class="field" />      

      <!-- Summary -->
      <div class="border field">
        <span class="text-red" style="padding-left: 10px">Summary</span>
        <div class="separator" />
      </div>
    </div>

    <!-- Second row -->
    <div class="row">
      <!-- Removed style="height: 100%" because flex: 1 on the parent handles it -->
      <div class="border field">
        <span class="text-red" style="padding-left: 10px;">Agent Info</span>
        <div class="separator" />
        <div></div>
      </div>

      <div class="border field">
        <span class="text-red" style="padding-left: 10px">Agent Logs</span>
        <div class="separator" />
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import Targets from "./Targets.vue";

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