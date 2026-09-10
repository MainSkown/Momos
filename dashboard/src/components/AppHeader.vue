<template>
    <div class="main-header row">
      <h2 class="text-red header-text">MOMOS</h2>

      <button
        class="button no-border settings-button"
        @click="showSettings = true"
      >
        <span class="material-icons-outlined">settings</span>
      </button>
    </div>

    <SettingsDialog v-model="showSettings" />
</template>

<script setup lang="ts">
import { ref } from "vue";
import SettingsDialog from "./Settings/SettingsDialog.vue";

const showSettings = ref<boolean>(false);
</script>

<style lang="css">

.main-header {
  width: auto;
  box-sizing: border-box;
  border: 2px solid var(--red-primary);
  background-color: var(--black);
  margin-bottom: 5px;
  justify-content: space-between;
  align-items: center;
}

.main-header .settings-button {
  aspect-ratio: 1;
  margin: 5px;
}
</style>
