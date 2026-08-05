<template>
  <div class="border column" style="padding: 0; height: 720px">
    <div class="header-text">{{ $t("tools.tools") }}</div>

    <div class="separator" />

    <div class="column full" style="margin-top: 5px">
      <button
        class="button no-border"
        :class="{ 'is-active': toolKey === t.key }"
        v-for="t in tools"
        style="justify-content: start; padding-left: 20px"
        @click="selectTool(t.key)"
      >
        <span class="settings-text">{{ $t(t.name) }}</span>
    </button>
    </div>

    <!-- User settings and stuff -->
    <div style="margin-top: auto">
      <div class="separator" />

      <div class="row flex-center gap-low options">
        <span>Model:</span>
        
        <select v-model="selectedModel" class="input-field full-width">
          <option>ChatGPT</option>
          <option>Gemini</option>
          <option>Big Boy AI</option>
        </select>
      
      </div>

      <div class="row gap-low options">
        <span>Kali Instance:</span>
        <span class="text-inactive text-bold">inactive</span>
      </div>

      <button class="no-border button full-width border-top" @click="showSettings = true">
        <span class="material-icons-outlined"> settings </span>
      </button>
    </div>
  </div>

  <SettingsDialog v-model="showSettings" />
</template>

<script setup lang="ts">
import {ref} from 'vue'
import { tools } from "../tools";
import SettingsDialog from '../Settings/SettingsDialog.vue';

const toolKey = defineModel<string>();

const selectTool = (key: string) => {
  toolKey.value = key;
};

const selectedModel = ref<string>("")
const showSettings = ref<boolean>(false)
</script>

<style scoped lang="css">
.options {
  margin: 10px;
}
</style>
