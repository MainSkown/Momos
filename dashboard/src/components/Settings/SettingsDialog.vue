<template>
  <Dialog v-model:visible="showSettings" title="Settings">
    <div class="row gap-low settings">
      <!-- Settings Options -->
      <div class="column full border-right">
      <button
        class="button no-border settings-options"
        :class="{ 'is-active': s.key === selectedSettings }"
        v-for="s in user_settings"
        style="justify-content: start; padding-left: 20px; padding-right: 20px;"
        @click="selectedSettings = s.key"
      >
        <span class="settings-text">{{ $t(s.name) }}</span>
    </button>
    </div>
      <!-- Display Options-->
      <div class="column">
        <AISettings v-if="selectedSettings === USER_SETTINGS_KEYS.AI" />
      </div>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import Dialog from "@/components/reusable/Dialog.vue";
import { user_settings, USER_SETTINGS_KEYS } from "../tools";
import { ref } from "vue";
import AISettings from "./AISettings.vue";
const showSettings = defineModel<boolean>();

const selectedSettings = ref<string>(user_settings[0]?.key ?? '')
</script>

<style scoped lang="css">
.settings{
  width: 80vw;
  height: 80vh;
}

.button{
  background-color: transparent
}
</style>
