<template>
  <div class="border" style="padding: 0; height: 720px">
    <div class="header-text">{{ $t('tools.tools') }}</div>

    <div class="separator" />

    <div class="column" style="margin-top: 5px">
      <div
        class="button"
        :class="{ 'is-active': toolKey === t.key }"
        v-for="t in tools"
        style="justify-content: start; padding-left: 20px"
        @click="selectTool(t.key)"
      >
        {{ $t(t.name)}}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { tools } from "../tools";

const toolKey = defineModel<string>();

const selectTool = (key: string) => {
  toolKey.value = key;
};

</script>

<style lang="css"></style>
