<template>
  <div class="border" style="padding: 0; height: 720px">
    <div class="header-text">TOOLS</div>

    <div class="separator" />

    <div class="column" style="margin-top: 5px">
      <div
        class="button"
        :class="{ 'is-active': toolID === t.id }"
        v-for="t in tools"
        style="justify-content: start; padding-left: 20px"
        @click="selectTool(t.id)"
      >
        {{ t.name }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { tools } from "../tools";

const toolID = defineModel<number>();

const selectTool = (id: number) => {
  toolID.value = id;
};

</script>

<style lang="css"></style>
