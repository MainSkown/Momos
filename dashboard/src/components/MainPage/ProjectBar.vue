<template>
  <div class="border row">
    <div
      v-for="p in store.getProjects"
      :key="p.id"
      class="button border"
      :class="{ 'is-active': store.openedProject === p.id }"
      @click="store.openedProject = p.id"
      style="min-width: 100px"
    >
      {{ p.name }}
    </div>

    <div class="add-button button border" @click="add_Project">+</div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useMomosStore } from "@/store/momos_store";

const store = useMomosStore();

if (store.openedProject === "") {
  store.openedProject = store.getProjects[0]?.id ?? "";
}

function add_Project(){
  store.addProject('kebab')
}
</script>

<style scoped lang="css">
.add-button {
  margin-left: auto;
  aspect-ratio: 1;
  border-top: none;
  border-bottom: none;
  border-right: none;

  font-size: x-large;
}

.button {
  border-top: none;
  border-bottom: none;
}
</style>
