<template>
  <div class="border row">
    <button
      v-for="p in store.getProjects"
      :key="p.id"
      class="button p_button border"
      :class="{ 'is-active': store.openedProject === p.id }"
      @click="store.openedProject = p.id"
      style="min-width: 100px"
    >
      {{ p.name }}
    </button>

    <button class="add-button button border" @click="show_add_project = true">
      +
    </button>
  </div>

  <div v-if="store.projects.length === 0" class="flex-center">
    <div class="column text-center text-red">
      <h4>{{ $t("project.no_projects") }}.</h4>
      <div class="row">
        <button
          class="button border"
          style="width: 300px"
          @click="show_add_project = true"
        >
          <h4>{{ $t("project.create_new") }}</h4>
        </button>
      </div>
    </div>
  </div>

  <ProjectDialog v-model="show_add_project" />
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useMomosStore } from "@/store/momos_store";
import ProjectDialog from "./ProjectDialog.vue";

const store = useMomosStore();

const show_add_project = ref<boolean>(false);

if (store.openedProject === "") {
  store.openedProject = store.getProjects[0]?.id ?? "";
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

.p_button {
  border-top: none;
  border-bottom: none;
}
</style>
