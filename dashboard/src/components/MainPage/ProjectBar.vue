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

    <button class="add-button button border" @click="show_add_project = true">+</button>
  </div>

  <div v-if="store.projects.length === 0" class="flex-center">
    <div class="column text-center text-red">
      <h4>{{ $t('project.no_projects') }}.</h4>
      <button class="button border" style="width: 300px" @click="show_add_project = true">
        <h4>{{ $t('project.create_new') }}</h4>
      </button>
    </div>
  </div>

  <Dialog v-model:visible="show_add_project">
    <template v-slot:title>
      <h3 class="no-margin">{{ $t('project.create_new') }}</h3>
    </template>
    <div class="column" style="gap: 10px;">
      <div class="input-wrapper">
      <label class="floating-label">{{ $t('project.name') }}</label>
    <input class="input-field" :placeholder="$t('project.enter_name')" v-model="projects_name"/>
    </div>
    <button class="button border" @click="add_Project">{{ $t('universal.add') }}</button>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useMomosStore } from "@/store/momos_store";
import Dialog from "../reusable/Dialog.vue";
import { toast } from "vue3-toastify";

const store = useMomosStore();

const show_add_project = ref<boolean>(false)

if (store.openedProject === "") {
  store.openedProject = store.getProjects[0]?.id ?? "";
}

const projects_name = ref<string>('')

function add_Project() {
  if(projects_name.value.length === 0){
    toast.error("Name can't be empty")
    return
  }

  store.addProject(projects_name.value)
  projects_name.value = ''
  show_add_project.value = false
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
