<template>
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
import Dialog from "@/components/reusable/Dialog.vue";
import { useMomosStore } from "@/store/momos_store";
import { ref } from "vue";
import { toast } from "vue3-toastify";

const show_add_project = defineModel({type: Boolean, default: false})

const store = useMomosStore();

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