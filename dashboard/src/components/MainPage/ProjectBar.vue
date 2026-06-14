<template>
    <div class="border row">
        <div 
            v-for="p in projects" 
            :key="p.id"
            class="button border"
            :class="{ 'is-active': activeProject === p.id }"
            @click="activeProject = p.id"
            style="min-width: 100px;"
        >
            {{ p.name }}
        </div>

        <div class="add-button button border" @click="">+</div>
    </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { tProject } from '../types';

const projects:tProject[] = [{ id:'123', name: 'test' }, {id:'213', name: 'test2' }]
const activeProject = defineModel<string>()
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
</style>