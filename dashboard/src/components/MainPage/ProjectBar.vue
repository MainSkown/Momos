<template>
    <div class="border row">
        <div 
            v-for="p in projects" 
            :key="p.name"
            class="button border"
            :class="{ 'is-active': activeProject === p.name }"
            @click="activeProject = p.name"
            style="min-width: 100px;"
        >
            {{ p.name }}
        </div>

        <div class="add-button button border" @click="console.log('lick')"> +</div>
    </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const projects = [{ name: 'test' }, { name: 'test2' }]
const activeProject = ref<string | null>(null)
</script>

<style lang="css">

.add-button {
    margin-left: auto;
    aspect-ratio: 1;
    border-top: none;
    border-bottom: none;
    border-right: none;

    font-size: x-large;
}
</style>