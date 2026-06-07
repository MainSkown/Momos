<template>
<div class="border" style="padding: 0; height: 720px;">
    <div class="header-text">
        TOOLS
    </div>

    <div class="separator" />

    <div class="column" style="margin-top: 5px;">
        <div class="button" v-for="t in tools" style="justify-content: start; padding-left: 20px;">
            {{ t.name }}
        </div>
    </div>
</div>

</template>

<script setup lang="ts">
import type { tTool } from '../types'

const tools: tTool[] = [
  {
    name: 'Overview',
    on_click: () => {},
  },
  {
    name: 'Vulnerabilities',
    on_click: () => {}
  },
  {
    name: 'Settings',
    on_click: () => {}
  }
]
</script>

<style lang="css">

</style>