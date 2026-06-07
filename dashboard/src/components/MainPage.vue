<template>
    <div class="main-page">
        <ProjectBar class="project-bar"/>
        <div class="row gap-low">
            <ToolsBar class="tool-bar"/>
            <ContextView class="context-view"/>
        </div>
    </div>
</template>

<script setup lang="ts">
import ContextView from './MainPage/ContextView.vue';
import ProjectBar from './MainPage/ProjectBar.vue';
import ToolsBar from './MainPage/ToolsBar.vue';

</script>

<style lang="css">
.project-bar{
    margin-bottom: 5px;
}

.main-page{
    width: auto;
    display: flex;
    flex-direction: column;
}

.tool-bar{
    flex-grow: 1;
}

.context-view{
    flex-grow: 8;
}
</style>