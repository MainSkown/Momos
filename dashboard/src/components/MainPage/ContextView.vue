<template>
<div class="border">
    <div class="header-text">
        {{ title }}
    </div>

    <div class="separator" />

    <slot></slot>
</div>
</template>

<script setup lang="ts">
defineProps<{ title: string }>();
</script>