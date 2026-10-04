<template>
<div class="border">
    <div class="header-text context-header-row">
        <span class="truncate-text">{{ title }}</span>
        <!-- A page nested in the default slot below (e.g. ProjectSettingsPage)
             can Teleport its own status text here - e.g. an autosave
             indicator - without this component needing to know anything
             about it (no prop/emit plumbing through MainPage.vue for
             state that's really only ever local to one tool page). Empty
             and inert for every other tool, which doesn't use it. -->
        <div id="context-header-extra" class="context-header-extra"></div>
    </div>

    <div class="separator" />

    <slot></slot>
</div>
</template>

<script setup lang="ts">
defineProps<{ title: string }>();
</script>

<style scoped>
.context-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-sm);
}

/* A flex item's default min-width:auto stops .truncate-text's own
   overflow/ellipsis rules from taking effect - without this, a long or
   translated title can push the teleported status text out instead of
   truncating. Scoped to this row rather than changing the shared rule
   itself, which other call sites rely on outside a flex context. */
.context-header-row > .truncate-text {
  min-width: 0;
}

.context-header-extra {
  display: flex;
  align-items: center;
  padding-right: var(--spacing-sm);
}
</style>