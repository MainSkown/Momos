<template>
  <span ref="triggerRef" class="hover-menu" @mouseenter="show" @mouseleave="scheduleHide">
    <span class="hover-menu-trigger">
      <slot name="trigger" />
    </span>

    <Teleport to="body">
      <Transition name="hover-menu-fade">
        <div
          v-if="visible"
          class="hover-menu-panel"
          :style="panelStyle"
          @mouseenter="cancelHide"
          @mouseleave="scheduleHide"
        >
          <slot />
        </div>
      </Transition>
    </Teleport>
  </span>
</template>

<script setup lang="ts">
import { ref } from "vue";

const props = withDefaults(
  defineProps<{
    maxWidth?: string;
  }>(),
  {
    maxWidth: "320px",
  },
);

const triggerRef = ref<HTMLElement | null>(null);
const visible = ref(false);
const position = ref({ x: 0, y: 0 });
// Teleported to <body>, so it isn't actually nested under the trigger -
// without a short grace period, moving the mouse from the trigger down to
// the panel (which never overlaps the trigger's own bounding box) would
// immediately fire the trigger's mouseleave and close it before it's
// reached. Cancelled by the panel's own mouseenter once the pointer makes
// it there in time.
const HIDE_DELAY_MS = 150;
let hideTimer: ReturnType<typeof setTimeout> | null = null;

const panelStyle = ref<Record<string, string>>({});

function updatePosition() {
  const trigger = triggerRef.value;
  if (!trigger) return;

  const rect = trigger.getBoundingClientRect();
  panelStyle.value = {
    left: `${rect.left}px`,
    top: `${rect.bottom + 6}px`,
  };
}

function show() {
  if (hideTimer) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
  updatePosition();
  visible.value = true;
}

function scheduleHide() {
  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = setTimeout(() => {
    visible.value = false;
    hideTimer = null;
  }, HIDE_DELAY_MS);
}

function cancelHide() {
  if (hideTimer) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
}
</script>

<style scoped>
.hover-menu {
  position: relative;
  display: inline-flex;
}

.hover-menu-trigger {
  display: inline-flex;
  cursor: default;
}

.hover-menu-panel {
  position: fixed;
  z-index: 1000;
  background-color: var(--black);
  color: var(--text-white);
  border: 1px solid var(--border-primary);
  box-shadow: var(--shadow-red-subtle);
  padding: var(--spacing-sm);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  width: max-content;
  max-width: v-bind("props.maxWidth");
}

.hover-menu-fade-enter-active,
.hover-menu-fade-leave-active {
  transition: opacity var(--transition-fast);
}

.hover-menu-fade-enter-from,
.hover-menu-fade-leave-to {
  opacity: 0;
}
</style>
