<template>
  <span ref="triggerRef" class="tooltip" @mouseenter="showTooltip" @mouseleave="hideTooltip" @mousemove="updateTooltipPosition">
    <span class="tooltip-trigger">
      <slot />
    </span>

    <Teleport to="body">
      <Transition name="tooltip-fade">
        <div v-if="visible" class="tooltip-text" :style="tooltipStyle">
          {{ message }}
        </div>
      </Transition>
    </Teleport>
  </span>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";

const props = withDefaults(
  defineProps<{
    message: string;
    offset?: number;
    maxWidth?: string;
  }>(),
  {
    offset: 10,
    maxWidth: "280px",
  },
);

const triggerRef = ref<HTMLElement | null>(null);
const visible = ref(false);
const position = ref({ x: 0, y: 0 });

const tooltipStyle = computed(() => ({
  left: `${position.value.x}px`,
  top: `${position.value.y}px`,
  maxWidth: `min(${props.maxWidth}, calc(100vw - 32px))`,
}));

const updateTooltipPosition = () => {
  const trigger = triggerRef.value;
  if (!trigger) return;

  const rect = trigger.getBoundingClientRect();
  position.value.x = rect.left + rect.width / 2;
  position.value.y = rect.top - props.offset;
};

const showTooltip = () => {
  visible.value = true;
  updateTooltipPosition();
};

const hideTooltip = () => {
  visible.value = false;
};
</script>

<style scoped>
.tooltip {
  position: relative;
  display: inline-flex;
}

.tooltip-trigger {
  display: inline-flex;
}

.tooltip-text {
  position: fixed;
  z-index: 1000;
  pointer-events: none;
  background-color: var(--black);
  color: var(--text-white);
  border: 1px solid var(--border-primary);
  box-shadow: var(--shadow-red-subtle);
  padding: var(--spacing-sm) var(--spacing-md);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  line-height: 1.3;
  letter-spacing: 0.5px;
  white-space: normal;
  overflow-wrap: anywhere;
  text-align: center;
  visibility: visible;
  opacity: 1;
  transform: translate(-50%, -100%) translateY(-10px);
  transition: opacity var(--transition-fast), transform var(--transition-fast), visibility var(--transition-fast);
}

.tooltip-text::after {
  content: "";
  position: absolute;
  top: 100%;
  left: 50%;
  margin-left: -6px;
  border-width: 6px;
  border-style: solid;
  border-color: var(--border-primary) transparent transparent transparent;
}

.tooltip-fade-enter-active,
.tooltip-fade-leave-active {
  transition: opacity var(--transition-fast), transform var(--transition-fast);
}

.tooltip-fade-enter-from,
.tooltip-fade-leave-to {
  opacity: 0;
  transform: translate(-50%, -100%) translateY(-5px);
}
</style>
