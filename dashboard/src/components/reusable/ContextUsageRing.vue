<template>
  <Tooltip :message="tooltipMessage">
    <svg
      class="context-ring"
      width="22"
      height="22"
      viewBox="0 0 22 22"
    >
      <circle
        class="context-ring-track"
        cx="11"
        cy="11"
        :r="radius"
        fill="none"
        stroke-width="3"
      />
      <circle
        class="context-ring-fill"
        cx="11"
        cy="11"
        :r="radius"
        fill="none"
        stroke-width="3"
        stroke-linecap="round"
        :stroke="ringColor"
        :stroke-dasharray="circumference"
        :stroke-dashoffset="dashOffset"
      />
    </svg>
  </Tooltip>
</template>

<script setup lang="ts">
import { computed } from "vue";
import Tooltip from "./Tooltip.vue";

const props = defineProps<{
  usedTokens: number;
  contextWindow: number;
}>();

const radius = 9;
const circumference = 2 * Math.PI * radius;

const fraction = computed(() => {
  if (!props.contextWindow) return 0;
  return Math.min(1, Math.max(0, props.usedTokens / props.contextWindow));
});

const dashOffset = computed(() => circumference * (1 - fraction.value));

const ringColor = computed(() => {
  if (fraction.value > 0.9) return "var(--status-critical)";
  if (fraction.value > 0.7) return "var(--status-medium)";
  return "var(--status-success)";
});

const percentLabel = computed(() => Math.round(fraction.value * 100));

const tooltipMessage = computed(
  () =>
    `Context used: ${props.usedTokens.toLocaleString()} / ${props.contextWindow.toLocaleString()} tokens (${percentLabel.value}%)`,
);
</script>

<style scoped>
.context-ring {
  transform: rotate(-90deg);
  flex-shrink: 0;
}

.context-ring-track {
  stroke: var(--border-subtle);
}

.context-ring-fill {
  transition: stroke-dashoffset var(--transition-normal), stroke var(--transition-normal);
}
</style>
