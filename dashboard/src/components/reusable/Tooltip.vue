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
// How far the box's own center had to shift from the trigger's center to
// stay on-screen (see updateTooltipPosition) - applied to the arrow so it
// still points at the trigger even when the box itself is off-center.
const arrowOffset = ref(0);

// Keep the box at least this far from the viewport edge - a trigger
// closer to the edge than this pushes the box inward instead of letting
// it (or its centered arrow) run past the edge. Comfortably more than
// the box's own box-shadow bleed (--shadow-red-subtle), so the glow
// never reads as the box itself touching the edge.
const VIEWPORT_MARGIN = 24;

function parsePixels(value: string): number {
  const parsed = parseFloat(value);
  return Number.isNaN(parsed) ? 280 : parsed;
}

const tooltipStyle = computed(() => ({
  left: `${position.value.x}px`,
  top: `${position.value.y}px`,
  maxWidth: `min(${props.maxWidth}, calc(100vw - ${2 * VIEWPORT_MARGIN}px))`,
  "--tooltip-arrow-offset": `${arrowOffset.value}px`,
}));

const updateTooltipPosition = () => {
  const trigger = triggerRef.value;
  if (!trigger) return;

  const rect = trigger.getBoundingClientRect();
  const desiredX = rect.left + rect.width / 2;

  // The box's actual rendered width is content-dependent (see the
  // `width: max-content` comment below) and isn't known until after it's
  // in the DOM, so clamp against the worst case (its configured max
  // width) - this can never let it overflow, even if the real box ends
  // up narrower and so isn't perfectly centered on the trigger.
  const effectiveMaxWidth = Math.min(
    parsePixels(props.maxWidth),
    window.innerWidth - 2 * VIEWPORT_MARGIN,
  );
  const halfWidth = effectiveMaxWidth / 2;
  const minX = halfWidth + VIEWPORT_MARGIN;
  const maxX = window.innerWidth - halfWidth - VIEWPORT_MARGIN;
  const clampedX = Math.min(Math.max(desiredX, minX), maxX);

  position.value.x = clampedX;
  position.value.y = rect.top - props.offset;

  const maxArrowOffset = Math.max(0, halfWidth - 12);
  arrowOffset.value = Math.min(
    Math.max(desiredX - clampedX, -maxArrowOffset),
    maxArrowOffset,
  );
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
  /* A fixed-position element with only `left` set (no `right`) and no
     explicit width should shrink-to-fit its content, but `width: auto`
     can instead collapse to a minimum-content width in this positioning
     context - each word (even each character, with overflow-wrap:
     anywhere) then wraps onto its own line, rendering as a single-
     character-wide vertical column. `width: max-content` forces sizing
     to the content's natural (unwrapped) width, still capped by the
     inline max-width style below it. */
  width: max-content;
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
  /* Offset by how far the box itself had to shift to stay on-screen (see
     updateTooltipPosition), so the arrow keeps pointing at the trigger
     instead of just the box's own (possibly off-center) midpoint. */
  left: calc(50% + var(--tooltip-arrow-offset, 0px));
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
