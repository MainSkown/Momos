<template>
  <div class="column gap-low scope-range-input">
    <div class="input-wrapper">
      <label class="floating-label">{{ $t("project.host_range") }}</label>
      <input
        v-model="hostRange"
        class="input-field border host-range-input"
        :class="{ 'is-invalid': isHostRangeEmpty }"
        :placeholder="$t('project.host_range_placeholder')"
        spellcheck="false"
      />
    </div>

    <span v-if="warning" class="text-red scope-range-warning">{{ warning }}</span>

    <div class="row gap-low">
      <div class="input-wrapper full-width">
        <label class="floating-label">{{ $t("project.port_range_start") }}</label>
        <input
          v-model.number="portRangeStart"
          type="number"
          min="1"
          max="65535"
          inputmode="numeric"
          class="input-field border full-width port-range-start-input"
        />
      </div>

      <div class="input-wrapper full-width">
        <label class="floating-label">{{ $t("project.port_range_end") }}</label>
        <input
          v-model.number="portRangeEnd"
          type="number"
          min="1"
          max="65535"
          inputmode="numeric"
          class="input-field border full-width port-range-end-input"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import type { tScopeRange } from "@/types";

defineProps<{
  warning?: string | null;
}>();

const model = defineModel<tScopeRange>({ required: true });

const { t: $t } = useI18n();

// Each setter rebuilds the whole object rather than mutating model.value
// in place - defineModel's parent-sync only fires on a .value
// *reassignment*, not on mutating a property of the object it currently
// holds.
const hostRange = computed({
  get: () => model.value.host_range,
  set: (value: string) => {
    model.value = { ...model.value, host_range: value };
  },
});

const portRangeStart = computed({
  get: () => model.value.port_range_start,
  set: (value: number) => {
    model.value = { ...model.value, port_range_start: value };
  },
});

const portRangeEnd = computed({
  get: () => model.value.port_range_end,
  set: (value: number) => {
    model.value = { ...model.value, port_range_end: value };
  },
});

// Real parsing (single IP / CIDR / host list, IPv4 and IPv6) stays
// server-side - see the spec's "Decisions" - this only flags the one
// obviously-wrong case so an empty scope doesn't silently slip through.
const isHostRangeEmpty = computed(() => hostRange.value.trim().length === 0);
</script>

<style scoped>
.scope-range-warning {
  font-size: 0.85rem;
}
</style>
