<template>
  <Dialog v-model:visible="visible" :title="$t('project.scope_dialog_title')">
    <div class="column gap-mid scope-authorization-body">
      <div class="row gap-low flex-center">
        <span class="text-bold">{{ $t("project.acknowledgment_status") }}</span>
        <span
          class="acknowledgment-status-badge"
          :class="isAcknowledged ? 'text-active' : 'text-inactive'"
        >
          {{ isAcknowledged ? $t("project.acknowledged") : $t("project.needs_reacknowledgment") }}
        </span>
      </div>

      <div class="separator" />

      <div class="column gap-low">
        <span class="text-bold">{{ $t("project.scope_section_title") }}</span>
        <ScopeRangeInput v-model="scope" :warning="warning" />
        <button
          type="button"
          class="button border full-width save-scope-button"
          :disabled="isSaving || isHostRangeEmpty"
          @click="saveScope"
        >
          {{ isSaving ? $t("project.saving_scope") : $t("project.save_scope") }}
        </button>
      </div>

      <div class="separator" />

      <div class="column gap-low">
        <span class="text-bold">{{ $t("project.acknowledgment_section_title") }}</span>

        <div class="input-wrapper">
          <label class="floating-label">{{ $t("project.acknowledged_by") }}</label>
          <input
            v-model="acknowledgedBy"
            class="input-field border acknowledged-by-input"
            :placeholder="$t('project.acknowledged_by_placeholder')"
          />
        </div>

        <div class="input-wrapper">
          <label class="floating-label">{{ $t("project.acknowledgment_description") }}</label>
          <textarea
            v-model="description"
            class="input-field border acknowledgment-description-input"
            :placeholder="$t('project.acknowledgment_description_placeholder')"
          />
        </div>

        <button
          type="button"
          class="button border full-width submit-acknowledgment-button"
          :disabled="isSubmittingAcknowledgment || isAcknowledgedByEmpty"
          @click="submitAcknowledgment"
        >
          {{
            isSubmittingAcknowledgment
              ? $t("project.submitting_acknowledgment")
              : $t("project.submit_acknowledgment")
          }}
        </button>
      </div>

      <div class="separator" />

      <div class="column gap-low">
        <span class="text-bold">{{ $t("project.discovery_section_title") }}</span>
        <DiscoveryResults :project-id="props.projectId" />
      </div>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import Dialog from "@/components/reusable/Dialog.vue";
import ScopeRangeInput from "./ScopeRangeInput.vue";
import DiscoveryResults from "./DiscoveryResults.vue";
import { useMomosStore } from "@/store/momos_store";
import type { tScopeRange } from "@/types";

const props = defineProps<{
  projectId: string;
}>();

const visible = defineModel<boolean>("visible", { default: false });

const emits = defineEmits<{
  "acknowledgment-status-change": [isAcknowledged: boolean];
}>();

const store = useMomosStore();
const { t: $t } = useI18n();

const scope = ref<tScopeRange>({ host_range: "", port_range_start: 1, port_range_end: 65535 });
const warning = ref<string | null>(null);
const isAcknowledged = ref(false);
const isSaving = ref(false);
const acknowledgedBy = ref("");
const description = ref("");
const isSubmittingAcknowledgment = ref(false);

const isHostRangeEmpty = computed(() => scope.value.host_range.trim().length === 0);
const isAcknowledgedByEmpty = computed(() => acknowledgedBy.value.trim().length === 0);

// `immediate: true` so a dialog already mounted visible (as every spec
// here mounts it) loads right away, not only on a later true->false->true
// toggle - matches "on open" meaning "whenever it becomes/is visible", not
// "only on a change event".
watch(
  visible,
  (isVisible) => {
    if (isVisible) loadScope();
  },
  { immediate: true },
);

async function refreshAcknowledgmentStatus() {
  try {
    const status = await store.getAcknowledgmentStatus(props.projectId);
    isAcknowledged.value = status;
    emits("acknowledgment-status-change", status);
  } catch (error) {
    console.error("Failed to load acknowledgment status:", error);
  }
}

async function loadScope() {
  try {
    const result = await store.getProjectScope(props.projectId);
    scope.value = {
      host_range: result.host_range,
      port_range_start: result.port_range_start,
      port_range_end: result.port_range_end,
    };
    warning.value = null;
    await refreshAcknowledgmentStatus();
  } catch (error) {
    console.error("Failed to load project scope:", error);
    toast.error($t("project.scope_load_failed"));
  }
}

async function saveScope() {
  isSaving.value = true;

  try {
    const result = await store.updateProjectScope(
      props.projectId,
      scope.value.host_range,
      scope.value.port_range_start,
      scope.value.port_range_end,
    );
    scope.value = {
      host_range: result.scope.host_range,
      port_range_start: result.scope.port_range_start,
      port_range_end: result.scope.port_range_end,
    };
    warning.value = result.large_range_warning ? $t("project.scope_large_range_warning") : null;
    toast.success($t("project.scope_save_success"));
    // Widening may have just invalidated the existing acknowledgment (per
    // the spec, narrowing never does) - re-fetch rather than assume either
    // way, since that logic is server-side (ProjectScopeService).
    await refreshAcknowledgmentStatus();
  } catch (error) {
    console.error("Failed to update project scope:", error);
    toast.error($t("project.scope_save_failed"));
  } finally {
    isSaving.value = false;
  }
}

async function submitAcknowledgment() {
  isSubmittingAcknowledgment.value = true;

  try {
    await store.submitAcknowledgment(props.projectId, acknowledgedBy.value, description.value);
    acknowledgedBy.value = "";
    description.value = "";
    toast.success($t("project.acknowledgment_submit_success"));
    await refreshAcknowledgmentStatus();
  } catch (error) {
    console.error("Failed to submit authorization acknowledgment:", error);
    toast.error($t("project.acknowledgment_submit_failed"));
  } finally {
    isSubmittingAcknowledgment.value = false;
  }
}
</script>

<style scoped>
.scope-authorization-body {
  width: 480px;
}

.acknowledgment-status-badge {
  font-weight: bold;
}

.acknowledgment-description-input {
  min-height: 80px;
  resize: vertical;
}
</style>
