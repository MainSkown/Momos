<template>
  <div class="border field">
    <div class="row">
      <span class="text-red" style="padding-left: 10px">{{
        $t("overview.attack_vectors")
      }}</span>
    </div>
    <div class="separator" />

    <div class="column attack-vectors-body">
      <div v-if="!displayTargetId" class="text-center text-gray no-vectors">
        {{ $t("attack_vectors.no_running_target") }}
      </div>

      <div v-else class="board-columns scrollable-panel">
        <div v-for="column in COLUMNS" :key="column.status" class="board-column">
          <div
            class="row board-column-header"
            :class="column.status === 'tested_vulnerable' ? 'severity-critical' : 'text-gray'"
          >
            <span class="truncate-text">{{ $t(column.labelKey) }}</span>
            <span class="column-count">{{ vectorsFor(column.status).length }}</span>
          </div>

          <div
            v-for="vector in vectorsFor(column.status)"
            :key="vector.id"
            class="border vector-card"
            :class="column.status === 'tested_vulnerable' ? 'severity-critical' : ''"
          >
            <span
              v-if="vector.linked_vulnerability_id"
              class="material-icons-outlined vector-reported-icon"
              :title="$t('attack_vectors.reported')"
              >task_alt</span
            >
            <span class="vector-description">{{ vector.description }}</span>
          </div>

          <span v-if="vectorsFor(column.status).length === 0" class="text-gray no-vectors-in-column"
            >—</span
          >
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useMomosStore } from "@/store/momos_store";
import type { AttackVectorStatus } from "@/api/types.gen";

const store = useMomosStore();

const COLUMNS: { status: AttackVectorStatus; labelKey: string }[] = [
  { status: "pending", labelKey: "attack_vectors.status_pending" },
  { status: "testing", labelKey: "attack_vectors.status_testing" },
  { status: "tested_vulnerable", labelKey: "attack_vectors.status_tested_vulnerable" },
  { status: "tested_not_vulnerable", labelKey: "attack_vectors.status_tested_not_vulnerable" },
  { status: "inconclusive", labelKey: "attack_vectors.status_inconclusive" },
];

// Attack vectors are per-target, but (like AgentLogs/UserConsole) this
// card is project-wide - only one target can ever be running in a
// project at a time (see AgentService.start_agent's own exclusivity
// rule).
const runningTargetId = computed(() => store.getRunningTarget(store.openedProject));

// Which target's board to show - follows runningTargetId while a run is
// live, but deliberately does NOT clear back to null when the run ends:
// the last run's board stays on screen (so a finished pentest's results
// are still readable) until a NEW run actually starts, either on the
// same target (which wipes and repopulates it - see
// delete_attack_vectors_for_target's own docstring on the backend) or a
// different one in this project.
const displayTargetId = ref<string | null>(runningTargetId.value);

function vectorsFor(status: AttackVectorStatus) {
  if (!displayTargetId.value) return [];
  return store.getAttackVectors(displayTargetId.value).filter((v) => v.status === status);
}

async function loadForTarget(targetID: string | null) {
  if (targetID) await store.loadAttackVectors(store.openedProject, targetID);
}

onMounted(() => loadForTarget(displayTargetId.value));

watch(runningTargetId, (newTarget) => {
  if (!newTarget) return;
  displayTargetId.value = newTarget;
  loadForTarget(newTarget);
});

// Switching projects entirely - the previous project's target has nothing
// to do with this one's board, so (unlike a run simply ending) this does
// reset back to null when nothing is running in the newly opened project.
watch(
  () => store.openedProject,
  (newProject) => {
    displayTargetId.value = store.getRunningTarget(newProject);
    loadForTarget(displayTargetId.value);
  },
);
</script>

<style scoped lang="css">
.attack-vectors-body {
  flex: 1;
  min-height: 0;
  padding: 8px;
  box-sizing: border-box;
}

.no-vectors {
  margin: auto;
}

.board-columns {
  display: flex;
  gap: 8px;
  height: 100%;
  overflow: auto;
}

.board-column {
  flex: 1 1 0;
  min-width: 140px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding-right: 8px;
}

.board-column:not(:last-child) {
  border-right: 1px solid var(--border-primary);
}

.board-column-header {
  justify-content: space-between;
  font-size: 0.75rem;
  font-weight: bold;
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border-primary);
}

.column-count {
  flex-shrink: 0;
}

.vector-card {
  display: flex;
  align-items: flex-start;
  gap: 4px;
  padding: 6px;
  font-size: 0.8rem;
}

.vector-reported-icon {
  font-size: 1rem;
  line-height: 1.2;
  flex-shrink: 0;
}

.vector-description {
  overflow-wrap: break-word;
}

.no-vectors-in-column {
  font-size: 0.8rem;
  text-align: center;
}
</style>
