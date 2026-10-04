<template>
  <div class="border field">
    <div class="row">
      <span class="text-red" style="padding-left: 10px">{{
        $t("overview.attack_vectors")
      }}</span>
    </div>
    <div class="separator" />

    <div class="column attack-vectors-body">
      <div v-if="!runningTargetId" class="text-center text-gray no-vectors">
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
import { computed, onMounted, watch } from "vue";
import { useMomosStore } from "@/store/momos_store";
import type { AttackVectorStatus } from "@/api/types.gen";

const store = useMomosStore();

const COLUMNS: { status: AttackVectorStatus; labelKey: string }[] = [
  { status: "pending", labelKey: "attack_vectors.status_pending" },
  { status: "testing", labelKey: "attack_vectors.status_testing" },
  { status: "tested_vulnerable", labelKey: "attack_vectors.status_tested_vulnerable" },
  { status: "tested_not_vulnerable", labelKey: "attack_vectors.status_tested_not_vulnerable" },
  { status: "inconclusive", labelKey: "attack_vectors.status_inconclusive" },
  { status: "skipped", labelKey: "attack_vectors.status_skipped" },
];

// Attack vectors are per-target, but (like AgentLogs/UserConsole) this
// card is project-wide - only one target can ever be running in a
// project at a time (see AgentService.start_agent's own exclusivity
// rule), so the currently-running target is the only one with anything
// live to show. A finished target's own board is still reachable later
// once a dedicated view exists for it - out of scope here.
const runningTargetId = computed(() => store.getRunningTarget(store.openedProject));

function vectorsFor(status: AttackVectorStatus) {
  if (!runningTargetId.value) return [];
  return store.getAttackVectors(runningTargetId.value).filter((v) => v.status === status);
}

async function loadForTarget(targetID: string | null) {
  if (targetID) await store.loadAttackVectors(store.openedProject, targetID);
}

onMounted(() => loadForTarget(runningTargetId.value));
watch(runningTargetId, (newTarget) => loadForTarget(newTarget));
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
  flex: 0 0 140px;
  display: flex;
  flex-direction: column;
  gap: 6px;
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
