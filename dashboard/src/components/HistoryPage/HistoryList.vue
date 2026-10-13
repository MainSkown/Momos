<template>
  <div class="column layout-container">
    <!-- Filter bar -->
    <div class="row gap-low filter-bar">
      <select v-model="targetFilter" class="input-field">
        <option value="">{{ $t("history.filter_all_targets") }}</option>
        <option v-for="t in projectTargets" :key="t.id" :value="t.id">
          {{ t.name }}
        </option>
      </select>
      <select v-model="outcomeFilter" class="input-field">
        <option value="">{{ $t("history.filter_all_outcomes") }}</option>
        <option v-for="o in OUTCOMES" :key="o" :value="o">
          {{ $t(OUTCOME_LABEL_KEYS[o]) }}
        </option>
      </select>
    </div>

    <div class="column gap-low scrollable-panel session-list">
      <SessionCard
        v-for="session in sortedSessions"
        :key="session.id"
        :session="session"
        :target-name="targetName(session.target_id)"
        @select="emit('select', $event)"
      />

      <div class="text-center no-sessions" v-if="sortedSessions.length === 0">
        {{ $t("history.no_sessions") }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useMomosStore } from "@/store/momos_store";
import type { TestSessionOutcome } from "@/api";
import SessionCard from "./SessionCard.vue";
import { OUTCOME_LABEL_KEYS } from "./historyUtils";

const { t: $t } = useI18n();
const store = useMomosStore();

const emit = defineEmits<{
  select: [sessionId: string];
}>();

const OUTCOMES: TestSessionOutcome[] = [
  "running",
  "paused",
  "finished",
  "time_expired",
  "failed",
  "aborted",
];

const targetFilter = ref("");
const outcomeFilter = ref<TestSessionOutcome | "">("");

const projectTargets = computed(() => store.getProjectsTargets(store.openedProject));

function targetName(targetId: string): string {
  return projectTargets.value.find((t) => t.id === targetId)?.name ?? targetId;
}

async function reload() {
  const projectId = store.openedProject;
  if (!projectId) return;

  await store.loadSessions(projectId, {
    target_id: targetFilter.value || undefined,
    outcome: outcomeFilter.value || undefined,
  });
}

onMounted(() => {
  reload();
  store.loadTargets(store.openedProject);
});

// A project switch needs both: the new project's targets (or every card
// shows a raw target_id instead of a name - Vulnerabilities.vue does the
// same pairing in its own openedProject watcher), and the filters reset
// (a target/outcome filter carried over from the previous project would
// almost certainly match nothing in this one, silently showing an empty
// list with no indication a stale filter is still active).
watch(
  () => store.openedProject,
  (newProject) => {
    targetFilter.value = "";
    outcomeFilter.value = "";
    reload();
    store.loadTargets(newProject);
  },
);
watch([targetFilter, outcomeFilter], reload);

// Server returns newest-started-first already (see
// get_test_sessions_for_project) - this just pins a currently running
// session to the very top regardless of how long ago it actually
// started (a resumed session can be much older than every finished one
// listed below it).
const sortedSessions = computed(() => {
  const sessions = store.getSessions(store.openedProject);
  const running = sessions.filter((s) => s.outcome === "running");
  const rest = sessions.filter((s) => s.outcome !== "running");
  return [...running, ...rest];
});
</script>

<style scoped lang="css">
.layout-container {
  height: 82vh;
  box-sizing: border-box;
  padding-bottom: 5px;
}

.filter-bar {
  padding: 10px;
  flex-wrap: wrap;
}

.filter-bar .input-field {
  flex: 1;
  min-width: 140px;
}

.session-list {
  flex: 1;
  min-height: 0;
  padding: 0 10px 10px 10px;
}

.no-sessions {
  color: var(--text-gray-dark);
  margin-top: auto;
  margin-bottom: auto;
}
</style>
