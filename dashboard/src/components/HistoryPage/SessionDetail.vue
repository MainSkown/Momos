<template>
  <div class="column layout-container">
    <div class="row session-header-row">
      <div class="button border back-button" @click="emit('back')">
        <span class="material-icons-outlined">arrow_back</span>
        <span>{{ $t("history.back_to_list") }}</span>
      </div>
    </div>

    <div v-if="loadError" class="column flex-center loading-placeholder">
      <span class="text-gray">{{ $t("history.load_failed") }}</span>
      <div class="button border retry-button" @click="loadSessionData">
        {{ $t("history.retry") }}
      </div>
    </div>

    <div v-else-if="!detail" class="text-center text-gray loading-placeholder">…</div>

    <template v-else>
      <div class="border session-meta">
        <div class="row gap-low session-meta-top">
          <span class="text-bold text-white truncate-text">{{ targetName }}</span>
          <span class="tag border" :class="outcomeClass">
            <span v-if="detail.outcome === 'running'" class="running-dot" />
            {{ outcomeLabel }}
          </span>
        </div>

        <div class="row gap-mid session-meta-row text-gray">
          <span>{{ $t("history.started_at") }}: {{ formatDateTime(detail.started_at) }}</span>
          <span>{{ $t("history.ended_at") }}: {{ formatDateTime(detail.ended_at) }}</span>
          <span>{{ $t("history.active_duration") }}: {{ formattedActiveDuration }} {{ budgetLabel }}</span>
        </div>

        <div class="column gap-low config-snapshot">
          <span class="text-gray config-snapshot-title">{{ $t("history.config_snapshot") }}</span>
          <div class="row gap-mid config-snapshot-row text-gray">
            <span>{{ $t("history.pipeline_mode") }}: {{ pipelineModeLabel }}</span>
            <template v-if="detail.pipeline_mode === 'multi_agent'">
              <span>{{ $t("history.max_concurrent_agents") }}: {{ detail.max_concurrent_agents }}</span>
            </template>
            <template v-else>
              <span>{{ $t("history.base_model") }}: {{ detail.base_model_name || "—" }}</span>
            </template>
          </div>
          <div v-if="detail.pipeline_mode === 'multi_agent'" class="row gap-mid config-snapshot-row text-gray">
            <span>{{ $t("history.orchestrator_model") }}: {{ detail.orchestrator_model_name || "—" }}</span>
            <span>{{ $t("history.scouting_model") }}: {{ detail.scouting_model_name || "—" }}</span>
            <span>{{ $t("history.pentesting_model") }}: {{ detail.pentesting_model_name || "—" }}</span>
            <span>{{ $t("history.reporting_model") }}: {{ detail.reporting_model_name || "—" }}</span>
          </div>
        </div>

        <div v-if="resultSummaryItems.length > 0" class="row gap-mid result-counts text-gray">
          <span v-for="item in resultSummaryItems" :key="item.key">{{ item.label }}</span>
        </div>
      </div>

      <div class="radio-group full-width session-tabs-group">
        <input
          id="session-tab-vectors"
          type="radio"
          value="vectors"
          v-model="activeTab"
          class="radio-input"
        />
        <label for="session-tab-vectors" class="radio-label">
          {{ $t("history.tab_attack_vectors") }}
        </label>

        <input
          id="session-tab-logs"
          type="radio"
          value="logs"
          v-model="activeTab"
          class="radio-input"
        />
        <label for="session-tab-logs" class="radio-label">{{ $t("history.tab_logs") }}</label>
      </div>

      <div class="session-tab-body">
        <!-- Both tabs stay mounted (v-show, not v-if) so Logs keeps its
             loaded page/scroll position across tab switches, and so a
             vector click can hand it a run filter through a plain prop
             (see jumpToRunId below) without having to remount it. -->
        <AttackVectors
          v-show="activeTab === 'vectors'"
          class="session-vectors"
          :vectors="vectors"
          :empty-text="$t('history.no_sessions_vectors')"
          @select-vector="onSelectVector"
        />
        <SessionLogs
          v-show="activeTab === 'logs'"
          class="session-logs-panel"
          :session-id="sessionId"
          :jump-to-run-id="jumpToRunId"
        />
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import { useMomosStore } from "@/store/momos_store";
import { getTestSessionAttackVectors, type ResponseAttackVector } from "@/api";
import AttackVectors from "../OverviewPage/AttackVectors.vue";
import SessionLogs from "./SessionLogs.vue";
import { formatDateTime, formatDuration, OUTCOME_CLASS, OUTCOME_LABEL_KEYS } from "./historyUtils";

const { t: $t } = useI18n();
const store = useMomosStore();

const props = defineProps<{
  sessionId: string;
}>();

const emit = defineEmits<{
  back: [];
}>();

const activeTab = ref<"vectors" | "logs">("vectors");
const jumpToRunId = ref<string | null>(null);
const vectors = ref<ResponseAttackVector[]>([]);

const detail = computed(() => store.getSessionDetail(props.sessionId));

const targetName = computed(() => {
  if (!detail.value) return "";
  const target = store.targets.find((t) => t.id === detail.value!.target_id);
  return target?.name ?? detail.value.target_id;
});

// outcome/active_seconds are typed optional by the generator (server-side
// defaults make OpenAPI mark them "not required"), but a real response
// always sets them - see SessionCard.vue's identical comment.
const outcomeLabel = computed(() =>
  detail.value ? $t(OUTCOME_LABEL_KEYS[detail.value.outcome ?? "running"]) : "",
);
const outcomeClass = computed(() =>
  detail.value ? OUTCOME_CLASS[detail.value.outcome ?? "running"] : "",
);

const formattedActiveDuration = computed(() =>
  detail.value ? formatDuration(detail.value.active_seconds ?? 0, $t) : "",
);

const budgetLabel = computed(() => {
  if (!detail.value) return "";
  if (!detail.value.time_budget_seconds) return `(${$t("history.no_budget")})`;
  return $t("history.of_budget", {
    budget: formatDuration(detail.value.time_budget_seconds, $t),
  });
});

const pipelineModeLabel = computed(() =>
  detail.value?.pipeline_mode === "multi_agent"
    ? $t("settings.pipeline_mode_multi_agent")
    : $t("settings.pipeline_mode_single_agent"),
);

const VECTOR_STATUS_ORDER = [
  "pending",
  "testing",
  "tested_vulnerable",
  "tested_not_vulnerable",
  "inconclusive",
] as const;

const resultSummaryItems = computed(() => {
  // Captured into a plain local const - Vue's computed .value is a
  // getter, which TS can't prove stays non-null after the early return
  // below the way it would for a plain variable, so detail.value itself
  // (not this local) would still type-error as possibly-null everywhere
  // after it.
  const d = detail.value;
  if (!d) return [];

  const items: { key: string; label: string }[] = [];
  for (const status of VECTOR_STATUS_ORDER) {
    const count = d.vector_counts[status] ?? 0;
    if (count === 0) continue;
    items.push({
      key: status,
      label: `${count} ${$t("attack_vectors.status_" + status)}`,
    });
  }

  if (d.vulnerability_count > 0) {
    const key =
      d.vulnerability_count === 1
        ? "history.vulnerability_count_one"
        : "history.vulnerability_count_other";
    items.push({
      key: "vulnerabilities",
      label: $t(key, { count: d.vulnerability_count }),
    });
  }

  return items;
});

async function loadVectors() {
  const result = await getTestSessionAttackVectors({
    path: { session_id: props.sessionId },
  });
  vectors.value = result.data ?? [];
}

function onSelectVector(vector: ResponseAttackVector) {
  // assigned_run_id (the pentesting run actually testing it) is usually
  // the more useful jump target once one exists; discovered_by_run_id
  // (scouting, or the single-agent run that first proposed it) is the
  // only one a still-pending vector ever has.
  jumpToRunId.value = vector.assigned_run_id ?? vector.discovered_by_run_id ?? null;
  activeTab.value = "logs";
}

const loadError = ref(false);

async function loadSessionData() {
  loadError.value = false;
  try {
    await store.loadSessionDetail(props.sessionId);
    await store.loadTargets(detail.value?.project_id ?? store.openedProject);
    await loadVectors();
  } catch (err) {
    // loadSessionDetail/loadTargets/loadVectors all throw on a failed/
    // empty response (same pattern as deleteProject/loadAttackVectors) -
    // uncaught, this left `detail` null forever with no feedback beyond
    // the indefinite "…" placeholder.
    console.error("Could not load session:", err);
    loadError.value = true;
    toast.error($t("history.load_failed"), { position: toast.POSITION.TOP_CENTER });
  }
}

onMounted(loadSessionData);
</script>

<style scoped lang="css">
.layout-container {
  height: 82vh;
  box-sizing: border-box;
  padding: 0 10px;
  display: flex;
  flex-direction: column;
}

.session-header-row {
  padding-top: 10px;
}

.back-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  width: fit-content;
  padding: 5px;
}

.back-button .material-icons-outlined {
  font-size: 18px;
}

.loading-placeholder {
  margin: auto;
  gap: 10px;
}

.retry-button {
  width: fit-content;
}

.session-meta {
  margin: 10px 0;
  padding: 10px 14px;
  border-color: var(--border-subtle);
}

.session-meta-top {
  align-items: center;
  justify-content: space-between;
}

.session-meta-row {
  margin-top: 6px;
  font-size: 0.85rem;
  flex-wrap: wrap;
}

.config-snapshot {
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px solid var(--border-subtle);
}

.config-snapshot-title {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.config-snapshot-row {
  font-size: 0.8rem;
  flex-wrap: wrap;
}

.result-counts {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border-subtle);
  font-size: 0.8rem;
  flex-wrap: wrap;
}

.tag {
  padding: 2px 8px;
  font-size: 0.75rem;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}

.running-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: pulse 1.4s ease-in-out infinite;
}

@keyframes pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.3;
  }
}

.session-tabs-group .radio-label {
  flex: 1;
}

.session-tab-body {
  flex: 1;
  min-height: 0;
  margin: 10px 0;
  display: flex;
}

.session-vectors,
.session-logs-panel {
  flex: 1;
  min-height: 0;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
</style>
