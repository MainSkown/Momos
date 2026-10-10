<template>
  <div class="column session-logs">
    <div class="row gap-low filter-bar">
      <select v-model="roleFilter" class="input-field">
        <option value="">{{ $t("history.filter_all_roles") }}</option>
        <option v-for="r in ROLE_OPTIONS" :key="r" :value="r">{{ roleLabel(r) }}</option>
      </select>
      <select v-model="runFilter" class="input-field">
        <option value="">{{ $t("history.filter_all_runs") }}</option>
        <option v-for="r in runs" :key="r.id" :value="r.id">{{ runLabel(r) }}</option>
      </select>
      <select v-model="typeFilter" class="input-field">
        <option value="">{{ $t("history.filter_all_types") }}</option>
        <option value="thinking">{{ $t("history.type_thinking") }}</option>
        <option value="action">{{ $t("history.type_action") }}</option>
        <option value="tool">{{ $t("history.type_tool") }}</option>
      </select>
      <input
        v-model="searchQuery"
        class="input-field search-field"
        :placeholder="$t('history.filter_search')"
      />
    </div>

    <div class="row gap-low scroll-controls">
      <button
        class="button border"
        :disabled="loading || offset <= 0"
        @click="loadOlder"
      >
        {{ $t("history.load_older") }}
      </button>
      <span class="text-gray count-label">{{ rangeLabel }}</span>
      <button
        class="button border"
        :disabled="loading || !hasMoreNewer"
        @click="loadNewer"
      >
        {{ $t("history.load_newer") }}
      </button>
      <span class="scroll-controls-spacer" />
      <div
        class="button border icon-button"
        :title="$t('history.scroll_to_top')"
        @click="logListRef?.scrollToTop()"
      >
        <span class="material-icons-outlined">vertical_align_top</span>
      </div>
      <div
        class="button border icon-button"
        :title="$t('history.scroll_to_bottom')"
        @click="logListRef?.scrollToBottom()"
      >
        <span class="material-icons-outlined">vertical_align_bottom</span>
      </div>
    </div>

    <div class="log-list-body">
      <LogEntryList
        ref="logListRef"
        :entries="entries"
        :empty-text="$t('agent_logs.no_logs')"
        :auto-scroll="false"
        :show-date="true"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  getTestSessionLogs,
  getTestSessionRuns,
  type AgentLogResponse,
  type AgentLogType,
  type AgentRunResponse,
} from "@/api";
import LogEntryList from "../reusable/LogEntryList.vue";

const { t: $t } = useI18n();

const props = defineProps<{
  sessionId: string;
  // Set by SessionDetail right after a vector is clicked on the Attack
  // Vectors tab - jumps the role/run filters to that vector's
  // discovered_by_run_id and reloads. A plain prop + watcher (not an
  // exposed imperative method) so this works whether or not this
  // component happens to already be mounted - SessionDetail keeps both
  // tabs mounted (v-show, not v-if) specifically so this state survives
  // switching back and forth.
  jumpToRunId?: string | null;
}>();

const PAGE_SIZE = 200;

type RoleOption = "single_agent" | "orchestrator" | "scouting" | "pentesting" | "reporting";
const ROLE_OPTIONS: RoleOption[] = [
  "single_agent",
  "orchestrator",
  "scouting",
  "pentesting",
  "reporting",
];
const ROLE_LABEL_KEYS: Record<RoleOption, string> = {
  single_agent: "settings.pipeline_mode_single_agent",
  orchestrator: "agent_logs.role_orchestrator",
  scouting: "agent_logs.role_scouting",
  pentesting: "agent_logs.role_pentesting",
  reporting: "agent_logs.role_reporting",
};

function roleLabel(role: string): string {
  return role in ROLE_LABEL_KEYS ? $t(ROLE_LABEL_KEYS[role as RoleOption]) : role;
}

function runLabel(run: AgentRunResponse): string {
  const label = run.role ? roleLabel(run.role) : "?";
  return `${label} (${run.id.slice(0, 8)}…)`;
}

const roleFilter = ref("");
const runFilter = ref("");
const typeFilter = ref<AgentLogType | "">("");
const searchQuery = ref("");

const entries = ref<AgentLogResponse[]>([]);
const total = ref(0);
const offset = ref(0);
const loading = ref(false);
const runs = ref<AgentRunResponse[]>([]);

const logListRef = ref<InstanceType<typeof LogEntryList> | null>(null);

const hasMoreNewer = computed(() => offset.value + entries.value.length < total.value);

const rangeLabel = computed(() => {
  if (total.value === 0) return "0 / 0";
  return `${offset.value + 1}–${offset.value + entries.value.length} / ${total.value}`;
});

async function loadRuns() {
  const result = await getTestSessionRuns({ path: { session_id: props.sessionId } });
  runs.value = result.data ?? [];
}

async function fetchPage(off: number, limit: number) {
  const result = await getTestSessionLogs({
    path: { session_id: props.sessionId },
    query: {
      role: roleFilter.value || undefined,
      agent_run_id: runFilter.value || undefined,
      type: (typeFilter.value || undefined) as AgentLogType | undefined,
      q: searchQuery.value || undefined,
      limit,
      offset: off,
    },
  });

  if (result.error || result.data === undefined) {
    throw new Error("Could not load session logs");
  }

  return result.data;
}

// Resets to the LAST page of the current filters - a finished session is
// usually opened to see how it ended, not how it started; "Load older
// entries" walks backward from there.
async function resetAndLoadLast() {
  loading.value = true;
  try {
    const probe = await fetchPage(0, PAGE_SIZE);

    if (probe.total <= PAGE_SIZE) {
      entries.value = probe.items;
      offset.value = 0;
      total.value = probe.total;
    } else {
      const lastOffset = Math.max(0, probe.total - PAGE_SIZE);
      const last = await fetchPage(lastOffset, PAGE_SIZE);
      entries.value = last.items;
      offset.value = lastOffset;
      total.value = last.total;
    }
  } catch (err) {
    console.error(err);
    entries.value = [];
    total.value = 0;
    offset.value = 0;
  } finally {
    loading.value = false;
  }

  await nextTick();
  logListRef.value?.scrollToBottom();
}

async function loadOlder() {
  if (loading.value || offset.value <= 0) return;
  loading.value = true;

  const newOffset = Math.max(0, offset.value - PAGE_SIZE);
  const fetchLimit = offset.value - newOffset;

  try {
    const page = await fetchPage(newOffset, fetchLimit);
    // Prepending shifts everything already on screen further down the
    // DOM without moving scrollTop - compensate so the entries the user
    // was already looking at stay in view instead of jumping.
    const heightBefore = logListRef.value?.getScrollHeight() ?? 0;
    const scrollTopBefore = logListRef.value?.getScrollTop() ?? 0;

    entries.value = [...page.items, ...entries.value];
    offset.value = newOffset;
    total.value = page.total;

    await nextTick();
    const heightAfter = logListRef.value?.getScrollHeight() ?? 0;
    logListRef.value?.setScrollTop(scrollTopBefore + (heightAfter - heightBefore));
  } finally {
    loading.value = false;
  }
}

async function loadNewer() {
  if (loading.value || !hasMoreNewer.value) return;
  loading.value = true;

  const nextOffset = offset.value + entries.value.length;

  try {
    const page = await fetchPage(nextOffset, PAGE_SIZE);
    entries.value = [...entries.value, ...page.items];
    total.value = page.total;
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  loadRuns();
  resetAndLoadLast();
});

watch([roleFilter, runFilter, typeFilter], resetAndLoadLast);

let searchDebounce: ReturnType<typeof setTimeout> | undefined;
watch(searchQuery, () => {
  if (searchDebounce) clearTimeout(searchDebounce);
  searchDebounce = setTimeout(resetAndLoadLast, 350);
});

watch(
  () => props.jumpToRunId,
  (runId) => {
    if (!runId) return;
    roleFilter.value = "";
    runFilter.value = runId;
  },
);
</script>

<style scoped lang="css">
.session-logs {
  flex: 1;
  min-height: 0;
}

.filter-bar {
  padding: 10px 10px 0 10px;
  flex-wrap: wrap;
}

.filter-bar .input-field {
  flex: 1;
  min-width: 120px;
}

.search-field {
  flex: 2;
  min-width: 160px;
}

.scroll-controls {
  padding: 8px 10px;
  align-items: center;
}

.count-label {
  font-size: 0.8rem;
  white-space: nowrap;
}

.scroll-controls-spacer {
  flex: 1;
}

.icon-button {
  width: 28px;
  height: 28px;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}

.icon-button .material-icons-outlined {
  font-size: 18px;
}

.log-list-body {
  flex: 1;
  min-height: 0;
  display: flex;
}
</style>
