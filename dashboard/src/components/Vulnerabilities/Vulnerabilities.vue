<template>
  <div class="column layout-container">
    <!-- Filter bar -->
    <div class="row gap-low filter-bar">
      <input
        v-model="nameFilter"
        class="input-field"
        :placeholder="$t('vulnerabilities.filter_name')"
      />
      <select v-model="targetFilter" class="input-field">
        <option value="">{{ $t("vulnerabilities.filter_all_targets") }}</option>
        <option v-for="t in projectTargets" :key="t.id" :value="t.id">
          {{ t.name }}
        </option>
      </select>
      <select v-model="modelFilter" class="input-field">
        <option value="">{{ $t("vulnerabilities.filter_all_models") }}</option>
        <option v-for="m in distinctModels" :key="m" :value="m">{{ m }}</option>
      </select>
      <input
        type="date"
        v-model="dateFrom"
        class="input-field"
        :title="$t('vulnerabilities.filter_date_from')"
      />
      <input
        type="date"
        v-model="dateTo"
        class="input-field"
        :title="$t('vulnerabilities.filter_date_to')"
      />
    </div>

    <div class="column gap-low scrollable-panel vuln-list">
      <VulnerabilityCard
        v-for="v in filteredVulnerabilities"
        :key="v.id"
        :vulnerability="v"
        :target-name="targetName(v.found_in)"
        @updated="onUpdated"
        @deleted="onDeleted"
      />

      <div
        class="text-center no-vulns"
        v-if="filteredVulnerabilities.length === 0"
      >
        {{ $t("vulnerabilities.no_vulnerabilities") }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useMomosStore } from "@/store/momos_store";
import { getAllVulnerabilitiesInProject } from "@/api";
import type { tVulnerability } from "@/types";
import VulnerabilityCard from "./VulnerabilityCard.vue";

const { t: $t } = useI18n();
const store = useMomosStore();

const vulnerabilities = ref<tVulnerability[]>([]);

async function loadVulnerabilities(project_id: string) {
  if (!project_id) {
    vulnerabilities.value = [];
    return;
  }

  const result = await getAllVulnerabilitiesInProject({ path: { project_id } });
  vulnerabilities.value = result.data ?? [];
}

onMounted(() => {
  loadVulnerabilities(store.openedProject);
  store.loadTargets(store.openedProject);
});

watch(
  () => store.openedProject,
  (newProject) => {
    loadVulnerabilities(newProject);
    store.loadTargets(newProject);
  },
);

const projectTargets = computed(() => store.getProjectsTargets(store.openedProject));

function targetName(targetId: string): string {
  return projectTargets.value.find((t) => t.id === targetId)?.name ?? targetId;
}

const nameFilter = ref("");
const targetFilter = ref("");
const modelFilter = ref("");
const dateFrom = ref("");
const dateTo = ref("");

const distinctModels = computed(() => {
  const models = new Set<string>();
  for (const v of vulnerabilities.value) {
    if (v.found_by_model) models.add(v.found_by_model);
  }
  return [...models].sort();
});

const filteredVulnerabilities = computed(() => {
  return vulnerabilities.value
    .filter((v) => {
      if (
        nameFilter.value &&
        !v.name.toLowerCase().includes(nameFilter.value.toLowerCase())
      )
        return false;

      if (targetFilter.value && v.found_in !== targetFilter.value) return false;
      if (modelFilter.value && v.found_by_model !== modelFilter.value) return false;

      // Date-only comparison against the UTC date portion of an ISO
      // timestamp - close enough for a coarse filter, not meant to be
      // timezone-exact around midnight.
      const createdDate = v.created_at.slice(0, 10);
      if (dateFrom.value && createdDate < dateFrom.value) return false;
      if (dateTo.value && createdDate > dateTo.value) return false;

      return true;
    })
    .sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
});

function onUpdated(updated: tVulnerability) {
  const idx = vulnerabilities.value.findIndex((v) => v.id === updated.id);
  if (idx !== -1) vulnerabilities.value[idx] = updated;
}

function onDeleted(id: string) {
  vulnerabilities.value = vulnerabilities.value.filter((v) => v.id !== id);
}
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

.vuln-list {
  flex: 1;
  min-height: 0;
  padding: 0 10px 10px 10px;
}

.no-vulns {
  color: var(--text-gray-dark);
  margin-top: auto;
  margin-bottom: auto;
}
</style>
