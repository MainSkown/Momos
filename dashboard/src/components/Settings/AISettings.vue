<template>
  <div class="full-width ai-settings row">
    <div class="column ai-settings-sidebar">
      <button
        v-for="item in staticFilters"
        :key="item.id"
        type="button"
        class="button no-border ai-filter-button"
        :class="{ 'is-active': activeFilter === item.id }"
        :data-filter-id="item.id"
        @click="activeFilter = item.id"
      >
        <span class="ai-filter-label">{{ $t(item.labelKey) }}</span>
        <span class="ai-filter-count">{{ item.count }}</span>
      </button>

      <div class="separator ai-filter-divider" />

      <button
        v-for="item in familyFilters"
        :key="item.id"
        type="button"
        class="button no-border ai-filter-button"
        :class="{ 'is-active': activeFilter === item.id }"
        :data-filter-id="item.id"
        @click="activeFilter = item.id"
      >
        <span class="ai-filter-label">{{ item.label }}</span>
        <span class="ai-filter-count">{{ item.count }}</span>
      </button>
    </div>

    <div class="column full-width ai-settings-main">
      <ConnectionSettings v-if="!props.selectable" />

      <div class="row ai-settings-toolbar">
        <input
          v-model="searchQuery"
          class="input-field border ai-settings-search-input"
          :placeholder="$t('models.search_placeholder')"
        />
      </div>

      <div class="scrollable-panel ai-settings-grid-wrapper" style="max-height: 75vh">
        <div v-if="filteredModels.length === 0" class="ai-settings-empty">
          {{ $t("models.no_search_results") }}
        </div>
        <div v-else class="suggestions-list">
          <AIBox
            v-for="model in filteredModels"
            :key="model.name"
            :model="model"
            :installed="model.installed"
            :selected="isSelected(model.name)"
            @deleted="refreshInstalledModels"
            @download-finished="refreshInstalledModels"
            @select="onSelect(model)"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { aiModelsManager } from "../tools";
import AIBox from "./AIBox.vue";
import ConnectionSettings from "./ConnectionSettings.vue";
import { type OllamaModelData } from "@/api/types.gen";
import { useI18n } from "vue-i18n";

type MergedModel = OllamaModelData & { installed: boolean };
type FilterId = "all" | "installed" | "recommended_agent" | "recommended_parsing" | `family:${string}`;

const props = withDefaults(
  defineProps<{
    selectable?: boolean;
    selectedModelName?: string | null;
  }>(),
  {
    selectable: false,
    selectedModelName: null,
  },
);

const emits = defineEmits<{
  select: [model: OllamaModelData];
}>();

const { t: $t } = useI18n();

const searchQuery = ref("");
const activeFilter = ref<FilterId>("all");

// Merge by name, preferring the catalog (downloadable_models) entry's
// metadata - it carries the `recommended` tag the installed-only entry
// never does - so a model that's both recommended and installed never
// loses that tag just because it's also present in installed_models.
const mergedModels = computed<MergedModel[]>(() => {
  const installedNames = new Set(
    aiModelsManager.installed_models.value.map((model) => model.name),
  );

  const merged: MergedModel[] = aiModelsManager.downloadable_models.value.map((model) => ({
    ...model,
    installed: installedNames.has(model.name),
  }));

  const catalogNames = new Set(merged.map((model) => model.name));
  for (const model of aiModelsManager.installed_models.value) {
    if (!catalogNames.has(model.name)) {
      merged.push({ ...model, installed: true });
    }
  }

  return merged;
});

const families = computed(() =>
  Array.from(new Set(mergedModels.value.map((model) => model.family))).sort((a, b) =>
    a.localeCompare(b),
  ),
);

const staticFilters = computed(() => [
  {
    id: "all" as FilterId,
    labelKey: "models.all_models",
    count: mergedModels.value.length,
  },
  {
    id: "installed" as FilterId,
    labelKey: "models.installed",
    count: mergedModels.value.filter((model) => model.installed).length,
  },
  {
    id: "recommended_agent" as FilterId,
    labelKey: "models.recommended_agent",
    count: mergedModels.value.filter((model) => model.recommended === "agent").length,
  },
  {
    id: "recommended_parsing" as FilterId,
    labelKey: "models.recommended_parsing",
    count: mergedModels.value.filter((model) => model.recommended === "parsing").length,
  },
]);

const familyFilters = computed(() =>
  families.value.map((family) => ({
    id: `family:${family}` as FilterId,
    label: family,
    count: mergedModels.value.filter((model) => model.family === family).length,
  })),
);

const filteredModels = computed<MergedModel[]>(() => {
  let list = mergedModels.value;

  if (activeFilter.value === "installed") {
    list = list.filter((model) => model.installed);
  } else if (activeFilter.value === "recommended_agent") {
    list = list.filter((model) => model.recommended === "agent");
  } else if (activeFilter.value === "recommended_parsing") {
    list = list.filter((model) => model.recommended === "parsing");
  } else if (activeFilter.value.startsWith("family:")) {
    const family = activeFilter.value.slice("family:".length);
    list = list.filter((model) => model.family === family);
  }

  const query = searchQuery.value.trim().toLowerCase();
  if (query.length > 0) {
    list = list.filter((model) => model.name.toLowerCase().includes(query));
  }

  return [...list].sort((a, b) => a.parameters_size_b - b.parameters_size_b);
});

function onSelect(model: OllamaModelData) {
  if (props.selectable) {
    emits("select", model);
  }
}

function isSelected(modelName: string): boolean {
  return props.selectable && props.selectedModelName === modelName;
}

async function refreshInstalledModels() {
  await aiModelsManager.refreshInstalledModels();
}

onMounted(async () => {
  await aiModelsManager.initialize();
});
</script>

<style lang="css" scoped>
.ai-settings {
  align-items: stretch;
  gap: 0;
  min-width: 0;
}

.ai-settings-sidebar {
  flex-shrink: 0;
  width: 220px;
  border-right: 2px solid var(--border-primary);
  padding-right: 10px;
  margin-right: 10px;
  gap: 2px;
}

.ai-filter-button {
  justify-content: space-between;
  white-space: nowrap;
  padding: 6px 10px;
}

.ai-filter-label {
  overflow: hidden;
  text-overflow: ellipsis;
}

.ai-filter-count {
  opacity: 0.7;
  font-size: 0.8rem;
  flex-shrink: 0;
  margin-left: 8px;
}

.ai-filter-divider {
  margin-block: 6px;
}

.ai-settings-main {
  min-width: 0;
}

.ai-settings-toolbar {
  gap: 10px;
  align-items: center;
  margin-bottom: 10px;
}

.ai-settings-search-input {
  flex: 1;
}

.ai-settings-empty {
  opacity: 0.7;
  padding: 20px 0;
  text-align: center;
}

.suggestions-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

/* Below this width the dialog itself (SettingsDialog's .settings) no
   longer has room for a fixed-width side rail next to the grid - the
   sidebar becomes a horizontally-scrollable chip row instead of
   disappearing or overlapping the model grid. */
@media (max-width: 700px) {
  .ai-settings {
    flex-direction: column;
  }

  .ai-settings-sidebar {
    width: 100%;
    flex-direction: row;
    overflow-x: auto;
    border-right: none;
    border-bottom: 2px solid var(--border-primary);
    padding-right: 0;
    padding-bottom: 8px;
    margin-right: 0;
    margin-bottom: 10px;
  }

  .ai-filter-divider {
    width: 1px;
    height: auto;
    align-self: stretch;
    margin-inline: 4px;
  }
}
</style>
