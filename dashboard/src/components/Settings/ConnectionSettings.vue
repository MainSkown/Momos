<template>
  <div class="column gap-mid full-width connection-settings">
    <span v-if="loadError" class="text-red">{{ $t("settings.connection_load_error") }}</span>

    <div class="border settings-card column">
      <div
        class="row connection-header"
        role="button"
        tabindex="0"
        @click="toggleExpanded"
        @keydown.enter="toggleExpanded"
        @keydown.space.prevent="toggleExpanded"
      >
        <div class="row gap-low connection-header-text">
          <span class="text-red settings-card-title">{{ $t("settings.section_connection") }}</span>
          <span v-if="!isExpanded" class="connection-summary truncate-text">{{ connectionSummary }}</span>
        </div>
        <span class="material-icons-outlined connection-toggle-icon">
          {{ isExpanded ? "expand_less" : "expand_more" }}
        </span>
      </div>

      <template v-if="isExpanded">
        <div class="separator" />

        <div class="column gap-low settings-card-body">
          <div class="field-group">
            <label class="text-bold">{{ $t("settings.connection_mode") }}</label>
            <div class="radio-group full-width">
              <input
                id="connection-mode-local"
                v-model="mode"
                type="radio"
                value="local"
                class="radio-input"
                :disabled="controlsDisabled"
              />
              <label for="connection-mode-local" class="radio-label">
                {{ $t("settings.connection_mode_local") }}
              </label>

              <input
                id="connection-mode-remote"
                v-model="mode"
                type="radio"
                value="remote"
                class="radio-input"
                :disabled="controlsDisabled"
              />
              <label for="connection-mode-remote" class="radio-label">
                {{ $t("settings.connection_mode_remote") }}
              </label>
            </div>
          </div>

          <template v-if="mode === 'remote'">
            <div class="field-group">
              <label class="text-bold">{{ $t("settings.connection_remote_url_label") }}</label>
              <input
                v-model="remoteUrl"
                class="input-field border full-width remote-url-input"
                :class="{ 'is-invalid': isRemoteUrlEmpty }"
                :placeholder="$t('settings.connection_remote_url_placeholder')"
                :disabled="controlsDisabled"
                spellcheck="false"
              />
            </div>

            <div class="field-group">
              <label class="text-bold">{{ $t("settings.connection_remote_api_key_label") }}</label>
              <input
                v-model="remoteApiKey"
                type="password"
                class="input-field border full-width remote-api-key-input"
                :placeholder="remoteApiKeyPlaceholder"
                :disabled="controlsDisabled"
                spellcheck="false"
                @input="keyTouched = true"
              />
            </div>

            <button
              type="button"
              class="button border test-connection-button"
              :disabled="controlsDisabled || testing || isRemoteUrlEmpty"
              @click="testConnection"
            >
              {{ testing ? $t("settings.connection_testing") : $t("settings.connection_test") }}
            </button>

            <span v-if="testResultText" class="connection-test-result" :class="testResultClass">
              {{ testResultText }}
            </span>
          </template>

          <span v-if="saveError" class="text-red save-error-message">{{ saveError }}</span>

          <button
            type="button"
            class="button border save-connection-button"
            :disabled="controlsDisabled || saving || remoteUrlMissing"
            @click="saveConnection"
          >
            {{ saving ? $t("settings.connection_saving") : $t("settings.connection_save") }}
          </button>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import { updateOllamaConnection, testOllamaConnection } from "@/api";
import type { OllamaConnectionPublic } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import { aiModelsManager } from "@/components/tools";

type ConnectionMode = "local" | "remote";

const store = useMomosStore();
const { t } = useI18n();

const loadError = ref(false);
const isExpanded = ref(false);
const mode = ref<ConnectionMode>("local");
const remoteUrl = ref("");
const remoteApiKey = ref("");
const keyTouched = ref(false);
const hasRemoteApiKey = ref(false);

const saving = ref(false);
const saveError = ref<string | null>(null);
const testing = ref(false);
const testResult = ref<{
  reachable: boolean;
  latency_ms?: number | null;
  error?: string | null;
} | null>(null);

const controlsDisabled = computed(() => loadError.value);

const isRemoteUrlEmpty = computed(() => remoteUrl.value.trim().length === 0);

const remoteUrlMissing = computed(() => mode.value === "remote" && isRemoteUrlEmpty.value);

const remoteApiKeyPlaceholder = computed(() =>
  hasRemoteApiKey.value
    ? t("settings.connection_remote_api_key_placeholder_keep")
    : t("settings.connection_remote_api_key_placeholder"),
);

const connectionSummary = computed(() =>
  mode.value === "remote"
    ? t("settings.connection_status_remote", { url: remoteUrl.value })
    : t("settings.connection_status_local"),
);

const testResultText = computed(() => {
  if (testResult.value === null) return null;

  if (testResult.value.reachable) {
    const ms = Math.round(testResult.value.latency_ms ?? 0);
    return t("settings.connection_reachable", { ms });
  }

  return testResult.value.error
    ? t("settings.connection_unreachable_with_error", { error: testResult.value.error })
    : t("settings.connection_unreachable");
});

const testResultClass = computed(() => (testResult.value?.reachable ? "text-active" : "text-red"));

function toggleExpanded() {
  isExpanded.value = !isExpanded.value;
}

// Mirrors UserOptions.vue's own revert-to-last-saved pattern: resets every
// local field from a freshly loaded/saved connection, including clearing
// the key input - GET/PUT never return the key itself (OllamaConnectionPublic
// only ever carries has_remote_api_key), so the field has nothing to show
// but blank either way.
function applyConnection(connection: OllamaConnectionPublic) {
  mode.value = connection.mode === "remote" ? "remote" : "local";
  remoteUrl.value = connection.remote_url;
  hasRemoteApiKey.value = connection.has_remote_api_key;
  remoteApiKey.value = "";
  keyTouched.value = false;
}

onMounted(async () => {
  try {
    await store.loadOllamaConnection();
  } catch (error) {
    console.error("Failed to load Ollama connection:", error);
    loadError.value = true;
    return;
  }

  if (store.ollama_connection === null) {
    loadError.value = true;
    return;
  }

  applyConnection(store.ollama_connection);
});

function extractErrorDetail(error: unknown): string | undefined {
  if (error && typeof error === "object" && "detail" in error) {
    const detail = (error as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
  }
  return undefined;
}

async function testConnection() {
  if (isRemoteUrlEmpty.value) return;

  testing.value = true;
  testResult.value = null;

  try {
    const result = await testOllamaConnection({
      body: {
        remote_url: remoteUrl.value,
        remote_api_key: keyTouched.value ? remoteApiKey.value : undefined,
      },
    });

    if (result.data !== undefined) {
      testResult.value = result.data;
    }
  } catch (error) {
    console.error("Failed to test Ollama connection:", error);
    testResult.value = { reachable: false, error: t("settings.connection_test_failed") };
  } finally {
    testing.value = false;
  }
}

async function saveConnection() {
  if (remoteUrlMissing.value) return;

  saving.value = true;
  saveError.value = null;

  try {
    const result = await updateOllamaConnection({
      body: {
        mode: mode.value,
        remote_url: remoteUrl.value,
        remote_api_key: keyTouched.value ? remoteApiKey.value : undefined,
      },
    });

    if (result.error || result.data === undefined) {
      saveError.value = extractErrorDetail(result.error) ?? t("settings.connection_save_failed");
      return;
    }

    store.setOllamaConnection(result.data);
    applyConnection(result.data);
    await aiModelsManager.refreshInstalledModels();
    toast.success(t("settings.connection_save_success"));
  } catch (error) {
    console.error("Failed to save Ollama connection:", error);
    saveError.value = t("settings.connection_save_failed");
  } finally {
    saving.value = false;
  }
}
</script>

<style scoped lang="css">
/* Same "titled card" chrome as UserOptions.vue/ProjectSettingsPage.vue's
   own .settings-card/.settings-card-title/.settings-card-body/.field-group -
   copied rather than imported across components (they're scoped there). */
.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.settings-card {
  width: 100%;
  padding-bottom: var(--spacing-md);
}

.settings-card-title {
  padding: 0;
}

.settings-card-body {
  padding: var(--spacing-md) var(--spacing-md) 0;
}

.connection-settings {
  margin-bottom: var(--spacing-md);
}

.connection-header {
  cursor: pointer;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) var(--spacing-md) 0;
}

.connection-header-text {
  align-items: baseline;
  min-width: 0;
  flex: 1;
}

.connection-summary {
  opacity: 0.7;
  font-size: 0.85rem;
  min-width: 0;
}

.connection-toggle-icon {
  flex-shrink: 0;
}

.connection-test-result {
  font-family: var(--font-mono);
  font-size: 0.85rem;
}
</style>
