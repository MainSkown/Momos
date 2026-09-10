<template>
  <div
    class="border ai-box column"
    :class="{ 'is-selected': selected }"
    @click="emits('select')"
  >
    <button
      v-if="!isBeingDownloaded()"
      class="button action-button"
      :class="installed ? 'action-button-delete' : 'action-button-add'"
      type="button"
      :aria-label="installed ? 'Delete model' : 'Install model'"
      :title="installed ? 'Delete model' : 'Install model'"
      @click.stop="
        async () => {
          if (!installed) await store.downloadModel(model.name);
          else toDelete = true;
        }
      "
    >
      <span class="material-icons-outlined">
        {{ installed ? "delete_outline" : "download" }}
      </span>
    </button>
    <span class="text-bold model-name">{{ model.name }}</span>
    <div class="model-meta-group">
      <div class="model-meta-short-row">
        <span class="model-meta model-meta-short"
          >{{ model.parameters_size_b.toFixed(1) }}B</span
        >
        <span class="model-meta model-meta-short"
          >{{ model.size_gb.toFixed(1) }}GB</span
        >
        <span class="model-meta model-meta-short"
          >{{ model.context_window / 1000 }}K</span
        >
        <span
          v-if="model.thinking"
          class="model-meta model-meta-short material-icons-outlined"
          >psychology</span
        >
      </div>
      <div class="model-meta-expanded">
        <span class="model-meta model-meta-full"
          >Parameters: {{ model.parameters_size_b.toFixed(1) }}B</span
        >
        <span class="model-meta model-meta-full"
          >Size: {{ model.size_gb.toFixed(1) }}GB</span
        >
        <span class="model-meta model-meta-full"
          >Context window: {{ model.context_window / 1000 }}K</span
        >
        <span v-if="model.thinking" class="model-meta model-meta-full"
          >Thinking</span
        >
      </div>
      <div v-if="isBeingDownloaded()">
        <progress
          :value="store.getQueueObjectCompletion(model.name).completed"
          :max="store.getQueueObjectCompletion(model.name).total"
        />
      </div>
    </div>

    <Dialog
      v-if="toDelete"
      :visible="toDelete"
      :title="$t('targets.to_delete')"
      :no-close-button="true"
    >
      <span class="text-center flex-center" style="margin-bottom: 20px">{{
        $t("targets.delete_info")
      }}</span>
      <div class="row flex-center gap-high" style="padding-inline: 10px">
        <button
          class="button border"
          style="flex-grow: 1"
          @click="
            {
              _deleteModel();
              toDelete = false;
            }
          "
        >
          <span>{{ $t("universal.yes") }}</span>
        </button>
        <button
          class="button border"
          style="flex-grow: 1"
          @click="toDelete = false"
        >
          <span>{{ $t("universal.no") }}</span>
        </button>
      </div>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { type OllamaModelData } from "@/api/types.gen";
import { useMomosStore } from "@/store/momos_store";
import { ref, watch } from "vue";
import Dialog from "../reusable/Dialog.vue";
import { deleteModel } from "@/api";
import { toast } from "vue3-toastify";
import { useI18n } from "vue-i18n";

const store = useMomosStore();
const { t: $t } = useI18n();

const toDelete = ref<boolean>(false);

const emits = defineEmits(["deleted", "download-finished", "select"]);

const props = withDefaults(
  defineProps<{
    model: OllamaModelData;
    installed: boolean;
    selected?: boolean;
  }>(),
  {
    selected: false,
  },
);

async function _deleteModel() {
  if (props.installed) {
    const result = await deleteModel({
      body: { model_name: props.model.name },
    });

    if (result.response?.status === 200) {
      toast.success($t("Deleted"), {
        position: toast.POSITION.TOP_CENTER,
      });
      emits("deleted");
    }
  }
}

function isBeingDownloaded() {
  return store.download_queue.some((q) => q.model_name === props.model.name);
}

watch(
  () => isBeingDownloaded(),
  (newVal, oldVal) => {
    if (newVal === false && oldVal === true) {
      emits("download-finished");
    }
  },
);
</script>

<style lang="css" scoped>
.ai-box {
  position: relative;
  padding: 10px;
  gap: 6px;
  justify-content: flex-start;
  transition:
    box-shadow var(--transition-normal),
    transform var(--transition-normal),
    border-color var(--transition-normal),
    background-color var(--transition-normal),
    max-height var(--transition-normal);
  width: fit-content;
  max-width: 100%;
  align-self: flex-start;
  min-width: 160px;
  box-sizing: border-box;
  overflow: hidden;
  transform-origin: center;
  padding-bottom: 10px;
  cursor: pointer;
}

.ai-box.is-selected {
  border-color: var(--active-bg);
  background-color: var(--hover-bg);
  box-shadow: var(--shadow-red-medium);
}

.ai-box:hover {
  transform: translateY(-1px);
  max-height: 220px;
  box-shadow: var(--shadow-red-medium);
  border-color: var(--border-secondary);
  background-color: var(--hover-bg);
  padding-right: 50px;
}

.action-button {
  position: absolute;
  right: 8px;
  bottom: 8px;
  width: 30px;
  height: 30px;
  opacity: 0;
  transform: scale(0.85) translateY(-2px);
  pointer-events: none;
  transition:
    opacity var(--transition-normal),
    transform var(--transition-normal),
    border-color var(--transition-normal),
    background-color var(--transition-normal),
    color var(--transition-normal);
  z-index: 1;
}

.action-button:hover {
  filter: brightness(1.08);
}

.ai-box:hover .action-button {
  opacity: 1;
  transform: scale(1) translateY(0);
  pointer-events: auto;
}

.action-button-add {
  color: var(--status-success);
  border-color: rgba(34, 197, 94, 0.45);
}

.action-button-delete {
  color: var(--status-critical);
  border-color: rgba(219, 18, 18, 0.45);
}

.action-button-add:hover {
  background-color: rgba(34, 197, 94, 0.12);
  border-color: rgba(34, 197, 94, 0.45);
}

.action-button-delete:hover {
  background-color: rgba(219, 18, 18, 0.12);
  border-color: rgba(219, 18, 18, 0.45);
}

.model-name {
  display: block;
}

.model-meta-group {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.model-meta-short-row,
.model-meta-expanded {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  transition:
    opacity var(--transition-normal),
    transform var(--transition-normal),
    max-height var(--transition-normal),
    margin-top var(--transition-normal);
  will-change: opacity, transform;
}

.model-meta-short-row {
  opacity: 1;
  transform: translateY(0);
  max-height: 28px;
  overflow: hidden;
}

.model-meta-expanded {
  max-height: 0;
  overflow: hidden;
  margin-top: 0;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
  opacity: 0;
  transform: translateY(6px);
  pointer-events: none;
}

.model-meta {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 2px 6px;
  border: 1px solid var(--border-primary);
  border-radius: 999px;
  font-size: 0.72rem;
  line-height: 1;
  white-space: nowrap;
}

.model-meta-short {
  flex: 0 0 auto;
}

.model-meta-full {
  width: 90%;
  justify-content: flex-start;
}

.ai-box:hover .model-meta-short-row {
  opacity: 0;
  transform: translateY(-4px);
  max-height: 0;
}

.ai-box:hover .model-meta-expanded {
  max-height: 120px;
  margin-top: 2px;
  opacity: 1;
  transform: translateY(0);
  pointer-events: auto;
}
</style>
