<template>
  <Dialog v-model:visible="visible" :title="title">
    <div class="model-picker-body">
      <AISettings
        selectable
        :selected-model-name="selectedModelName"
        @select="onSelect"
      />
    </div>
  </Dialog>

  <Dialog
    v-model:visible="showDownloadConfirm"
    title="Model not installed"
    :no-close-button="true"
  >
    <span class="text-center flex-center" style="margin-bottom: 20px">
      "{{ pendingModel?.name }}" is not installed. Download it now and use it
      once ready?
    </span>
    <div class="row flex-center gap-high" style="padding-inline: 10px">
      <button
        class="button border"
        style="flex-grow: 1"
        @click="confirmDownload"
      >
        <span>Yes</span>
      </button>
      <button
        class="button border"
        style="flex-grow: 1"
        @click="cancelDownload"
      >
        <span>No</span>
      </button>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, watch } from "vue";
import { toast } from "vue3-toastify";
import Dialog from "@/components/reusable/Dialog.vue";
import AISettings from "@/components/Settings/AISettings.vue";
import { type OllamaModelData } from "@/api/types.gen";
import { aiModelsManager } from "@/components/tools";
import { useMomosStore } from "@/store/momos_store";

const store = useMomosStore();

defineProps<{
  title: string;
  selectedModelName?: string | null;
}>();

const visible = defineModel<boolean>("visible", { default: false });

const emits = defineEmits<{
  select: [model: OllamaModelData];
}>();

const showDownloadConfirm = ref(false);
const pendingModel = ref<OllamaModelData | null>(null);

function onSelect(model: OllamaModelData) {
  if (aiModelsManager.isInstalled(model.name)) {
    visible.value = false;
    emits("select", model);
    return;
  }

  pendingModel.value = model;
  showDownloadConfirm.value = true;
}

function cancelDownload() {
  showDownloadConfirm.value = false;
  pendingModel.value = null;
}

async function confirmDownload() {
  const model = pendingModel.value;
  showDownloadConfirm.value = false;
  pendingModel.value = null;
  visible.value = false;

  if (model === null) return;

  const alreadyDownloading = store.download_queue.some(
    (q) => q.model_name === model.name,
  );

  if (!alreadyDownloading) {
    try {
      await store.downloadModel(model.name);
    } catch (error) {
      console.error("Failed to start model download:", error);
      toast.error(`Failed to download model "${model.name}"`, {
        position: toast.POSITION.TOP_CENTER,
      });
      return;
    }
  }

  toast.info(`Downloading "${model.name}" in the background...`, {
    position: toast.POSITION.TOP_CENTER,
  });

  const stopWatch = watch(
    () => store.download_queue.some((q) => q.model_name === model.name),
    (isQueued, wasQueued) => {
      if (wasQueued && !isQueued) {
        stopWatch();
        aiModelsManager.refreshInstalledModels();
        emits("select", model);
        toast.success(`"${model.name}" downloaded and selected`, {
          position: toast.POSITION.TOP_CENTER,
        });
      }
    },
  );
}
</script>

<style scoped>
.model-picker-body {
  width: 85vw;
  height: 80vh;
}
</style>
