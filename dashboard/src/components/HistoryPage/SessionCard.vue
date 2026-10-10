<template>
  <div class="border session-card session-card-clickable" @click="emit('select', session.id)">
    <div
      class="button border action-button"
      :class="{ 'action-button-disabled': session.outcome === 'running' }"
      :title="
        session.outcome === 'running'
          ? $t('history.delete_running_disabled')
          : $t('history.delete')
      "
      @click.stop="onDeleteClick"
    >
      <span class="material-icons-outlined" data-fallback="✕">delete_outline</span>
    </div>

    <div class="row gap-low session-card-header">
      <span class="text-bold text-white truncate-text">{{ targetName }}</span>
      <span class="tag border" :class="outcomeClass">
        <span v-if="session.outcome === 'running'" class="running-dot" />
        {{ outcomeLabel }}
      </span>
    </div>

    <div class="row gap-low text-gray session-card-meta">
      <span>{{ formattedStartedAt }}</span>
      <span>·</span>
      <span>{{ $t("history.active_duration") }}: {{ formattedActiveDuration }}</span>
    </div>

    <Dialog
      v-if="confirmDelete"
      :visible="confirmDelete"
      :title="$t('history.to_delete')"
      :no-close-button="true"
    >
      <span class="text-center flex-center" style="margin-bottom: 20px">
        {{ $t("history.delete_info") }}
      </span>
      <div class="row flex-center gap-high" style="padding-inline: 10px">
        <button
          class="button border"
          style="flex-grow: 1"
          :disabled="deleting"
          @click.stop="onDelete"
        >
          <span>{{ $t("universal.yes") }}</span>
        </button>
        <button
          class="button border"
          style="flex-grow: 1"
          :disabled="deleting"
          @click.stop="confirmDelete = false"
        >
          <span>{{ $t("universal.no") }}</span>
        </button>
      </div>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { toast } from "vue3-toastify";
import { useMomosStore } from "@/store/momos_store";
import type { TestSessionResponse } from "@/api";
import Dialog from "../reusable/Dialog.vue";
import { formatDuration, OUTCOME_CLASS, OUTCOME_LABEL_KEYS } from "./historyUtils";

const { t: $t } = useI18n();
const store = useMomosStore();

const props = defineProps<{
  session: TestSessionResponse;
  targetName: string;
}>();

const emit = defineEmits<{
  select: [sessionId: string];
  deleted: [sessionId: string];
}>();

const confirmDelete = ref(false);
const deleting = ref(false);

// outcome/started_at/active_seconds are typed optional by the generator
// (they have server-side defaults, so OpenAPI marks them "not required"),
// but a real response always sets them - the fallbacks below exist only
// to satisfy the type checker, not because these are ever actually
// missing in practice.
const outcome = computed(() => props.session.outcome ?? "running");
const outcomeLabel = computed(() => $t(OUTCOME_LABEL_KEYS[outcome.value]));
const outcomeClass = computed(() => OUTCOME_CLASS[outcome.value]);
const formattedStartedAt = computed(() =>
  new Date(props.session.started_at ?? "").toLocaleString(),
);
const formattedActiveDuration = computed(() =>
  formatDuration(props.session.active_seconds ?? 0, $t),
);

function onDeleteClick() {
  if (outcome.value === "running") return;
  confirmDelete.value = true;
}

async function onDelete() {
  if (deleting.value) return;
  deleting.value = true;

  try {
    await store.deleteSession(props.session.id);
    toast.success($t("history.delete_success"), {
      position: toast.POSITION.TOP_CENTER,
    });
    confirmDelete.value = false;
    emit("deleted", props.session.id);
  } catch (err) {
    console.error("Could not delete session:", err);
    toast.error($t("history.delete_failed"), {
      position: toast.POSITION.TOP_CENTER,
    });
  } finally {
    deleting.value = false;
  }
}
</script>

<style scoped lang="css">
.session-card {
  position: relative;
  padding: 10px;
  padding-right: 40px;
  border-color: var(--border-subtle);
}

.session-card-clickable {
  cursor: pointer;
}

.session-card-clickable:hover {
  background: var(--hover-bg);
}

.action-button {
  position: absolute;
  top: 8px;
  right: 8px;
  width: 22px;
  height: 22px;
  padding: 0;
}

.action-button .material-icons-outlined {
  font-size: 16px;
}

.action-button-disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.session-card-header {
  align-items: center;
  justify-content: space-between;
}

.session-card-meta {
  margin-top: 4px;
  font-size: 0.8rem;
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
</style>
