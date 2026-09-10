<template>
  <div class="border" style="padding-bottom: 5px">
    <span class="text-red" style="padding-left: 10px">
      {{ $t("targets.targets") }}</span
    >
    <div class="separator" />
    <!-- Input box-->
    <div class="row">
      <div class="terminal-input-group" style="margin: 5px; width: 100%">
        <input
          v-model="target"
          class="input-field"
          :placeholder="$t('targets.enter_name')"
          @keydown.enter="addTarget"
        />
      </div>
      <div class="add-button button border" @click="addTarget">+</div>
    </div>

    <!-- Table -->
    <div class="flex flex-center">
      <div class="column table">
        <!-- Head-row -->
        <div class="row table-row">
          <!-- Name -->
          <div class="border cell text-center">
            <span>{{ $t("targets.name") }}</span>
          </div>
          <!-- Target -->
          <div class="border cell text-center">
            <span>{{ $t("targets.target") }}</span>
          </div>
          <!-- Settings -->
          <div class="border small-cell" />
          <div class="border small-cell" />
          <div class="border small-cell" />
        </div>

        <!-- Target Rows -->
        <div
          class="column scrollable-panel"
          style="max-height: 200px; width: 100%"
        >
          <div
            class="row table-row"
            v-for="t in store.getProjectsTargets(store.openedProject)"
          >
            <div class="border cell text-center truncate-text">
              <span>{{ t.name }}</span>
            </div>
            <div class="border cell text-center">
              <span>{{ getTarget(t) || $t("targets.no_target") }} </span>
            </div>

            <!-- Start target scan -->
            <div class="border small-cell">
              <button
                class="button no-border"
                :disabled="t.task_duration === null && t.task_duration === 0"
              >
                <span
                  v-if="t.task_duration !== null && t.task_duration > 0"
                  class="material-icons-outlined"
                >
                  play_arrow
                </span>
                <Tooltip
                  v-else
                  :message="$t('targets.duration_required')"
                >
                  <span class="material-icons-outlined"> timer_off </span>
                </Tooltip>
              </button>
            </div>

            <!-- Settings button -->
            <div class="button border small-cell" @click="showDialogFor = t.id">
              <span class="material-icons-outlined" data-fallback="✕">
                settings
              </span>
            </div>

            <!-- Delete button-->
            <div class="button border small-cell" @click="toDelete = t.id">
              <span class="material-icons-outlined" data-fallback="✕">
                delete_outline
              </span>

              <Dialog
                v-if="toDelete === t.id"
                :visible="toDelete === t.id"
                :title="$t('targets.to_delete')"
                :no-close-button="true"
              >
                <span
                  class="text-center flex-center"
                  style="margin-bottom: 20px"
                  >{{ $t("targets.delete_info") }}</span
                >
                <div
                  class="row flex-center gap-high"
                  style="padding-inline: 10px"
                >
                  <button
                    class="button border"
                    style="flex-grow: 1"
                    @click="
                      deleteTarget(toDelete);
                      toDelete = '';
                    "
                  >
                    <span>{{ $t("universal.yes") }}</span>
                  </button>
                  <button
                    class="button border"
                    style="flex-grow: 1"
                    @click="toDelete = ''"
                  >
                    <span>{{ $t("universal.no") }}</span>
                  </button>
                </div>
              </Dialog>
            </div>

            <!-- Settings Dialog -->
            <TargetSettingsDialog
              v-if="showDialogFor == t.id"
              :visible="showDialogFor == t.id"
              @update:visible="
                (v) => {
                  if (!v) showDialogFor = '';
                }
              "
              :target="t"
            />
          </div>

          <div
            class="border text-center"
            v-if="store.getProjectsTargets(store.openedProject).length === 0"
          >
            {{ $t("targets.no_targets") }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { useMomosStore } from "@/store/momos_store";
import { getTarget } from "@/types";
import { toast } from "vue3-toastify";
import { useI18n } from "vue-i18n";
import TargetSettingsDialog from "./TargetSettingsDialog.vue";
import Dialog from "../reusable/Dialog.vue";
import Tooltip from "../reusable/Tooltip.vue";

const { t: $t } = useI18n();
const store = useMomosStore();

const showDialogFor = ref<string>("");
const toDelete = ref<string>("");

function loadTargets() {
  store.loadTargets(store.openedProject);
}

onMounted(() => {
  loadTargets();
});

// Load targets when opened project changes
watch(
  () => store.openedProject,
  (newProject, oldProject) => {
    if (newProject !== oldProject) {
      store.loadTargets(store.openedProject);
    }
  },
);

const target = ref<string>("");

function addTarget() {
  const name = target.value;

  if (name.length === 0) {
    toast.error($t("targets.name_empty"), {
      position: toast.POSITION.TOP_CENTER,
    });
  }

  store.addTarget2Project(name, store.openedProject);
  target.value = "";
}

function deleteTarget(id: string) {
  store.deleteTarget(id);
}
</script>

<style scoped lang="css">
.input-field {
  width: 100%;
}

.add-button {
  aspect-ratio: 1;
  width: 5%;

  font-size: x-large;
  margin: 5px;
}

.table {
  width: calc(100% - 10px);
}

.table-row {
  display: flex;
  width: 100%;
}

.table-row > div {
  margin-left: -1px;
}

.table-row > div:first-child {
  margin-left: 0;
}

.cell {
  flex: 1 1 0px;
  padding: 5px 8px;
  min-width: 0;
}

.small-cell {
  flex: 0 0 40px;
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>
