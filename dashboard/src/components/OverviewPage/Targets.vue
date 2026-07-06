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
    <div class="column table">
      <!-- Head-row -->
      <div class="row table-row">
        <!-- Name -->
        <div class="border cell text-center">{{ $t("targets.name") }}</div>
        <!-- Target -->
        <div class="border cell text-center">{{ $t("targets.target") }}</div>
        <!-- Settings -->
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
          <div class="border cell text-center">
            {{ t.name }}
          </div>
          <div class="border cell text-center">
            {{ getTarget(t) || $t('targets.no_target') }}
          </div>          
          <div class="button border small-cell" @click="deleteTarget(t.id)">
            <span class="material-icons-outlined" data-fallback="✕">
              settings
            </span>
          </div>
          <div class="button border small-cell" @click="deleteTarget(t.id)">
            <span class="material-icons-outlined" data-fallback="✕">
              delete_outline
            </span>
          </div>
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
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { useMomosStore } from "@/store/momos_store";
import {
  domainPattern,
  getTarget,
  ipv4Pattern,
  ipv6Pattern,
  isAddressValid,
  type tAddresses,
} from "@/types";
import { toast } from "vue3-toastify";
import { useI18n } from "vue-i18n";

const { t: $t } = useI18n();
const store = useMomosStore();

function loadTargets(){
  store.loadTargets(store.openedProject)
}

onMounted(() => {
  loadTargets()
})

// Load targets when opened project changes
watch(
  () => store.openedProject,
  (newProject, oldProject) => {
    if (newProject !== oldProject){
      store.loadTargets(store.openedProject)
    }
  }
)

const target = ref<string>("");

const handleIPv4Input = (event: Event): string => {
  const e = event.target as HTMLInputElement;
  let value = e.value;

  // 1. Instantly remove any character that isn't a digit or a dot
  value = value.replace(/[^0-9.]/g, "");

  // 2. Split the string into segments by the dots
  const segments = value.split(".");

  // 3. Sanitize each segment (limit to a max of 4 segments total)
  const cleanedSegments = segments.slice(0, 4).map((segment) => {
    let clean = segment.slice(0, 3);

    if (parseInt(clean, 10) > 255) {
      clean = "255";
    }
    return clean;
  });

  const joinedResult = cleanedSegments.join(".");

  // FORCE THE DOM SYNC: This instantly vanishes illegal characters from the screen
  e.value = joinedResult;

  return joinedResult;
};

const handleIPv6Input = (event: Event): string => {
  const e = event.target as HTMLInputElement;
  let value = e.value;

  // 1. Keep only hex characters and colons (case-insensitive)
  value = value.replace(/[^0-9a-fA-F:]/g, "");

  // 2. Split into segments by colons
  const segments = value.split(":");

  // 3. Max 8 segments total, max 4 characters per segment
  const cleanedSegments = segments.slice(0, 8).map((segment) => {
    return segment.slice(0, 4);
  });

  const joinedResult = cleanedSegments.join(":");

  // Force DOM sync
  e.value = joinedResult;
  return joinedResult;
};

const handleDomainInput = (event: Event): string => {
  const e = event.target as HTMLInputElement;
  let value = e.value;

  // 1. Lowercase it automatically and strip non-domain characters
  value = value.toLowerCase().replace(/[^a-z0-9.-]/g, "");

  // 2. Prevent consecutive dots (e.g., typing 'google..com' instantly becomes 'google.com')
  value = value.replace(/\.{2,}/g, ".");

  // Force DOM sync
  e.value = value;
  return value;
};

function addTarget(){
  const name = target.value

  if (name.length === 0){
    toast.error($t('targets.name_empty'), {position:toast.POSITION.TOP_CENTER})
  }

  store.addTarget2Project(name, store.openedProject)
  target.value = ''
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
  width: 4%;

  font-size: x-large;
  margin: 5px;
}

.table {
  justify-content: center;
  align-items: safe center;
  margin: 5px 5px 0 5px;
  width: 98.8%;
}

.table-row {
  width: 100%;
}

.cell {
  padding-top: 5px;
  padding-bottom: 5px;
  flex-grow: 1;
  width: 25%;
}

.small-cell {
  width: 4%;
}
</style>
