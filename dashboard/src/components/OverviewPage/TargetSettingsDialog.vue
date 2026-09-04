<template>
  <Dialog
    :title="$t('targets.target') + ': ' + target.name"
    v-model:visible="visible"
  >
    <div class="row gap-low target-settings">
      <!-- Basic values-->
      <div class="column gap-low col">
        <div class="input-wrapper">
          <label class="floating-label">{{ $t("targets.name") }}</label>
          <input
            v-model="localTarget.name"
            class="input-field border"
            :class="{ 'is-invalid': localTarget.name.length === 0 }"
            :placeholder="$t('targets.enter_name')"
          />
        </div>

        <div class="input-wrapper">
          <label class="floating-label">{{ $t("targets.ipv4") }}</label>
          <input
            v-model="localTarget.ipv4"
            @input="localTarget.ipv4 = handleIPv4Input($event)"
            class="input-field border"
            :class="{ 'is-invalid': isInvalid(localTarget.ipv4, ipv4Pattern) }"
            :placeholder="$t('targets.no_ipv4')"
            spellcheck="false"
          />
        </div>

        <div class="input-wrapper">
          <label class="floating-label">{{ $t("targets.ipv6") }}</label>
          <input
            v-model="localTarget.ipv6"
            @input="localTarget.ipv6 = handleIPv6Input($event)"
            class="input-field border"
            :class="{ 'is-invalid': isInvalid(localTarget.ipv6, ipv6Pattern) }"
            :placeholder="$t('targets.no_ipv6')"
            spellcheck="false"
          />
        </div>

        <div class="input-wrapper">
          <label class="floating-label">{{ $t("targets.ports") }}</label>
          <input
            :value="portsInput"
            @input="updatePorts"
            class="input-field border"
            :class="{ 'is-invalid': arePortsInvalid() }"
            :placeholder="$t('targets.no_ports')"
            spellcheck="false"
          />
        </div>

        <!-- <div class="input-wrapper">
          <label class="floating-label">{{ $t("targets.domain") }}</label>
          <input
            v-model="localTarget.domain"
            @input="localTarget.domain = handleDomainInput($event)"
            class="input-field border"
            :class="{
              'is-invalid': isInvalid(localTarget.domain, domainPattern),
            }"
            :placeholder="$t('targets.no_domain')"
            spellcheck="false"
          />
        </div> -->
        
        <div class="input-wrapper">
          <label class="floating-label">
            {{ $t("targets.scan_duration") }}
          </label>

          <input
            v-model="localTarget.task_duration"
            type="text"
            inputmode="numeric"
            placeholder="HH:MM"
            pattern="^\d+:[0-5]\d$"
            class="input-field border"
          />
        </div>
      </div>

      <!-- Description -->
      <div class="column full-width description">
        <div class="input-wrapper description">
          <label class="floating-label">{{ $t("targets.description") }}</label>
          <textarea
            v-model="localTarget.description"
            class="input-field border description"
            placeholder="Enter description for LLM"
            spellcheck="true"
          />
        </div>
      </div>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { domainPattern, ipv4Pattern, ipv6Pattern, type tTarget } from "@/types";
import Dialog from "../reusable/Dialog.vue";
import { useMomosStore } from "@/store/momos_store.ts";

const visible = defineModel("visible", { type: Boolean, default: false });
const target = defineModel<tTarget>("target", { required: true });

const localTarget = ref<tTarget>({ ...target.value });

const portsInput = ref<string>(localTarget.value.ports?.join(", ") || "");

const updatePorts = (event: Event) => {
  const e = event.target as HTMLInputElement;

  const sanitizedValue = e.value.replace(/[^0-9, ]/g, "");
  e.value = sanitizedValue;
  portsInput.value = sanitizedValue;

  const portsArray = sanitizedValue
    .split(",")
    .map((p) => parseInt(p.trim(), 10))
    .filter((p) => !isNaN(p) && p > 0 && p <= 65535);

  localTarget.value.ports = [...new Set(portsArray)];
};

const isFormValid = (val?: tTarget): boolean => {
  const { name, ipv4, ipv6, /*domain,*/ ports } = val || localTarget.value;

  if (name.length === 0) return false;
  if (ipv4 && !ipv4Pattern.test(ipv4)) return false;
  if (ipv6 && !ipv6Pattern.test(ipv6)) return false;
  // if (domain && !domainPattern.test(domain)) return false;

  if (ports && ports.length > 0) {
    const arePortsValid = ports.every((p) => p >= 1 && p <= 65535);
    if (!arePortsValid) return false;
  }

  return true;
};

const duration = computed({
  get() {
    const total = localTarget.value.task_duration ?? 0;

    return {
      hours: Math.floor(total / 3600),
      minutes: Math.floor((total % 3600) / 60),
      seconds: total % 60,
    };
  },

  set(value) {
    localTarget.value.task_duration =
      value.hours * 3600 + value.minutes * 60 + value.seconds;
  },
});

const isInvalid = (
  value: string | null | undefined,
  pattern: RegExp,
): boolean => {
  if (!value) return false;
  return !pattern.test(value);
};

const arePortsInvalid = (): boolean => {
  if (!portsInput.value.trim()) return false;

  const segments = portsInput.value.split(",");
  return segments.some((p) => {
    const val = parseInt(p.trim(), 10);
    return isNaN(val) || val < 1 || val > 65535;
  });
};

const store = useMomosStore();

// Updating the target
let debounceTimeout: ReturnType<typeof setTimeout> | null = null;

watch(
  localTarget,
  (newData) => {
    if (debounceTimeout) {
      clearTimeout(debounceTimeout);
    }

    debounceTimeout = setTimeout(() => {
      if (!isFormValid(newData)) return;
      store.updateTarget(newData);
    }, 1000);
  },
  { deep: true },
);

watch(visible, (newData) => {
  // Update target on leave
  if (newData === false && debounceTimeout) clearTimeout(debounceTimeout);
});

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
</script>

<style scoped lang="css">
.target-settings {
  width: 1000px;
  display: flex;
  align-items: stretch;
}

.col {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.description {
  flex: 2;
  display: flex;
  flex-direction: column;
}

.input-wrapper.description {
  flex-grow: 1;
  display: flex;
  flex-direction: column;
}

textarea.description {
  flex-grow: 1;
  height: 100%;
  min-height: 200px;
}
</style>
