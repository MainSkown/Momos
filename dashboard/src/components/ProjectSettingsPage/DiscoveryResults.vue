<template>
  <div class="column gap-low discovery-results">
    <button
      class="button border discover-hosts-button"
      :disabled="loading"
      @click="runDiscovery"
    >
      {{ loading ? $t("discovery.discovering") : $t("discovery.discover_hosts") }}
    </button>

    <span v-if="error" class="text-red discovery-error">{{ error }}</span>

    <template v-if="hosts !== null">
      <div v-if="hosts.length === 0" class="text-gray text-center no-hosts-found">
        {{ $t("discovery.no_hosts_found") }}
      </div>

      <template v-else>
        <div
          v-for="host in hosts"
          :key="host.host"
          class="row gap-low discovery-host-row"
          :class="{ 'discovery-host-row--out-of-scope': !host.in_scope }"
        >
          <input
            :id="`discovery-host-${host.host}`"
            class="checkbox-input"
            type="checkbox"
            :disabled="!host.in_scope"
            :checked="isSelected(host)"
            @change="toggleHost(host)"
          />
          <label :for="`discovery-host-${host.host}`" class="column gap-low">
            <span class="text-bold">{{ host.host }}</span>
            <span v-if="!host.in_scope" class="text-gray out-of-scope-label">
              {{ $t("discovery.outside_scope") }}
            </span>
          </label>
        </div>

        <button
          class="button border add-selected-button"
          :disabled="selected.size === 0"
          @click="addSelected"
        >
          {{ $t("discovery.add_selected") }}
        </button>
      </template>
    </template>

    <span v-if="addError" class="text-red discovery-add-error">{{ addError }}</span>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import type { DiscoveredHost } from "@/api";
import { useMomosStore } from "@/store/momos_store";

const props = defineProps<{
  projectId: string;
}>();

const store = useMomosStore();
const { t: $t } = useI18n();

const hosts = ref<DiscoveredHost[] | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
const addError = ref<string | null>(null);
const selected = ref<Set<string>>(new Set());

function isSelected(host: DiscoveredHost): boolean {
  return selected.value.has(host.host);
}

// Guards against ever selecting an out-of-scope host regardless of how the
// checkbox's change event fired - the :disabled attribute alone only
// blocks a real user click, not a programmatically dispatched one.
function toggleHost(host: DiscoveredHost) {
  if (!host.in_scope) {
    return;
  }

  const next = new Set(selected.value);
  if (next.has(host.host)) {
    next.delete(host.host);
  } else {
    next.add(host.host);
  }
  selected.value = next;
}

async function runDiscovery() {
  loading.value = true;
  error.value = null;

  try {
    hosts.value = await store.discoverHosts(props.projectId);
    selected.value = new Set();
  } catch {
    hosts.value = null;
    error.value = $t("discovery.discovery_failed");
  } finally {
    loading.value = false;
  }
}

async function addSelected() {
  // Re-derive from the current host list rather than trusting `selected`
  // alone, so an out-of-scope host could never be added even if some
  // future change let it slip into the selection set.
  const toAdd = (hosts.value ?? []).filter(
    (host) => host.in_scope && selected.value.has(host.host),
  );
  addError.value = null;

  try {
    for (const host of toAdd) {
      // nmap -sn only ever reports a bare IPv4 or IPv6 address (see
      // backend's parse_nmap_ping_sweep) - a colon is enough to tell them
      // apart, no need for full address validation here.
      const isIpv6 = host.host.includes(":");
      await store.addTarget2Project(
        host.host,
        props.projectId,
        isIpv6 ? undefined : host.host,
        isIpv6 ? host.host : undefined,
      );
    }
    selected.value = new Set();
  } catch {
    addError.value = $t("discovery.add_failed");
  }
}
</script>
