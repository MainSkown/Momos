<template>
  <Dialog v-model:visible="visible" :title="$t('settings.tools_dialog_title')">
    <div class="tools-picker-body scrollable-panel column gap-low" style="max-height: 60vh">
      <div
        v-for="group in TOOL_GROUPS"
        :key="group.id"
        class="row gap-low full-width tool-group-row"
      >
        <input
          :id="`tool-group-${group.id}`"
          class="checkbox-input"
          type="checkbox"
          :checked="isChecked(group)"
          @change="toggle(group)"
        />
        <label :for="`tool-group-${group.id}`" class="column gap-low">
          <span class="text-bold">{{ $t(`settings.tool_groups.${group.labelKey}`) }}</span>
          <span class="text-gray">{{ $t(`settings.tool_groups.${group.descKey}`) }}</span>
        </label>
      </div>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import Dialog from "@/components/reusable/Dialog.vue";

// Mirrors backend/src/core/tool_groups.py's TOOL_GROUPS exactly (id +
// which tools/packages each one covers lives there - this side only needs
// the id, for the enabled_tools array, plus which i18n keys to show, plus
// defaultEnabled - must match each group's own default_enabled there, or
// this picker's "unset = checked" assumption silently disagrees with what
// the backend actually binds/installs for a project that's never saved
// enabled_tools). nmap_scan/searchsploit_search/searchsploit_view are
// core/always-on and deliberately not listed here - see that module's own
// docstring.
const TOOL_GROUPS = [
  { id: "hydra", labelKey: "hydra", descKey: "hydra_desc", defaultEnabled: true },
  { id: "gobuster", labelKey: "gobuster", descKey: "gobuster_desc", defaultEnabled: true },
  {
    id: "searchsploit_run",
    labelKey: "searchsploit_run",
    descKey: "searchsploit_run_desc",
    defaultEnabled: true,
  },
  { id: "ftp", labelKey: "ftp", descKey: "ftp_desc", defaultEnabled: true },
  { id: "ssh", labelKey: "ssh", descKey: "ssh_desc", defaultEnabled: true },
  { id: "telnet", labelKey: "telnet", descKey: "telnet_desc", defaultEnabled: true },
  {
    id: "metasploit",
    labelKey: "metasploit",
    descKey: "metasploit_desc",
    defaultEnabled: false,
  },
] as const;

const visible = defineModel<boolean>("visible", { default: false });
// null/undefined reads as "use each group's own defaultEnabled" - the
// same convention as the backend field it mirrors (ProjectSettings.
// enabled_tools, see project_scheme.py/tool_groups.py) - NOT the same as
// an empty array, which means "explicitly nothing enabled".
const enabledTools = defineModel<string[] | null | undefined>("enabledTools");

function isChecked(group: (typeof TOOL_GROUPS)[number]): boolean {
  const current = enabledTools.value;
  return current == null ? group.defaultEnabled : current.includes(group.id);
}

function toggle(group: (typeof TOOL_GROUPS)[number]) {
  const current = enabledTools.value;
  if (current == null) {
    // First-ever toggle against the defaults - materialize the full set
    // of currently-default-enabled ids, then flip this one, rather than
    // assuming "everything was on" (no longer true now that metasploit
    // defaults to off).
    const defaults = new Set(TOOL_GROUPS.filter((g) => g.defaultEnabled).map((g) => g.id));
    if (defaults.has(group.id)) {
      defaults.delete(group.id);
    } else {
      defaults.add(group.id);
    }
    enabledTools.value = [...defaults];
    return;
  }

  enabledTools.value = current.includes(group.id)
    ? current.filter((g) => g !== group.id)
    : [...current, group.id];
}
</script>

<style scoped>
.tools-picker-body {
  width: 420px;
  padding: 4px;
}

.tool-group-row {
  /* .row alone left-aligns (no justify-content), but still defaults to
     align-items: stretch - flex-start instead so the checkbox sits at the
     top of a 2-line label instead of stretching/centering against it. */
  align-items: flex-start;
}

.tool-group-row .checkbox-input {
  margin-top: 2px;
}
</style>
