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
          :checked="isChecked(group.id)"
          @change="toggle(group.id)"
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
// the id, for the enabled_tools array, plus which i18n keys to show).
// nmap_scan/searchsploit_search/searchsploit_view are core/always-on and
// deliberately not listed here - see that module's own docstring.
const TOOL_GROUPS = [
  { id: "hydra", labelKey: "hydra", descKey: "hydra_desc" },
  { id: "gobuster", labelKey: "gobuster", descKey: "gobuster_desc" },
  { id: "searchsploit_run", labelKey: "searchsploit_run", descKey: "searchsploit_run_desc" },
  { id: "ftp", labelKey: "ftp", descKey: "ftp_desc" },
  { id: "ssh", labelKey: "ssh", descKey: "ssh_desc" },
  { id: "telnet", labelKey: "telnet", descKey: "telnet_desc" },
] as const;

const visible = defineModel<boolean>("visible", { default: false });
// null/undefined reads as "every group enabled" - the same convention as
// the backend field it mirrors (ProjectSettings.enabled_tools, see
// project_scheme.py) - NOT the same as an empty array, which means
// "explicitly nothing enabled".
const enabledTools = defineModel<string[] | null | undefined>("enabledTools");

function isChecked(id: string): boolean {
  const current = enabledTools.value;
  return current == null ? true : current.includes(id);
}

function toggle(id: string) {
  const current = enabledTools.value;
  if (current == null) {
    // First-ever uncheck against the "everything on" default - materialize
    // the full id list minus this one, rather than just [id] (which would
    // silently disable every other group too).
    enabledTools.value = TOOL_GROUPS.map((g) => g.id).filter((g) => g !== id);
    return;
  }

  enabledTools.value = current.includes(id)
    ? current.filter((g) => g !== id)
    : [...current, id];
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
