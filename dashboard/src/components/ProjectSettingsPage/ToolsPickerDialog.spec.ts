import { describe, it, expect, afterEach } from "vitest";
import { mount } from "@vue/test-utils";
import ToolsPickerDialog from "./ToolsPickerDialog.vue";

const DEFAULT_CHECKED_BY_GROUP: ReadonlyArray<[string, boolean]> = [
  ["sqlmap", true],
  ["mysql", true],
  ["snmp", true],
  ["scripting", false],
  ["testssl", true],
  ["wpscan", true],
  ["dnsrecon", true],
  ["tshark", true],
  ["netexec", false],
  ["impacket", false],
  ["responder", false],
  ["password_cracking", false],
  ["commix", true],
];

function mountPicker(enabledTools: string[] | null) {
  return mount(ToolsPickerDialog, {
    props: { visible: true, enabledTools },
    global: { mocks: { $t: (key: string) => key } },
    attachTo: document.body,
  });
}

function checkboxFor(groupId: string): HTMLInputElement | null {
  return document.querySelector<HTMLInputElement>(`#tool-group-${groupId}`);
}

describe("ToolsPickerDialog default checked state (enabledTools unset)", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it.each(DEFAULT_CHECKED_BY_GROUP)(
    "group %s is checked=%s when the project has never saved enabled_tools",
    (groupId, expected) => {
      mountPicker(null);

      expect(checkboxFor(groupId)?.checked).toBe(expected);
    },
  );
});
