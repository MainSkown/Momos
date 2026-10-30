import { describe, it, expect, afterEach } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
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

const mountedPickers: VueWrapper[] = [];

function mountPicker(enabledTools: string[] | null) {
  const wrapper = mount(ToolsPickerDialog, {
    props: { visible: true, enabledTools },
    global: { mocks: { $t: (key: string) => key } },
    attachTo: document.body,
  });
  mountedPickers.push(wrapper);
  return wrapper;
}

function checkboxFor(groupId: string): HTMLInputElement | null {
  return document.querySelector<HTMLInputElement>(`#tool-group-${groupId}`);
}

describe("ToolsPickerDialog default checked state (enabledTools unset)", () => {
  afterEach(() => {
    mountedPickers.splice(0).forEach((wrapper) => wrapper.unmount());
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
