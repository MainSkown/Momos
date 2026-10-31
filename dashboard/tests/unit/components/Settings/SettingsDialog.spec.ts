import { afterEach, describe, it, expect } from "vitest";
import { mount, DOMWrapper } from "@vue/test-utils";
import SettingsDialog from "@/components/Settings/SettingsDialog.vue";
import { USER_SETTINGS_KEYS, user_settings } from "@/components/tools";

function mountDialog() {
  return mount(SettingsDialog, {
    props: { modelValue: true },
    global: {
      mocks: { $t: (key: string) => key },
      stubs: { AISettings: true, UserOptions: true },
    },
  });
}

describe("SettingsDialog User Options tab", () => {
  // Dialog.vue teleports to document.body, which persists across mounts
  // within a test file - without this, a later test would still see the
  // previous test's teleported content.
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("renders UserOptions once the User Options tab is selected", async () => {
    mountDialog();
    const body = new DOMWrapper(document.body);

    const tabs = body.findAll(".settings-options");
    const userOptionsIndex = user_settings.findIndex(
      (s) => s.key === USER_SETTINGS_KEYS.USER_OPTIONS,
    );
    await tabs[userOptionsIndex]!.trigger("click");

    expect(body.find("user-options-stub").exists()).toBe(true);
  });

  it("does not render UserOptions while the AI tab is selected (the default)", () => {
    mountDialog();
    const body = new DOMWrapper(document.body);

    expect(body.find("user-options-stub").exists()).toBe(false);
  });
});
