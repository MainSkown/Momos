import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises, type VueWrapper } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import UserOptions from "./UserOptions.vue";
import { useMomosStore } from "@/store/momos_store";
import type { UserSettings } from "@/api/types.gen";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

vi.mock("vue3-toastify", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    info: vi.fn(),
    POSITION: { TOP_CENTER: "top-center" },
  },
}));

vi.mock("@/api", () => ({
  getUserSettings: vi.fn(),
  updateUserSettings: vi.fn(),
}));

vi.mock("@/composables/useNotifications", () => ({
  requestNotificationPermission: vi.fn(),
  showBrowserNotification: vi.fn(),
}));

vi.mock("@/composables/useAccentTheme", () => ({
  ACCENT_PRESETS: ["red", "blue", "green", "purple", "orange"],
  applyAccent: vi.fn(),
}));

import { getUserSettings, updateUserSettings } from "@/api";
import { requestNotificationPermission } from "@/composables/useNotifications";
import { applyAccent } from "@/composables/useAccentTheme";
import { toast } from "vue3-toastify";

function makeSettings(overrides: Partial<UserSettings> = {}): UserSettings {
  return {
    notify_agent_finished: false,
    notify_vulnerability_found: false,
    notify_agent_paused: false,
    notify_agent_error: false,
    accent_color: "red",
    global_max_concurrent_agents: 3,
    ...overrides,
  };
}

// Mirrors ProjectSettingsPage.spec.ts's own fieldGroupControl - fields here
// follow the same .field-group + <label> convention, so a field is located
// by its (mocked, passthrough) i18n label key rather than by CSS class,
// which several controls share.
function fieldGroupControl(wrapper: VueWrapper, labelText: string, selector: string) {
  const group = wrapper
    .findAll(".field-group")
    .find((g) => g.find("label").text() === labelText);
  if (!group) throw new Error(`No .field-group with label "${labelText}"`);
  return group.find(selector);
}

function swatchButton(wrapper: VueWrapper, preset: string) {
  const button = wrapper
    .findAll(".accent-swatch")
    .find((b) => b.text().includes(`settings.accent_${preset}`));
  if (!button) throw new Error(`No accent swatch for preset "${preset}"`);
  return button;
}

function mountComponent() {
  const pinia = createTestingPinia({ stubActions: true });
  const store = useMomosStore(pinia);

  const wrapper = mount(UserOptions, {
    global: {
      plugins: [pinia],
      mocks: { $t: (key: string) => key },
    },
  });

  return { wrapper, store };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(getUserSettings).mockReset();
  vi.mocked(updateUserSettings).mockReset().mockResolvedValue({ data: {} } as never);
  vi.mocked(requestNotificationPermission).mockReset();
  vi.mocked(applyAccent).mockReset();
  vi.mocked(toast.error).mockClear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("UserOptions load", () => {
  it("populates toggles, swatches and the cap field from getUserSettings on mount", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({
      data: makeSettings({
        notify_agent_finished: true,
        notify_vulnerability_found: false,
        accent_color: "blue",
        global_max_concurrent_agents: 5,
      }),
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(
      (fieldGroupControl(wrapper, "settings.notify_agent_finished_label", "input")
        .element as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (fieldGroupControl(wrapper, "settings.notify_vulnerability_found_label", "input")
        .element as HTMLInputElement).checked,
    ).toBe(false);
    expect(swatchButton(wrapper, "blue").classes()).toContain("is-active");
    expect(swatchButton(wrapper, "red").classes()).not.toContain("is-active");
    expect(
      (fieldGroupControl(wrapper, "settings.global_max_concurrent_agents_label", "input")
        .element as HTMLInputElement).value,
    ).toBe("5");
  });

  it("shows an error and disables every control when loading fails", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({
      error: { message: "boom" },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.text()).toContain("settings.load_error");

    expect(
      fieldGroupControl(wrapper, "settings.notify_agent_finished_label", "input").attributes(
        "disabled",
      ),
    ).toBeDefined();
    expect(swatchButton(wrapper, "blue").attributes("disabled")).toBeDefined();
    expect(
      fieldGroupControl(wrapper, "settings.global_max_concurrent_agents_label", "input").attributes(
        "disabled",
      ),
    ).toBeDefined();
  });
});

describe("UserOptions notification toggles", () => {
  it("gates turning a toggle ON behind a granted permission, then autosaves", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({ data: makeSettings() } as never);
    vi.mocked(requestNotificationPermission).mockResolvedValue("granted");

    const { wrapper } = mountComponent();
    await flushPromises();

    const checkbox = fieldGroupControl(wrapper, "settings.notify_agent_finished_label", "input");
    (checkbox.element as HTMLInputElement).checked = true;
    await checkbox.trigger("change");
    await flushPromises();

    expect(requestNotificationPermission).toHaveBeenCalledTimes(1);
    expect((checkbox.element as HTMLInputElement).checked).toBe(true);

    await vi.advanceTimersByTimeAsync(800);
    await flushPromises();

    expect(updateUserSettings).toHaveBeenCalledTimes(1);
    const call = vi.mocked(updateUserSettings).mock.calls[0]![0] as { body: UserSettings };
    expect(call.body.notify_agent_finished).toBe(true);
  });

  it("snaps a toggle back off and toasts when permission is denied", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({ data: makeSettings() } as never);
    vi.mocked(requestNotificationPermission).mockResolvedValue("denied");

    const { wrapper } = mountComponent();
    await flushPromises();

    const checkbox = fieldGroupControl(wrapper, "settings.notify_agent_finished_label", "input");
    (checkbox.element as HTMLInputElement).checked = true;
    await checkbox.trigger("change");
    await flushPromises();

    expect((checkbox.element as HTMLInputElement).checked).toBe(false);
    expect(toast.error).toHaveBeenCalledWith("settings.notifications_denied");

    await vi.advanceTimersByTimeAsync(800);
    await flushPromises();
    expect(updateUserSettings).not.toHaveBeenCalled();
  });

  it("snaps a toggle back off and toasts the unsupported message when notifications aren't supported", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({ data: makeSettings() } as never);
    vi.mocked(requestNotificationPermission).mockResolvedValue("unsupported");

    const { wrapper } = mountComponent();
    await flushPromises();

    const checkbox = fieldGroupControl(wrapper, "settings.notify_agent_finished_label", "input");
    (checkbox.element as HTMLInputElement).checked = true;
    await checkbox.trigger("change");
    await flushPromises();

    expect((checkbox.element as HTMLInputElement).checked).toBe(false);
    expect(toast.error).toHaveBeenCalledWith("settings.notifications_unsupported");
  });

  it("turns a toggle OFF immediately without requesting permission, then autosaves", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({
      data: makeSettings({ notify_agent_finished: true }),
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    const checkbox = fieldGroupControl(wrapper, "settings.notify_agent_finished_label", "input");
    (checkbox.element as HTMLInputElement).checked = false;
    await checkbox.trigger("change");
    await flushPromises();

    expect(requestNotificationPermission).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(800);
    await flushPromises();

    expect(updateUserSettings).toHaveBeenCalledTimes(1);
    const call = vi.mocked(updateUserSettings).mock.calls[0]![0] as { body: UserSettings };
    expect(call.body.notify_agent_finished).toBe(false);
  });
});

describe("UserOptions appearance", () => {
  it("applies the accent live on click and persists it after the debounce", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({
      data: makeSettings({ accent_color: "red" }),
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    await swatchButton(wrapper, "blue").trigger("click");

    expect(applyAccent).toHaveBeenCalledWith("blue");

    await vi.advanceTimersByTimeAsync(800);
    await flushPromises();

    expect(updateUserSettings).toHaveBeenCalledTimes(1);
    const call = vi.mocked(updateUserSettings).mock.calls[0]![0] as { body: UserSettings };
    expect(call.body.accent_color).toBe("blue");
  });
});

describe("UserOptions autosave failure", () => {
  it("reverts the field to its last known-good value and shows a save-failed toast", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({
      data: makeSettings({ global_max_concurrent_agents: 3 }),
    } as never);
    vi.mocked(updateUserSettings).mockResolvedValue({ error: { message: "boom" } } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    const input = fieldGroupControl(
      wrapper,
      "settings.global_max_concurrent_agents_label",
      "input",
    );
    await input.setValue(9);

    await vi.advanceTimersByTimeAsync(800);
    await flushPromises();

    expect((input.element as HTMLInputElement).value).toBe("3");
    expect(toast.error).toHaveBeenCalledWith("settings.autosave_error");
  });
});
