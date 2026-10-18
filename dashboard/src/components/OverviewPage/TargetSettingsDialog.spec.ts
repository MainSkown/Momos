import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, DOMWrapper } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import TargetSettingsDialog from "./TargetSettingsDialog.vue";
import { useMomosStore } from "@/store/momos_store";
import type { ResponseTarget } from "@/api";

function makeTarget(overrides: Partial<ResponseTarget> = {}): ResponseTarget {
  return {
    id: "target-1",
    project_id: "project-1",
    name: "Target 1",
    ipv4: null,
    ipv6: null,
    description: null,
    ports: null,
    task_duration: null,
    run_mode: "timer",
    safety_cap_duration: null,
    ...overrides,
  };
}

function mountDialog(target: ResponseTarget) {
  const pinia = createTestingPinia({ stubActions: true });
  const store = useMomosStore(pinia);

  mount(TargetSettingsDialog, {
    props: { visible: true, target },
    global: {
      plugins: [pinia],
      // TargetSettingsDialog.vue has no local useI18n() call - its
      // template calls the global $t injected by the app's i18n plugin.
      mocks: { $t: (key: string) => key },
    },
  });

  // Dialog.vue teleports its whole slot content to document.body, so none
  // of this dialog's inputs are reachable through the mounted wrapper's
  // own element tree - every query here goes through document.body.
  const body = new DOMWrapper(document.body);
  const portsInput = () => body.find('input[placeholder="targets.no_ports"]');

  return { store, portsInput };
}

describe("TargetSettingsDialog ports validation/save gap", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    // Dialog.vue teleports to document.body, and jsdom's document persists
    // across tests within this file - without this, an unmounted previous
    // test's teleported dialog stays the first DOM match for the next
    // test's query.
    document.body.innerHTML = "";
  });

  it("flags an out-of-range typed port red, and the debounced save stays blocked while it's showing (fixed)", async () => {
    const { store, portsInput } = mountDialog(makeTarget());

    await portsInput().setValue("99999");

    // arePortsInvalid() does flag this red, correctly.
    expect(portsInput().classes()).toContain("is-invalid");
    expect(store.updateTarget).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1000);

    // Fixed: isFormValid() now also checks arePortsInvalid() - the raw,
    // unfiltered input - instead of only localTarget.ports (which
    // updatePorts() had already silently pre-filtered down to valid
    // values alone, 99999 never making it in). The debounced save stays
    // blocked for as long as the red flag is showing.
    expect(store.updateTarget).not.toHaveBeenCalled();
  });

  it("accepts and displays valid ports correctly", async () => {
    const { store, portsInput } = mountDialog(makeTarget());

    await portsInput().setValue("80, 443");

    expect(portsInput().classes()).not.toContain("is-invalid");
    expect((portsInput().element as HTMLInputElement).value).toBe("80, 443");

    await vi.advanceTimersByTimeAsync(1000);

    expect(store.updateTarget).toHaveBeenCalledTimes(1);
    expect(store.updateTarget).toHaveBeenCalledWith(
      expect.objectContaining({ ports: [80, 443] }),
    );
  });
});
