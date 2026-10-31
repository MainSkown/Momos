import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/composables/useAccentTheme", () => ({
  applyAccent: vi.fn(),
}));

import { applyAccent } from "@/composables/useAccentTheme";
import { applyPersistedAccentColor } from "@/bootstrap/applyPersistedAccentColor";

function fakeStore(overrides: {
  loadUserSettings?: () => Promise<void>;
  accent_color?: string | null;
} = {}) {
  return {
    loadUserSettings: overrides.loadUserSettings ?? vi.fn().mockResolvedValue(undefined),
    user_settings:
      overrides.accent_color === null
        ? null
        : { accent_color: overrides.accent_color ?? "blue" },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("applyPersistedAccentColor", () => {
  it("loads user settings then applies the persisted accent before anything else awaits it", async () => {
    const store = fakeStore({ accent_color: "purple" });

    await applyPersistedAccentColor(store as never);

    expect(store.loadUserSettings).toHaveBeenCalledOnce();
    expect(applyAccent).toHaveBeenCalledWith("purple");
  });

  it("falls back to red when the fetch succeeds but somehow leaves user_settings null", async () => {
    const store = fakeStore({ accent_color: null });

    await applyPersistedAccentColor(store as never);

    expect(applyAccent).toHaveBeenCalledWith("red");
  });

  it("never throws when loadUserSettings rejects - boot must not crash on a backend error, it just keeps the default look", async () => {
    const store = fakeStore({ loadUserSettings: vi.fn().mockRejectedValue(new Error("network down")) });

    await expect(applyPersistedAccentColor(store as never)).resolves.toBeUndefined();
    expect(applyAccent).not.toHaveBeenCalled();
  });
});
