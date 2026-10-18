import { afterEach, describe, expect, it } from "vitest";

import { ACCENT_PRESETS, applyAccent } from "@/composables/useAccentTheme";

afterEach(() => {
  document.documentElement.removeAttribute("data-accent");
});

describe("ACCENT_PRESETS", () => {
  it("contains exactly the 5 expected preset ids", () => {
    expect(ACCENT_PRESETS).toEqual(["red", "blue", "green", "purple", "orange"]);
  });
});

describe("applyAccent", () => {
  it("sets data-accent on the html element for a non-default preset", () => {
    applyAccent("blue");

    expect(document.documentElement.getAttribute("data-accent")).toBe("blue");
  });

  it("overwrites a previously applied preset rather than leaving it alongside the new one", () => {
    applyAccent("blue");
    applyAccent("purple");

    expect(document.documentElement.getAttribute("data-accent")).toBe("purple");
  });

  it("removes the data-accent attribute for the red (default) preset, falling back to the base :root block", () => {
    applyAccent("blue");
    applyAccent("red");

    expect(document.documentElement.hasAttribute("data-accent")).toBe(false);
  });

  it("is a no-op removal when red is applied with no prior preset set", () => {
    applyAccent("red");

    expect(document.documentElement.hasAttribute("data-accent")).toBe(false);
  });
});
