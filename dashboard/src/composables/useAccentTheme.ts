export const ACCENT_PRESETS = ["red", "blue", "green", "purple", "orange"] as const;

export type AccentPreset = (typeof ACCENT_PRESETS)[number];

const DEFAULT_ACCENT: AccentPreset = "red";
const ACCENT_ATTRIBUTE = "data-accent";

/**
 * Applies an accent color preset by setting `data-accent` on `<html>`, which the
 * `:root[data-accent="..."]` blocks in main.css key off of. The default ("red")
 * removes the attribute instead of setting it, since the base `:root` block already
 * holds red's values and needs no override block.
 */
export function applyAccent(preset: AccentPreset): void {
  if (preset === DEFAULT_ACCENT) {
    document.documentElement.removeAttribute(ACCENT_ATTRIBUTE);
    return;
  }

  document.documentElement.setAttribute(ACCENT_ATTRIBUTE, preset);
}
