import { applyAccent, type AccentPreset } from "@/composables/useAccentTheme";
import type { useMomosStore } from "@/store/momos_store";

// Called once at app boot (see main.ts), before mount, so the persisted
// accent color is already applied by the time the first frame renders -
// without this there'd be a flash of the default red before the real
// preference loads. Swallows a failed fetch rather than letting it crash
// boot - a backend hiccup here should just mean "keep today's default
// look", not an unusable app.
export async function applyPersistedAccentColor(
  store: ReturnType<typeof useMomosStore>,
): Promise<void> {
  try {
    await store.loadUserSettings();
    applyAccent((store.user_settings?.accent_color as AccentPreset) ?? "red");
  } catch (error) {
    console.error("Could not load persisted accent color:", error);
  }
}
