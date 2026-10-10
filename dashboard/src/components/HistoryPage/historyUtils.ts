import type { TestSessionOutcome } from "@/api";

// "Session" in this folder (and in HistoryPage/* generally) always means
// a TestSession - one target Start->Pause/Finish, the thing History is
// browsing. It is NOT the same "session" the app already uses elsewhere
// for a Kali shell session (UserConsole.vue / agent_logs.tool_new_session
// "Session Opened" etc., which SessionLogs.vue's own log view can render
// right next to this feature's own "session" chrome) - the two are
// unrelated concepts that happen to share a name.

// started_at/ended_at are typed optional by the generator (they have
// server-side defaults, so OpenAPI marks them "not required"), even
// though a real response always sets started_at - this guard is purely
// defensive, shared so every caller falls back to the same "—" instead
// of some rendering `new Date("").toLocaleString()`'s "Invalid Date".
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// Takes the translate function as a parameter (rather than calling
// useI18n() itself) so this stays plain, component-independent code -
// vue-i18n's composable can only be called from within a component's own
// setup(), the same reason ToolsBar.vue's near-identical
// formatMsToHoursMinutes is defined inline in that component instead of
// here.
export function formatDuration(
  totalSeconds: number,
  t: (key: string, params?: Record<string, unknown>) => string,
): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const totalMinutes = Math.floor(seconds / 60);

  // Under a minute - show seconds so a session that just started (or a
  // very short test run) doesn't look stuck at "0h 00m".
  if (totalMinutes === 0) return `${seconds}s`;

  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;

  return t("time.hours_minutes", { hours, minutes: minutes.toString().padStart(2, "0") });
}

export const OUTCOME_LABEL_KEYS: Record<TestSessionOutcome, string> = {
  running: "history.outcome_running",
  paused: "history.outcome_paused",
  finished: "history.outcome_finished",
  time_expired: "history.outcome_time_expired",
  failed: "history.outcome_failed",
  aborted: "history.outcome_aborted",
};

// Loosely maps each outcome onto the existing severity/status color
// classes from main.css - there is no dedicated "badge" palette in this
// codebase, so this reuses the same classes VulnerabilityCard.vue/
// AttackVectors.vue already rely on for colored status text.
export const OUTCOME_CLASS: Record<TestSessionOutcome, string> = {
  running: "text-active",
  paused: "text-gray",
  finished: "text-active",
  time_expired: "severity-medium",
  failed: "severity-critical",
  aborted: "severity-high",
};
