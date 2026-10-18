import { showBrowserNotification } from "@/composables/useNotifications";
import { useMomosStore } from "@/store/momos_store";
import { useWebSocketClient } from "@/websockets/websocket_client";
import type { AgentRunState, AgentRunTimer, UserSettings, VulnerabilityFound } from "@/api";

// Mirrors AgentRunButton.vue's own ROOT_RUN_ROLES filter exactly - a
// sub-run (scouting/pentesting/reporting) broadcasts its own AgentRunTimer
// updates under the same target_id, and must never trigger a notification
// on its own finish/pause/failure, only the pipeline-level root run's.
const ROOT_RUN_ROLES = new Set(["single_agent", "orchestrator"]);

type NotifyToggle = Extract<
  keyof UserSettings,
  "notify_agent_finished" | "notify_agent_paused" | "notify_agent_error"
>;

// "interrupted" (blocked awaiting a tool-call approval) maps to the
// "paused" toggle; the plain, user-initiated "paused" state has nothing
// awaiting the user and never notifies. "running" never notifies either.
const STATUS_TOGGLE: Partial<Record<AgentRunState, NotifyToggle>> = {
  finished: "notify_agent_finished",
  interrupted: "notify_agent_paused",
  failed: "notify_agent_error",
};

function resolveProjectName(projectId: string): string {
  return useMomosStore().projects.find((p) => p.id === projectId)?.name ?? projectId;
}

function resolveTargetName(targetId: string): string {
  return useMomosStore().targets.find((t) => t.id === targetId)?.name ?? targetId;
}

function notificationForStatus(
  toggle: NotifyToggle,
  projectName: string,
): { title: string; body: string } {
  switch (toggle) {
    case "notify_agent_finished":
      return { title: "Agent finished", body: `Run on ${projectName} completed` };
    case "notify_agent_paused":
      return {
        title: "Agent paused",
        body: `Run on ${projectName} is awaiting your input`,
      };
    case "notify_agent_error":
      return { title: "Agent error", body: `Run on ${projectName} failed` };
  }
}

// Last notified status per root run id. The same status can legitimately
// be re-broadcast for a run that already notified (a reconnect replaying
// AgentRunTimer, or an unrelated field changing) - this map makes sure a
// notification fires only once per actual transition INTO a notifiable
// state, not once per message. Deliberately never cleared: run ids are
// never reused (same assumption momos_store.ts's clearCmdLines docstring
// makes about session names), so there's no case where clearing it would
// be correct - it would only reopen the door to the exact duplicate the
// map exists to prevent, e.g. right after the websocket reconnects and
// replays the current status. A status is only recorded once it has
// actually been notified (toggle was on) - a transition that arrived while
// the toggle was off is NOT recorded, so turning the toggle on later still
// notifies for the next re-broadcast of that same status.
const lastNotifiedStatusByRunId = new Map<string, AgentRunState>();

let agentNotificationHooksRegistered = false;

export function registerAgentNotificationHooks() {
  if (agentNotificationHooksRegistered) return;
  agentNotificationHooksRegistered = true;

  const ws_client = useWebSocketClient();

  ws_client.add_hook("AgentRunTimer", (message) => {
    if (message.error) return;

    const timerMessage = message as AgentRunTimer;
    const run = timerMessage.run;

    if (run.role && !ROOT_RUN_ROLES.has(run.role)) return;

    const toggle = STATUS_TOGGLE[run.status];
    if (!toggle) return;

    if (lastNotifiedStatusByRunId.get(run.id) === run.status) return;

    const store = useMomosStore();
    if (!store.user_settings?.[toggle]) return;

    lastNotifiedStatusByRunId.set(run.id, run.status);

    const { title, body } = notificationForStatus(toggle, resolveProjectName(run.project_id));
    showBrowserNotification(title, body);
  });

  ws_client.add_hook("VulnerabilityFound", (message) => {
    if (message.error) return;

    const vulnerabilityMessage = message as VulnerabilityFound;
    const store = useMomosStore();
    if (!store.user_settings?.notify_vulnerability_found) return;

    const projectName = resolveProjectName(vulnerabilityMessage.project_id);
    const targetName = resolveTargetName(vulnerabilityMessage.target_id);

    showBrowserNotification(
      "Vulnerability found",
      `${vulnerabilityMessage.vulnerability.name} found on ${projectName} / ${targetName}`,
    );
  });
}
