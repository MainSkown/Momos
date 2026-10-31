import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPinia, setActivePinia } from "pinia";
import type {
  AgentRunResponse,
  AgentRunTimer,
  ResponseVulnerability,
  VulnerabilityFound,
} from "@/api";

vi.mock("@/api", () => ({
  getAllProjects: vi.fn(),
  postProject: vi.fn(),
  deleteProject: vi.fn(),
  postTarget: vi.fn(),
  getAllTargetsInProject: vi.fn(),
  deleteTarget: vi.fn(),
  updateTarget: vi.fn(),
  getOllamaDownloadQueueDetails: vi.fn(),
  downloadOllamaModel: vi.fn(),
  isProjectAgentRunning: vi.fn(),
  getTargetAttackVectors: vi.fn(),
  getProjectTestSessions: vi.fn(),
  getTestSession: vi.fn(),
  deleteTestSession: vi.fn(),
  getUserSettings: vi.fn(),
}));

// A real reference-equality hooks map, mirroring websocket_client.ts's own
// hook_exists/add_hook - lets us capture the registered callback per
// message type and invoke it directly to simulate an incoming websocket
// message, and lets the "registered once" test assert genuine state rather
// than a canned mock return (same pattern as AgentRunButton.spec.ts's own
// websocket_client mock). This mock, and the module under test, are loaded
// once for the whole file - registerAgentNotificationHooks's own singleton
// guard means only the first call in the suite actually registers the
// hooks; every test below calls it regardless (it's idempotent) and relies
// on Pinia's per-test store reset for isolation, with a distinct run id
// per test so the module-level de-dup map (deliberately never cleared -
// see notification_hooks.ts) can't leak a result from one test into
// another.
vi.mock("@/websockets/websocket_client", () => {
  const hooks: Record<string, Array<(msg: unknown) => void>> = {};

  const hook_exists = vi.fn(
    (type: string, cb: (msg: unknown) => void) =>
      hooks[type]?.some((c) => c === cb) ?? false,
  );
  const add_hook = vi.fn((type: string, cb: (msg: unknown) => void) => {
    if (!hooks[type]) hooks[type] = [];
    if (hook_exists(type, cb)) return undefined;
    hooks[type].push(cb);
    return { delete: vi.fn() };
  });

  return {
    useWebSocketClient: () => ({ hooks, hook_exists, add_hook }),
  };
});

vi.mock("@/composables/useNotifications", () => ({
  showBrowserNotification: vi.fn(),
}));

import { showBrowserNotification } from "@/composables/useNotifications";
import { useWebSocketClient } from "@/websockets/websocket_client";
import { useMomosStore } from "@/store/momos_store";
import { registerAgentNotificationHooks } from "@/websockets/notification_hooks";

function makeRun(overrides: Partial<AgentRunResponse> = {}): AgentRunResponse {
  return {
    id: "run-1",
    status: "running",
    remaining_seconds: 100,
    target_id: "target-1",
    project_id: "project-1",
    role: "orchestrator",
    ...overrides,
  };
}

function makeTimerMessage(overrides: Partial<AgentRunResponse> = {}): AgentRunTimer {
  return { type: "AgentRunTimer", run: makeRun(overrides) };
}

function makeVulnerabilityMessage(
  overrides: Partial<ResponseVulnerability> = {},
): VulnerabilityFound {
  return {
    type: "VulnerabilityFound",
    project_id: "project-1",
    target_id: "target-1",
    vulnerability: {
      name: "SQL Injection",
      cvss4_vector: "CVSS:4.0/...",
      proof_of_concept: "poc",
      ...overrides,
    } as ResponseVulnerability,
  };
}

function setToggles(overrides: Partial<Record<string, boolean>> = {}) {
  const store = useMomosStore();
  store.user_settings = {
    notify_agent_finished: false,
    notify_vulnerability_found: false,
    notify_agent_paused: false,
    notify_agent_error: false,
    accent_color: "red",
    global_max_concurrent_agents: 1,
    ...overrides,
  };
  return store;
}

function getHooks() {
  return (useWebSocketClient() as unknown as {
    hooks: Record<string, Array<(msg: unknown) => void>>;
  }).hooks;
}

function fireTimerMessage(message: AgentRunTimer) {
  const hook = getHooks()["AgentRunTimer"]?.[0];
  if (!hook) throw new Error("AgentRunTimer hook was not registered");
  hook(message);
}

function fireVulnerabilityMessage(message: VulnerabilityFound) {
  const hook = getHooks()["VulnerabilityFound"]?.[0];
  if (!hook) throw new Error("VulnerabilityFound hook was not registered");
  hook(message);
}

beforeEach(() => {
  vi.clearAllMocks();
  setActivePinia(createPinia());
});

describe("registerAgentNotificationHooks - AgentRunTimer", () => {
  it("notifies on a root run (orchestrator) transitioning to finished when the toggle is on", () => {
    setToggles({ notify_agent_finished: true });
    useMomosStore().projects = [{ id: "project-1", name: "Acme Corp" }];
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-finished-1", status: "finished", role: "orchestrator" }),
    );

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
    const [, body] = vi.mocked(showBrowserNotification).mock.calls[0]!;
    expect(body).toContain("Acme Corp");
  });

  it("never notifies for a sub-run's own finish, regardless of the toggle", () => {
    setToggles({ notify_agent_finished: true });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-subrun-1", status: "finished", role: "pentesting" }),
    );

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });

  it("does not notify when the toggle is off", () => {
    setToggles({ notify_agent_finished: false });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-toggleoff-1", status: "finished", role: "orchestrator" }),
    );

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });

  it("does not notify when user_settings has not loaded yet", () => {
    // user_settings defaults to null on a fresh store - left untouched.
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-nullsettings-1", status: "finished", role: "orchestrator" }),
    );

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });

  it("only fires once for the same transition re-broadcast twice for the same run id", () => {
    setToggles({ notify_agent_finished: true });
    registerAgentNotificationHooks();
    const message = makeTimerMessage({
      id: "run-dedup-1",
      status: "finished",
      role: "orchestrator",
    });

    fireTimerMessage(message);
    fireTimerMessage(message);

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
  });

  it("fires with the paused toggle when a run transitions into interrupted", () => {
    setToggles({ notify_agent_paused: true });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-interrupted-1", status: "running", role: "orchestrator" }),
    );
    fireTimerMessage(
      makeTimerMessage({ id: "run-interrupted-1", status: "interrupted", role: "orchestrator" }),
    );

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
  });

  it("does not fire for a plain paused transition, even with the paused toggle on", () => {
    setToggles({ notify_agent_paused: true });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-plainpaused-1", status: "running", role: "orchestrator" }),
    );
    fireTimerMessage(
      makeTimerMessage({ id: "run-plainpaused-1", status: "paused", role: "orchestrator" }),
    );

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });

  it("fires with the error toggle when a run transitions to failed", () => {
    setToggles({ notify_agent_error: true });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-failed-1", status: "failed", role: "orchestrator" }),
    );

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
  });

  it("treats a missing role as a root run (older wire shape), not as a filtered-out sub-run", () => {
    setToggles({ notify_agent_finished: true });
    registerAgentNotificationHooks();

    const message = makeTimerMessage({ id: "run-norole-1", status: "finished" });
    delete (message.run as Partial<AgentRunResponse>).role;
    fireTimerMessage(message);

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
  });

  it("ignores a message carrying a websocket error", () => {
    setToggles({ notify_agent_finished: true });
    registerAgentNotificationHooks();

    const message = makeTimerMessage({
      id: "run-haserror-1",
      status: "finished",
      role: "orchestrator",
    });
    (message as unknown as { error: unknown }).error = { detail: "boom" };
    fireTimerMessage(message);

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });

  it("falls back to the raw project id when the project is not in the store", () => {
    setToggles({ notify_agent_finished: true });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({
        id: "run-unknownproject-1",
        status: "finished",
        role: "orchestrator",
        project_id: "unknown-project",
      }),
    );

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
    const [, body] = vi.mocked(showBrowserNotification).mock.calls[0]!;
    expect(body).toContain("unknown-project");
  });
});

describe("registerAgentNotificationHooks - VulnerabilityFound", () => {
  it("notifies with the vulnerability's name when the toggle is on", () => {
    setToggles({ notify_vulnerability_found: true });
    const store = useMomosStore();
    store.projects = [{ id: "project-1", name: "Acme Corp" }];
    store.targets = [
      {
        id: "target-1",
        project_id: "project-1",
        name: "Web Server",
        ipv4: null,
        ipv6: null,
        description: null,
        ports: null,
        task_duration: null,
      },
    ];
    registerAgentNotificationHooks();

    fireVulnerabilityMessage(makeVulnerabilityMessage({ name: "SQL Injection" }));

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
    const [, body] = vi.mocked(showBrowserNotification).mock.calls[0]!;
    expect(body).toContain("SQL Injection");
  });

  it("does not notify when the vulnerability toggle is off", () => {
    setToggles({ notify_vulnerability_found: false });
    registerAgentNotificationHooks();

    fireVulnerabilityMessage(makeVulnerabilityMessage());

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });

  it("ignores a message carrying a websocket error", () => {
    setToggles({ notify_vulnerability_found: true });
    registerAgentNotificationHooks();

    const message = makeVulnerabilityMessage();
    (message as unknown as { error: unknown }).error = { detail: "boom" };
    fireVulnerabilityMessage(message);

    expect(showBrowserNotification).not.toHaveBeenCalled();
  });
});

describe("registerAgentNotificationHooks - registration guard", () => {
  it("calling register twice does not register duplicate hooks", () => {
    registerAgentNotificationHooks();
    registerAgentNotificationHooks();

    expect(getHooks()["AgentRunTimer"]).toHaveLength(1);
    expect(getHooks()["VulnerabilityFound"]).toHaveLength(1);
  });

  it("a registered hook fires exactly once per notifiable transition even though register() has been called from multiple tests", () => {
    setToggles({ notify_agent_finished: true });
    registerAgentNotificationHooks();

    fireTimerMessage(
      makeTimerMessage({ id: "run-singlefire-1", status: "finished", role: "orchestrator" }),
    );

    expect(showBrowserNotification).toHaveBeenCalledTimes(1);
  });
});
