import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPinia, setActivePinia } from "pinia";

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

vi.mock("@/websockets/websocket_client", () => {
  const add_hook = vi.fn(() => ({ delete: vi.fn() }));
  return {
    useWebSocketClient: () => ({ add_hook }),
  };
});

import {
  deleteProject,
  deleteTarget,
  getOllamaDownloadQueueDetails,
  getUserSettings,
  updateTarget,
  type ResponseTarget,
  type UserSettings,
} from "@/api";
import { useWebSocketClient } from "@/websockets/websocket_client";
import { useMomosStore } from "@/store/momos_store";

function makeTarget(overrides: Partial<ResponseTarget> = {}): ResponseTarget {
  return {
    name: "target",
    ipv4: null,
    ipv6: null,
    description: null,
    ports: null,
    task_duration: null,
    id: "target-id",
    project_id: "project-id",
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  setActivePinia(createPinia());
});

describe("updateTarget", () => {
  it("does not modify targets when the id is unknown (fixed)", async () => {
    vi.mocked(updateTarget).mockResolvedValue({ response: { status: 200 } } as never);
    const store = useMomosStore();
    const existing = makeTarget({ id: "known" });
    store.targets = [existing];
    const unknown = makeTarget({ id: "does-not-exist", name: "new-name" });

    await store.updateTarget(unknown);

    expect(store.targets).toHaveLength(1);
    expect(store.targets[0]).toEqual(existing);
    expect(
      (store.targets as unknown as Record<string, ResponseTarget>)["-1"],
    ).toBeUndefined();
  });
});

describe("loadUserSettings", () => {
  function makeUserSettings(overrides: Partial<UserSettings> = {}): UserSettings {
    return {
      notify_agent_finished: false,
      notify_vulnerability_found: false,
      notify_agent_paused: false,
      notify_agent_error: false,
      accent_color: "red",
      global_max_concurrent_agents: 1,
      ...overrides,
    };
  }

  it("stores whatever GetUserSettings returns, as the shared source other parts of the app read live state from", async () => {
    const settings = makeUserSettings({ accent_color: "blue", notify_agent_finished: true });
    vi.mocked(getUserSettings).mockResolvedValue({
      data: settings,
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    await store.loadUserSettings();

    expect(store.user_settings).toEqual(settings);
    expect(store.getUserSettings).toEqual(settings);
  });

  it("throws instead of silently leaving stale/null state on a failed fetch", async () => {
    vi.mocked(getUserSettings).mockResolvedValue({
      error: { detail: "boom" },
      response: { status: 500 },
    } as never);
    const store = useMomosStore();

    await expect(store.loadUserSettings()).rejects.toThrow();
    expect(store.user_settings).toBeNull();
  });
});

describe("setUserSettings", () => {
  it("replaces the stored user settings in place, mirroring setProjectSettings's role for project settings", () => {
    const store = useMomosStore();
    const settings: UserSettings = {
      notify_agent_finished: true,
      notify_vulnerability_found: false,
      notify_agent_paused: false,
      notify_agent_error: false,
      accent_color: "green",
      global_max_concurrent_agents: 3,
    };

    store.setUserSettings(settings);

    expect(store.user_settings).toEqual(settings);
  });
});

describe("loadQueue", () => {
  it("called twice does not duplicate the queue entry or its websocket hook (fixed)", async () => {
    vi.mocked(getOllamaDownloadQueueDetails).mockResolvedValue({
      data: { current: null, queue: ["llama3"] },
    } as never);
    const store = useMomosStore();

    await store.loadQueue();
    await store.loadQueue();

    expect(
      store.download_queue.filter((q) => q.model_name === "llama3"),
    ).toHaveLength(1);
    expect(useWebSocketClient().add_hook).toHaveBeenCalledTimes(1);
  });
});

describe("deleteProject", () => {
  it("cleans up sessions/running_targets/attack_vectors/session_detail entries (fixed)", async () => {
    vi.mocked(deleteProject).mockResolvedValue({ response: { status: 204 } } as never);
    const store = useMomosStore();
    const pid = "proj-1";
    const tid = "target-1";
    const sid = "session-1";

    store.projects = [{ id: pid, name: "P" }];
    store.targets = [makeTarget({ id: tid, project_id: pid })];
    store.sessions[pid] = [{ id: sid, project_id: pid, target_id: tid } as never];
    store.running_targets[pid] = tid;
    store.attack_vectors[tid] = [{ id: "vec-1" } as never];
    store.session_detail[sid] = { id: sid } as never;

    await store.deleteProject(pid);

    expect(store.projects).toEqual([]);
    expect(store.targets).toEqual([]);
    expect(store.sessions[pid]).toBeUndefined();
    expect(store.running_targets[pid]).toBeUndefined();
    expect(store.attack_vectors[tid]).toBeUndefined();
    expect(store.session_detail[sid]).toBeUndefined();
  });
});

describe("deleteTarget", () => {
  it("cleans up running_targets/attack_vectors entries referencing the target (fixed)", async () => {
    vi.mocked(deleteTarget).mockResolvedValue({ response: { status: 204 } } as never);
    const store = useMomosStore();
    const pid = "proj-1";
    const tid = "target-1";

    store.targets = [makeTarget({ id: tid, project_id: pid })];
    store.running_targets[pid] = tid;
    store.attack_vectors[tid] = [{ id: "vec-1" } as never];

    await store.deleteTarget(tid);

    expect(store.targets).toEqual([]);
    expect(store.running_targets[pid]).toBeNull();
    expect(store.attack_vectors[tid]).toBeUndefined();
  });
});
