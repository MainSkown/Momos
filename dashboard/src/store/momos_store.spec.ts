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
  getProjectScope: vi.fn(),
  updateProjectScope: vi.fn(),
  submitAuthorizationAcknowledgment: vi.fn(),
  getAcknowledgmentStatus: vi.fn(),
  discoverProjectHosts: vi.fn(),
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
  discoverProjectHosts,
  getAcknowledgmentStatus,
  getOllamaDownloadQueueDetails,
  getProjectScope,
  getUserSettings,
  postProject,
  postTarget,
  submitAuthorizationAcknowledgment,
  updateProjectScope,
  updateTarget,
  type DiscoveredHost,
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

describe("addProject", () => {
  it("forwards the scope fields to postProject's body alongside the existing fields", async () => {
    vi.mocked(postProject).mockResolvedValue({
      data: { id: "proj-1", name: "new" },
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    await store.addProject("new", "base-model", "parse-model", "10.0.0.0/24", 1, 1024);

    expect(postProject).toHaveBeenCalledWith({
      body: {
        name: "new",
        base_model_name: "base-model",
        parsing_model_name: "parse-model",
        host_range: "10.0.0.0/24",
        port_range_start: 1,
        port_range_end: 1024,
      },
    });
    expect(store.projects).toEqual([{ id: "proj-1", name: "new" }]);
  });
});

describe("addTarget2Project", () => {
  it("posts a blank target (ipv4/ipv6 both null) when no IP is given, matching the existing new-blank-target flow", async () => {
    vi.mocked(postTarget).mockResolvedValue({
      data: makeTarget({ id: "t-1" }),
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    await store.addTarget2Project("new target", "proj-1");

    expect(postTarget).toHaveBeenCalledWith({
      body: {
        name: "new target",
        ipv4: null,
        ipv6: null,
        description: null,
        ports: null,
        task_duration: null,
      },
      path: { project_id: "proj-1" },
    });
  });

  it("posts the given ipv4 when discovery supplies one", async () => {
    vi.mocked(postTarget).mockResolvedValue({
      data: makeTarget({ id: "t-1" }),
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    await store.addTarget2Project("10.0.0.5", "proj-1", "10.0.0.5");

    expect(postTarget).toHaveBeenCalledWith({
      body: {
        name: "10.0.0.5",
        ipv4: "10.0.0.5",
        ipv6: null,
        description: null,
        ports: null,
        task_duration: null,
      },
      path: { project_id: "proj-1" },
    });
  });

  it("posts the given ipv6 when discovery supplies one instead of an ipv4", async () => {
    vi.mocked(postTarget).mockResolvedValue({
      data: makeTarget({ id: "t-1" }),
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    await store.addTarget2Project("::1", "proj-1", undefined, "::1");

    expect(postTarget).toHaveBeenCalledWith({
      body: {
        name: "::1",
        ipv4: null,
        ipv6: "::1",
        description: null,
        ports: null,
        task_duration: null,
      },
      path: { project_id: "proj-1" },
    });
  });
});

describe("getProjectScope", () => {
  it("returns the scope data from the API", async () => {
    const scope = { project_id: "proj-1", host_range: "10.0.0.0/24", port_range_start: 1, port_range_end: 1024 };
    vi.mocked(getProjectScope).mockResolvedValue({
      data: scope,
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    const result = await store.getProjectScope("proj-1");

    expect(result).toEqual(scope);
  });

  it("throws instead of returning undefined on a failed fetch", async () => {
    vi.mocked(getProjectScope).mockResolvedValue({
      error: { detail: "not found" },
      response: { status: 404 },
    } as never);
    const store = useMomosStore();

    await expect(store.getProjectScope("proj-1")).rejects.toThrow();
  });
});

describe("updateProjectScope", () => {
  it("returns the updated scope and large_range_warning flag", async () => {
    const body = {
      scope: { project_id: "proj-1", host_range: "10.0.0.0/16", port_range_start: 1, port_range_end: 65535 },
      large_range_warning: true,
    };
    vi.mocked(updateProjectScope).mockResolvedValue({
      data: body,
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    const result = await store.updateProjectScope("proj-1", "10.0.0.0/16", 1, 65535);

    expect(updateProjectScope).toHaveBeenCalledWith({
      path: { project_id: "proj-1" },
      body: {
        project_id: "proj-1",
        host_range: "10.0.0.0/16",
        port_range_start: 1,
        port_range_end: 65535,
      },
    });
    expect(result).toEqual(body);
  });

  it("throws on an invalid range rejected by the backend", async () => {
    vi.mocked(updateProjectScope).mockResolvedValue({
      error: { detail: "invalid host range" },
      response: { status: 400 },
    } as never);
    const store = useMomosStore();

    await expect(
      store.updateProjectScope("proj-1", "not an ip", 1, 1024),
    ).rejects.toThrow();
  });
});

describe("submitAcknowledgment", () => {
  it("posts the acknowledged_by/description fields and returns the created acknowledgment", async () => {
    const ack = {
      id: "ack-1",
      project_id: "proj-1",
      acknowledged_by: "alice",
      description: "pentest engagement",
      acknowledged_host_range: "10.0.0.0/24",
      acknowledged_port_range_start: 1,
      acknowledged_port_range_end: 1024,
      created_at: "2026-01-01T00:00:00Z",
    };
    vi.mocked(submitAuthorizationAcknowledgment).mockResolvedValue({
      data: ack,
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    const result = await store.submitAcknowledgment("proj-1", "alice", "pentest engagement");

    expect(submitAuthorizationAcknowledgment).toHaveBeenCalledWith({
      path: { project_id: "proj-1" },
      body: { acknowledged_by: "alice", description: "pentest engagement" },
    });
    expect(result).toEqual(ack);
  });
});

describe("getAcknowledgmentStatus", () => {
  it("returns the boolean status from the API", async () => {
    vi.mocked(getAcknowledgmentStatus).mockResolvedValue({
      data: { is_acknowledged: true },
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    const result = await store.getAcknowledgmentStatus("proj-1");

    expect(result).toBe(true);
  });
});

describe("discoverHosts", () => {
  it("returns the tagged host list from the API", async () => {
    const hosts: DiscoveredHost[] = [
      { host: "10.0.0.5", in_scope: true },
      { host: "192.168.1.1", in_scope: false },
    ];
    vi.mocked(discoverProjectHosts).mockResolvedValue({
      data: hosts,
      response: { status: 200 },
    } as never);
    const store = useMomosStore();

    const result = await store.discoverHosts("proj-1");

    expect(result).toEqual(hosts);
  });

  it("throws instead of returning undefined on a failed sweep", async () => {
    vi.mocked(discoverProjectHosts).mockResolvedValue({
      error: { detail: "nmap failed" },
      response: { status: 500 },
    } as never);
    const store = useMomosStore();

    await expect(store.discoverHosts("proj-1")).rejects.toThrow();
  });
});
