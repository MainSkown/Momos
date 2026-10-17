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
  updateTarget,
  type ResponseTarget,
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
  it("writes to targets[-1] instead of updating anything when the id is unknown (confirmed bug)", async () => {
    vi.mocked(updateTarget).mockResolvedValue({ response: { status: 200 } } as never);
    const store = useMomosStore();
    const existing = makeTarget({ id: "known" });
    store.targets = [existing];
    const unknown = makeTarget({ id: "does-not-exist", name: "new-name" });

    await store.updateTarget(unknown);

    expect(store.targets).toHaveLength(1);
    expect(store.targets[0]).toEqual(existing);
    expect((store.targets as unknown as Record<string, ResponseTarget>)["-1"]).toEqual(
      unknown,
    );
  });
});

describe("loadQueue", () => {
  it("called twice duplicates both the queue entry and its websocket hook (confirmed bug)", async () => {
    vi.mocked(getOllamaDownloadQueueDetails).mockResolvedValue({
      data: { current: null, queue: ["llama3"] },
    } as never);
    const store = useMomosStore();

    await store.loadQueue();
    await store.loadQueue();

    expect(
      store.download_queue.filter((q) => q.model_name === "llama3"),
    ).toHaveLength(2);
    expect(useWebSocketClient().add_hook).toHaveBeenCalledTimes(2);
  });
});

describe("deleteProject", () => {
  it("leaves stale sessions/running_targets/attack_vectors/session_detail entries behind (confirmed bug)", async () => {
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
    expect(store.sessions[pid]).toHaveLength(1);
    expect(store.running_targets[pid]).toBe(tid);
    expect(store.attack_vectors[tid]).toHaveLength(1);
    expect(store.session_detail[sid]).toBeDefined();
  });
});

describe("deleteTarget", () => {
  it("leaves stale running_targets/attack_vectors entries behind (confirmed bug)", async () => {
    vi.mocked(deleteTarget).mockResolvedValue({ response: { status: 204 } } as never);
    const store = useMomosStore();
    const pid = "proj-1";
    const tid = "target-1";

    store.targets = [makeTarget({ id: tid, project_id: pid })];
    store.running_targets[pid] = tid;
    store.attack_vectors[tid] = [{ id: "vec-1" } as never];

    await store.deleteTarget(tid);

    expect(store.targets).toEqual([]);
    expect(store.running_targets[pid]).toBe(tid);
    expect(store.attack_vectors[tid]).toHaveLength(1);
  });
});
