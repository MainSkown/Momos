import { beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import AgentRunButton from "./AgentRunButton.vue";
import type { AgentRunResponse, ResponseTarget } from "@/api";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

vi.mock("vue3-toastify", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    POSITION: { TOP_CENTER: "top-center" },
  },
}));

vi.mock("@/api", () => ({
  getTargetAgentRun: vi.fn(),
  getTargetPendingInterrupts: vi.fn(),
  getProjectKaliStatus: vi.fn(),
  startAgent: vi.fn(),
  pauseAgent: vi.fn(),
  finishAgent: vi.fn(),
}));

// A real reference-equality hooks map, mirroring websocket_client.ts's own
// hook_exists/add_hook/remove_hook exactly - this is what lets the
// hook-leak test below assert genuine state (whether the callback is still
// registered) rather than a canned mock return.
vi.mock("@/websockets/websocket_client", () => {
  const hooks: Record<string, Array<(msg: unknown) => void>> = {};

  const hook_exists = vi.fn(
    (type: string, cb: (msg: unknown) => void) =>
      hooks[type]?.some((c) => c === cb) ?? false,
  );
  const remove_hook = vi.fn((type: string, cb: (msg: unknown) => void) => {
    hooks[type] = (hooks[type] ?? []).filter((c) => c !== cb);
  });
  const add_hook = vi.fn((type: string, cb: (msg: unknown) => void) => {
    if (!hooks[type]) hooks[type] = [];
    if (hook_exists(type, cb)) return undefined;
    hooks[type].push(cb);
    return { delete: () => remove_hook(type, cb) };
  });
  const send_message = vi.fn();

  return {
    useWebSocketClient: () => ({ hooks, hook_exists, add_hook, remove_hook, send_message }),
  };
});

import {
  getTargetAgentRun,
  getTargetPendingInterrupts,
  getProjectKaliStatus,
  startAgent,
  pauseAgent,
} from "@/api";
import { useWebSocketClient } from "@/websockets/websocket_client";

function makeTarget(overrides: Partial<ResponseTarget> = {}): ResponseTarget {
  return {
    id: "target-1",
    project_id: "project-1",
    name: "Target 1",
    ipv4: null,
    ipv6: null,
    description: null,
    ports: null,
    task_duration: 600,
    run_mode: "timer",
    safety_cap_duration: null,
    ...overrides,
  };
}

function makeRun(overrides: Partial<AgentRunResponse> = {}): AgentRunResponse {
  return {
    status: "running",
    remaining_seconds: 120,
    recorded_at: new Date().toISOString(),
    ...overrides,
  } as AgentRunResponse;
}

function mountButton(target: ResponseTarget) {
  const pinia = createTestingPinia({ stubActions: true });

  const wrapper = mount(AgentRunButton, {
    props: { target },
    global: { plugins: [pinia] },
  });

  return { wrapper };
}

beforeEach(() => {
  vi.mocked(getTargetAgentRun).mockReset().mockResolvedValue({ data: null } as never);
  vi.mocked(getTargetPendingInterrupts).mockReset().mockResolvedValue({ data: [] } as never);
  vi.mocked(getProjectKaliStatus).mockReset().mockResolvedValue({ data: null } as never);
  vi.mocked(startAgent).mockReset().mockResolvedValue({ data: {} } as never);
  vi.mocked(pauseAgent).mockReset().mockResolvedValue({ data: {} } as never);
  const client = useWebSocketClient() as unknown as {
    add_hook: ReturnType<typeof vi.fn>;
    hook_exists: ReturnType<typeof vi.fn>;
    remove_hook: ReturnType<typeof vi.fn>;
  };
  client.add_hook.mockClear();
  client.hook_exists.mockClear();
  client.remove_hook.mockClear();
});

describe("AgentRunButton websocket hook teardown", () => {
  it("registers hooks onMounted and removes them onUnmounted (fixed resource leak)", async () => {
    const { wrapper } = mountButton(makeTarget());
    await flushPromises();

    const client = useWebSocketClient() as unknown as {
      add_hook: ReturnType<typeof vi.fn>;
      hook_exists: (type: string, cb: (msg: unknown) => void) => boolean;
      remove_hook: ReturnType<typeof vi.fn>;
    };

    const runTimerCall = client.add_hook.mock.calls.find(
      (call) => call[0] === "AgentRunTimer",
    );
    expect(runTimerCall).toBeDefined();
    const registeredCallback = runTimerCall![1] as (msg: unknown) => void;

    // Sanity: the hook really is live right after mount.
    expect(client.hook_exists("AgentRunTimer", registeredCallback)).toBe(true);

    wrapper.unmount();

    // Fixed: AgentRunButton now collects each add_hook's {delete} handle
    // (hook_handles) and calls it onUnmounted, same as UserConsole.vue -
    // the callback is genuinely gone afterward instead of staying live in
    // the hooks map as a closure over a torn-down component.
    expect(client.hook_exists("AgentRunTimer", registeredCallback)).toBe(false);
    expect(client.remove_hook).toHaveBeenCalledWith("AgentRunTimer", registeredCallback);
  });
});

describe("AgentRunButton render-state branches (happy path)", () => {
  it("shows the start button and calls startAgent when a fresh target has no run", async () => {
    const { wrapper } = mountButton(makeTarget());
    await flushPromises();

    const startButton = wrapper.find("button.no-border:not(.timer-button)");
    expect(startButton.exists()).toBe(true);
    expect(startButton.attributes("disabled")).toBeUndefined();
    expect(startButton.find(".material-icons-outlined").text()).toBe("play_arrow");

    await startButton.trigger("click");
    await flushPromises();

    expect(startAgent).toHaveBeenCalledWith({
      path: { project_id: "project-1", target_id: "target-1" },
    });
  });

  it("disables the start button with a timer_off icon when timer mode has no duration", async () => {
    const { wrapper } = mountButton(makeTarget({ task_duration: null }));
    await flushPromises();

    const startButton = wrapper.find("button.no-border:not(.timer-button)");
    expect(startButton.attributes("disabled")).toBeDefined();
    expect(startButton.find(".material-icons-outlined").text()).toBe("timer_off");
  });

  it("shows the live countdown and calls pauseAgent on click while running", async () => {
    vi.mocked(getTargetAgentRun).mockResolvedValue({
      data: makeRun({ status: "running", remaining_seconds: 61 }),
    } as never);

    const { wrapper } = mountButton(makeTarget());
    await flushPromises();

    const timerButton = wrapper.find("button.timer-button");
    expect(timerButton.exists()).toBe(true);
    expect(timerButton.find(".timer-text").text()).toBe("00:01:01");

    await timerButton.trigger("click");
    await flushPromises();

    expect(pauseAgent).toHaveBeenCalledWith({
      path: { project_id: "project-1", target_id: "target-1" },
    });
  });

  it("shows the resume icon and calls startAgent on click while paused", async () => {
    vi.mocked(getTargetAgentRun).mockResolvedValue({
      data: makeRun({ status: "paused", remaining_seconds: 30 }),
    } as never);

    const { wrapper } = mountButton(makeTarget());
    await flushPromises();

    const timerButton = wrapper.find("button.timer-button");
    expect(timerButton.find(".material-icons-outlined").text()).toBe("play_circle");

    await timerButton.trigger("click");
    await flushPromises();

    expect(startAgent).toHaveBeenCalledWith({
      path: { project_id: "project-1", target_id: "target-1" },
    });
  });

  it("marks the timer button as interrupted and does not call pauseAgent on click", async () => {
    vi.mocked(getTargetAgentRun).mockResolvedValue({
      data: makeRun({ status: "interrupted", remaining_seconds: 15 }),
    } as never);

    const { wrapper } = mountButton(makeTarget());
    await flushPromises();

    const timerButton = wrapper.find("button.timer-button");
    expect(timerButton.classes()).toContain("timer-button--interrupted");

    await timerButton.trigger("click");
    await flushPromises();

    // handleClick routes "interrupted" into handlePause, which itself
    // no-ops (status guard requires "running") - no API call should fire.
    expect(pauseAgent).not.toHaveBeenCalled();
  });
});
