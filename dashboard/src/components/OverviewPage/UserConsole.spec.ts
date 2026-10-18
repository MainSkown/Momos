import { beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import UserConsole from "./UserConsole.vue";

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
  createKaliUser: vi.fn(),
  getProjectKaliClient: vi.fn(),
  getConsoleSessions: vi.fn(),
}));

// A real reference-equality hooks map mirroring websocket_client.ts's own
// hook_exists/add_hook/remove_hook - lets both the leak test (AgentRunButton)
// and this component's own (correct) teardown be asserted against genuine
// registration state instead of a canned mock return.
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

import { createKaliUser, getProjectKaliClient, getConsoleSessions } from "@/api";
import { useWebSocketClient } from "@/websockets/websocket_client";

function fakeClient() {
  return useWebSocketClient() as unknown as {
    add_hook: ReturnType<typeof vi.fn>;
    hook_exists: ReturnType<typeof vi.fn> & ((type: string, cb: (msg: unknown) => void) => boolean);
    remove_hook: ReturnType<typeof vi.fn>;
  };
}

function mountConsole(openedProject = "project-1") {
  const pinia = createTestingPinia({
    stubActions: true,
    initialState: {
      momos: {
        openedProject,
        projects: [{ id: openedProject, name: "P" }],
        cmd_outputs: {},
      },
    },
  });

  const wrapper = mount(UserConsole, {
    global: { plugins: [pinia] },
  });

  return { wrapper };
}

beforeEach(() => {
  vi.mocked(getProjectKaliClient).mockReset().mockResolvedValue({ data: undefined } as never);
  vi.mocked(getConsoleSessions).mockReset().mockResolvedValue({ data: [] } as never);
  vi.mocked(createKaliUser).mockReset();
  fakeClient().add_hook.mockClear();
  fakeClient().hook_exists.mockClear();
  fakeClient().remove_hook.mockClear();
});

describe("UserConsole createNewKaliUser loading-flag gap", () => {
  it("confirmed bug: a failed connect leaves loading_dict stuck true, showing 'connecting' forever", async () => {
    vi.mocked(createKaliUser).mockResolvedValue({
      data: undefined,
      error: { message: "boom" },
    } as never);

    const { wrapper } = mountConsole();
    await flushPromises();

    const connectButton = wrapper.find(".connect-button");
    expect(connectButton.exists()).toBe(true);

    await connectButton.trigger("click");
    await flushPromises();

    // Bug: createNewKaliUser's `if (!result.data) { ...; return; }` branch
    // never resets loading_dict[project_id] back to false, and no
    // CreatedKaliUserMessage will ever arrive to do it via onKaliCreated -
    // the console is stuck showing the "connecting" placeholder.
    expect(wrapper.find(".connecting").exists()).toBe(true);
    expect(wrapper.text()).toContain("console.connecting");
    expect(wrapper.find(".connect-button").exists()).toBe(false);
  });

  it("contrast: a successful connect followed by the CreatedKaliUserMessage push clears the loading flag", async () => {
    vi.mocked(createKaliUser).mockResolvedValue({
      data: { client_id: "client-1" },
    } as never);

    const { wrapper } = mountConsole();
    await flushPromises();

    await wrapper.find(".connect-button").trigger("click");
    await flushPromises();

    // Still "connecting" at this point - createNewKaliUser's success path
    // does not itself clear loading_dict; only the websocket push does.
    expect(wrapper.find(".connecting").exists()).toBe(true);

    const createdCall = fakeClient().add_hook.mock.calls.find(
      (call) => call[0] === "CreatedKaliUserMessage",
    );
    expect(createdCall).toBeDefined();
    const onKaliCreated = createdCall![1] as (msg: unknown) => void;

    onKaliCreated({
      type: "CreatedKaliUserMessage",
      project_id: "project-1",
      client_id: "client-1",
    });
    await flushPromises();

    expect(wrapper.find(".connecting").exists()).toBe(false);
    // client_dict is now set for this project, so the console body (not
    // the empty/connect state) renders.
    expect(wrapper.find(".terminal-output-screen").exists()).toBe(true);
  });
});

describe("UserConsole websocket hook teardown (reference/positive case)", () => {
  it("removes its registered hooks onUnmounted, unlike AgentRunButton", async () => {
    const { wrapper } = mountConsole();
    await flushPromises();

    const createdCall = fakeClient().add_hook.mock.calls.find(
      (call) => call[0] === "ConsoleSessionCreatedMessage",
    );
    expect(createdCall).toBeDefined();
    const callback = createdCall![1] as (msg: unknown) => void;

    expect(fakeClient().hook_exists("ConsoleSessionCreatedMessage", callback)).toBe(true);

    wrapper.unmount();

    // UserConsole collects each add_hook's {delete} handle in hook_handles
    // and calls handle.delete() for every one of them onUnmounted - so,
    // unlike AgentRunButton, the callback is genuinely gone afterward.
    expect(fakeClient().hook_exists("ConsoleSessionCreatedMessage", callback)).toBe(false);
  });
});
