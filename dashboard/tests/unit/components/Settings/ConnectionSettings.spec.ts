import { beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import ConnectionSettings from "@/components/Settings/ConnectionSettings.vue";
import { useMomosStore } from "@/store/momos_store";
import type { OllamaConnectionPublic } from "@/api/types.gen";

// Serializes interpolation params onto the key instead of dropping them,
// mirroring ProjectSettingsPage.spec.ts's convention, so a call like
// t("settings.connection_status_remote", { url }) stays assertable.
function fakeT(key: string, params?: Record<string, unknown>): string {
  return params ? `${key}::${JSON.stringify(params)}` : key;
}

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: fakeT }),
}));

vi.mock("vue3-toastify", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    info: vi.fn(),
    POSITION: { TOP_CENTER: "top-center" },
  },
}));

vi.mock("@/api", () => ({
  getOllamaConnection: vi.fn(),
  updateOllamaConnection: vi.fn(),
  testOllamaConnection: vi.fn(),
}));

vi.mock("@/components/tools", () => ({
  aiModelsManager: { refreshInstalledModels: vi.fn() },
}));

import { getOllamaConnection, updateOllamaConnection, testOllamaConnection } from "@/api";
import { aiModelsManager } from "@/components/tools";
import { toast } from "vue3-toastify";

function makeConnection(overrides: Partial<OllamaConnectionPublic> = {}): OllamaConnectionPublic {
  return {
    mode: "local",
    remote_url: "",
    has_remote_api_key: false,
    ...overrides,
  };
}

function mountComponent() {
  const pinia = createTestingPinia({ stubActions: false });
  const store = useMomosStore(pinia);

  const wrapper = mount(ConnectionSettings, {
    global: {
      plugins: [pinia],
      mocks: { $t: fakeT },
    },
  });

  return { wrapper, store };
}

async function expandCard(wrapper: ReturnType<typeof mount>) {
  await wrapper.find(".connection-header").trigger("click");
  await flushPromises();
}

beforeEach(() => {
  vi.mocked(getOllamaConnection).mockReset();
  vi.mocked(updateOllamaConnection).mockReset();
  vi.mocked(testOllamaConnection).mockReset();
  vi.mocked(aiModelsManager.refreshInstalledModels).mockReset();
  vi.mocked(toast.error).mockClear();
  vi.mocked(toast.success).mockClear();
});

describe("ConnectionSettings load", () => {
  it("hides Remote-only fields for a loaded Local connection, and shows the keep-current-key placeholder immediately on switching to Remote", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "local",
        remote_url: "https://old.example.com",
        has_remote_api_key: true,
      }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    expect(wrapper.find(".remote-url-input").exists()).toBe(false);
    expect(wrapper.find(".remote-api-key-input").exists()).toBe(false);

    await wrapper.find("#connection-mode-remote").setValue(true);
    await flushPromises();

    const urlInput = wrapper.find(".remote-url-input");
    expect(urlInput.exists()).toBe(true);
    expect((urlInput.element as HTMLInputElement).value).toBe("https://old.example.com");

    const keyInput = wrapper.find(".remote-api-key-input");
    expect((keyInput.element as HTMLInputElement).value).toBe("");
    expect(keyInput.attributes("placeholder")).toBe(
      "settings.connection_remote_api_key_placeholder_keep",
    );
  });
});

describe("ConnectionSettings client-side validation", () => {
  it("never calls updateOllamaConnection when Save is clicked with an empty Remote URL", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({ mode: "local", remote_url: "", has_remote_api_key: false }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find("#connection-mode-remote").setValue(true);
    await flushPromises();
    expect(wrapper.find(".remote-url-input").exists()).toBe(true);

    await wrapper.find(".save-connection-button").trigger("click");
    await flushPromises();

    expect(updateOllamaConnection).not.toHaveBeenCalled();
  });
});

describe("ConnectionSettings Test Connection", () => {
  it("renders the reachable status with latency from the mocked response", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "remote",
        remote_url: "https://ollama.example.com",
        has_remote_api_key: false,
      }),
      response: { status: 200 },
    } as never);
    vi.mocked(testOllamaConnection).mockResolvedValue({
      data: { reachable: true, latency_ms: 123 },
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find(".test-connection-button").trigger("click");
    await flushPromises();

    expect(wrapper.find(".connection-test-result").text()).toContain("settings.connection_reachable");
    expect(wrapper.find(".connection-test-result").text()).toContain('"ms":123');
  });

  it("renders the distinct error string from an unreachable response", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "remote",
        remote_url: "https://ollama.example.com",
        has_remote_api_key: false,
      }),
      response: { status: 200 },
    } as never);
    vi.mocked(testOllamaConnection).mockResolvedValue({
      data: { reachable: false, error: "authentication failed" },
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find(".test-connection-button").trigger("click");
    await flushPromises();

    expect(wrapper.find(".connection-test-result").text()).toContain("authentication failed");
  });

  it("shows a test-failed status instead of an unhandled rejection when the request throws", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "remote",
        remote_url: "https://ollama.example.com",
        has_remote_api_key: false,
      }),
      response: { status: 200 },
    } as never);
    vi.mocked(testOllamaConnection).mockRejectedValue(new TypeError("network error"));

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find(".test-connection-button").trigger("click");
    await flushPromises();

    const resultEl = wrapper.find(".connection-test-result");
    expect(resultEl.exists()).toBe(true);
    expect(resultEl.classes()).toContain("text-red");
  });
});

describe("ConnectionSettings Save", () => {
  it("shows the 409 error message and keeps the unsaved form values on a blocked save", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "local",
        remote_url: "https://old.example.com",
        has_remote_api_key: false,
      }),
      response: { status: 200 },
    } as never);
    vi.mocked(updateOllamaConnection).mockResolvedValue({
      error: { detail: "Cannot switch while agents are running (2 agent run(s) still active.)" },
      response: { status: 409 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find("#connection-mode-remote").setValue(true);
    await flushPromises();
    await wrapper.find(".remote-url-input").setValue("https://new.example.com");

    await wrapper.find(".save-connection-button").trigger("click");
    await flushPromises();

    expect(wrapper.find(".save-error-message").text()).toContain(
      "Cannot switch while agents are running",
    );
    expect((wrapper.find(".remote-url-input").element as HTMLInputElement).value).toBe(
      "https://new.example.com",
    );
  });

  it("omits remote_api_key from the PUT body when the key field was never touched (fixed)", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "remote",
        remote_url: "https://old.example.com",
        has_remote_api_key: true,
      }),
      response: { status: 200 },
    } as never);
    vi.mocked(updateOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "remote",
        remote_url: "https://new.example.com",
        has_remote_api_key: true,
      }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find(".remote-url-input").setValue("https://new.example.com");

    await wrapper.find(".save-connection-button").trigger("click");
    await flushPromises();

    expect(updateOllamaConnection).toHaveBeenCalledTimes(1);
    const call = vi.mocked(updateOllamaConnection).mock.calls[0]![0] as {
      body: { remote_api_key?: string };
    };
    expect(call.body.remote_api_key).toBeUndefined();
    expect(JSON.stringify(call.body)).not.toContain("remote_api_key");
  });

  it("shows a save-failed message instead of an unhandled rejection when the request throws", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "local",
        remote_url: "https://old.example.com",
        has_remote_api_key: false,
      }),
      response: { status: 200 },
    } as never);
    vi.mocked(updateOllamaConnection).mockRejectedValue(new TypeError("network error"));

    const { wrapper } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find("#connection-mode-remote").setValue(true);
    await flushPromises();
    await wrapper.find(".remote-url-input").setValue("https://new.example.com");

    await wrapper.find(".save-connection-button").trigger("click");
    await flushPromises();

    expect(wrapper.find(".save-error-message").exists()).toBe(true);
    expect(wrapper.find(".save-error-message").text().length).toBeGreaterThan(0);
  });

  it("calls store.setOllamaConnection with the response data on a successful save", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({ mode: "local", remote_url: "", has_remote_api_key: false }),
      response: { status: 200 },
    } as never);
    const savedConnection = makeConnection({
      mode: "remote",
      remote_url: "https://new.example.com",
      has_remote_api_key: true,
    });
    vi.mocked(updateOllamaConnection).mockResolvedValue({
      data: savedConnection,
      response: { status: 200 },
    } as never);

    const { wrapper, store } = mountComponent();
    await flushPromises();
    await expandCard(wrapper);

    await wrapper.find("#connection-mode-remote").setValue(true);
    await flushPromises();
    await wrapper.find(".remote-url-input").setValue("https://new.example.com");

    await wrapper.find(".save-connection-button").trigger("click");
    await flushPromises();

    expect(store.setOllamaConnection).toHaveBeenCalledWith(savedConnection);
    expect(aiModelsManager.refreshInstalledModels).toHaveBeenCalledTimes(1);
  });
});

describe("ConnectionSettings collapse", () => {
  it("mounts collapsed by default, hiding the connection form", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({ mode: "local", remote_url: "", has_remote_api_key: false }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.find(".connection-header").exists()).toBe(true);
    expect(wrapper.find("#connection-mode-local").exists()).toBe(false);
    expect(wrapper.find(".save-connection-button").exists()).toBe(false);
  });

  it("expands the form when the header is clicked, and collapses it again on a second click", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({ mode: "local", remote_url: "", has_remote_api_key: false }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    await wrapper.find(".connection-header").trigger("click");
    await flushPromises();
    expect(wrapper.find("#connection-mode-local").exists()).toBe(true);
    expect(wrapper.find(".save-connection-button").exists()).toBe(true);

    await wrapper.find(".connection-header").trigger("click");
    await flushPromises();
    expect(wrapper.find("#connection-mode-local").exists()).toBe(false);
    expect(wrapper.find(".save-connection-button").exists()).toBe(false);
  });

  it("still shows the load-error message while collapsed", async () => {
    vi.mocked(getOllamaConnection).mockRejectedValue(new TypeError("network error"));

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.find("#connection-mode-local").exists()).toBe(false);
    expect(wrapper.text()).toContain("settings.connection_load_error");
  });
});

describe("ConnectionSettings collapsed summary", () => {
  it("shows a Local summary for a loaded Local connection", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({ mode: "local", remote_url: "", has_remote_api_key: false }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.find(".connection-summary").text()).toBe("settings.connection_status_local");
  });

  it("shows a Remote summary with the remote URL for a loaded Remote connection", async () => {
    vi.mocked(getOllamaConnection).mockResolvedValue({
      data: makeConnection({
        mode: "remote",
        remote_url: "https://ollama.example.com",
        has_remote_api_key: false,
      }),
      response: { status: 200 },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    const summary = wrapper.find(".connection-summary").text();
    expect(summary).toContain("settings.connection_status_remote");
    expect(summary).toContain('"url":"https://ollama.example.com"');
  });
});
