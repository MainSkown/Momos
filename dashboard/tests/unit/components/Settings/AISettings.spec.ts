import { beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import AISettings from "@/components/Settings/AISettings.vue";
import { useMomosStore } from "@/store/momos_store";
import type { OllamaConnectionPublic, OllamaModelData } from "@/api/types.gen";

const translations: Record<string, string> = {
  "models.no_search_results": "No models match your search.",
  "models.all_models": "All models",
  "models.installed": "Installed",
  "models.recommended_agent": "Recommended — Agent",
  "models.recommended_parsing": "Recommended — Parsing",
};

function fakeT(key: string, params?: Record<string, unknown>): string {
  let message = translations[key] ?? key;
  if (params) {
    for (const [paramKey, value] of Object.entries(params)) {
      message = message.replace(`{${paramKey}}`, String(value));
    }
  }
  return message;
}

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: fakeT }),
}));

vi.mock("@/components/tools", () => ({
  aiModelsManager: {
    downloadable_models: { value: [] as OllamaModelData[] },
    installed_models: { value: [] as OllamaModelData[] },
    initialize: vi.fn().mockResolvedValue(undefined),
    refreshInstalledModels: vi.fn().mockResolvedValue(undefined),
  },
}));

import { aiModelsManager } from "@/components/tools";

const AIBoxStub = {
  name: "AIBoxStub",
  props: ["model", "installed", "selected"],
  template: `<div
    class="ai-box-stub"
    :data-name="model.name"
    :data-family="model.family"
    :data-installed="installed"
    :data-selected="selected"
    :data-recommended="model.recommended ?? ''"
  ></div>`,
};

function makeModel(overrides: Partial<OllamaModelData> = {}): OllamaModelData {
  return {
    family: "llama",
    name: "llama3:8b",
    parameters_size_b: 8,
    thinking: false,
    context_window: 8000,
    size_gb: 4.5,
    recommended: null,
    ...overrides,
  };
}

function makeConnection(overrides: Partial<OllamaConnectionPublic> = {}): OllamaConnectionPublic {
  return {
    mode: "local",
    remote_url: "",
    has_remote_api_key: false,
    ...overrides,
  };
}

function mountComponent(
  ollamaConnection: OllamaConnectionPublic | null = makeConnection(),
  props: Record<string, unknown> = {},
) {
  const pinia = createTestingPinia({
    initialState: {
      momos: { ollama_connection: ollamaConnection },
    },
  });
  const store = useMomosStore(pinia);

  const wrapper = mount(AISettings, {
    props,
    global: {
      plugins: [pinia],
      mocks: { $t: fakeT },
      stubs: { AIBox: AIBoxStub, ConnectionSettings: true },
    },
  });

  return { wrapper, store };
}

function cardsByName(wrapper: ReturnType<typeof mountComponent>["wrapper"], name: string) {
  return wrapper.findAll(".ai-box-stub").filter((c) => c.attributes("data-name") === name);
}

function clickFilter(wrapper: ReturnType<typeof mountComponent>["wrapper"], filterId: string) {
  return wrapper.find(`[data-filter-id="${filterId}"]`).trigger("click");
}

beforeEach(() => {
  aiModelsManager.downloadable_models.value = [];
  aiModelsManager.installed_models.value = [];
  vi.mocked(aiModelsManager.initialize).mockClear();
  vi.mocked(aiModelsManager.refreshInstalledModels).mockClear();
});

describe("AISettings merged model list", () => {
  it("renders exactly one card for a model present in both lists, keeping installed:true and its recommended tag", async () => {
    aiModelsManager.downloadable_models.value = [
      makeModel({ name: "agentmodel:7b", family: "qwen", recommended: "agent" }),
    ];
    aiModelsManager.installed_models.value = [
      makeModel({ name: "agentmodel:7b", family: "qwen", recommended: null }),
    ];

    const { wrapper } = mountComponent();
    await flushPromises();

    const allCards = cardsByName(wrapper, "agentmodel:7b");
    expect(allCards).toHaveLength(1);
    expect(allCards[0]!.attributes("data-installed")).toBe("true");
    expect(allCards[0]!.attributes("data-recommended")).toBe("agent");

    await clickFilter(wrapper, "family:qwen");
    const familyCards = cardsByName(wrapper, "agentmodel:7b");
    expect(familyCards).toHaveLength(1);
    expect(familyCards[0]!.attributes("data-installed")).toBe("true");
    expect(familyCards[0]!.attributes("data-recommended")).toBe("agent");
  });

  it("still shows a model that only exists in installed_models, under All models and its own family filter", async () => {
    aiModelsManager.downloadable_models.value = [
      makeModel({ name: "catalog-model:3b", family: "mistral" }),
    ];
    aiModelsManager.installed_models.value = [
      makeModel({ name: "manually-pulled:1b", family: "custom-family", recommended: null }),
    ];

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(cardsByName(wrapper, "manually-pulled:1b")).toHaveLength(1);

    await clickFilter(wrapper, "family:custom-family");
    expect(cardsByName(wrapper, "manually-pulled:1b")).toHaveLength(1);
    expect(cardsByName(wrapper, "catalog-model:3b")).toHaveLength(0);
  });
});

describe("AISettings sidebar filters", () => {
  it("filters the grid to the selected bucket and computes counts from the merged list", async () => {
    aiModelsManager.downloadable_models.value = [
      makeModel({ name: "shared:8b", family: "A", recommended: "agent" }),
      makeModel({ name: "catalog-only:2b", family: "B", recommended: "parsing" }),
    ];
    aiModelsManager.installed_models.value = [
      makeModel({ name: "shared:8b", family: "A", recommended: null }),
      makeModel({ name: "installed-only:1b", family: "C", recommended: null }),
    ];

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.find('[data-filter-id="all"]').text()).toContain("3");
    expect(wrapper.find('[data-filter-id="installed"]').text()).toContain("2");
    expect(wrapper.find('[data-filter-id="family:A"]').text()).toContain("1");
    expect(wrapper.find('[data-filter-id="family:B"]').text()).toContain("1");
    expect(wrapper.find('[data-filter-id="family:C"]').text()).toContain("1");

    await clickFilter(wrapper, "installed");

    const visibleNames = wrapper
      .findAll(".ai-box-stub")
      .map((c) => c.attributes("data-name"));
    expect(visibleNames.sort()).toEqual(["installed-only:1b", "shared:8b"]);
  });
});

describe("AISettings search", () => {
  it("narrows the active filter by name and shows the empty-results message when nothing matches", async () => {
    aiModelsManager.downloadable_models.value = [
      makeModel({ name: "alpha-model:7b", family: "A" }),
    ];
    aiModelsManager.installed_models.value = [
      makeModel({ name: "alpha-model:7b", family: "A" }),
      makeModel({ name: "beta-model:7b", family: "A" }),
    ];

    const { wrapper } = mountComponent();
    await flushPromises();

    await clickFilter(wrapper, "installed");
    const searchInput = wrapper.find(".ai-settings-search-input");

    await searchInput.setValue("alpha");
    expect(cardsByName(wrapper, "alpha-model:7b")).toHaveLength(1);
    expect(cardsByName(wrapper, "beta-model:7b")).toHaveLength(0);

    await searchInput.setValue("nonexistent");
    expect(wrapper.findAll(".ai-box-stub")).toHaveLength(0);
    expect(wrapper.find(".ai-settings-empty").text()).toBe("No models match your search.");
  });
});

describe("AISettings embedded ConnectionSettings", () => {
  it("renders ConnectionSettings as a child when not selectable (standalone Settings usage)", async () => {
    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.find("connection-settings-stub").exists()).toBe(true);
  });

  it("does not render ConnectionSettings when selectable (ModelPickerDialog usage)", async () => {
    const { wrapper } = mountComponent(makeConnection(), { selectable: true });
    await flushPromises();

    expect(wrapper.find("connection-settings-stub").exists()).toBe(false);
  });
});

describe("AISettings AIBox contract", () => {
  it("still passes AIBox exactly the model/installed/selected props it receives today", async () => {
    aiModelsManager.downloadable_models.value = [
      makeModel({ name: "contract-model:7b", family: "A" }),
    ];
    aiModelsManager.installed_models.value = [];

    const { wrapper } = mountComponent();
    await flushPromises();

    const card = wrapper.findComponent(AIBoxStub);
    expect(Object.keys(card.props()).sort()).toEqual(["installed", "model", "selected"]);
    expect(card.props("installed")).toBe(false);
    expect(card.props("selected")).toBe(false);
    expect((card.props("model") as OllamaModelData).name).toBe("contract-model:7b");
  });
});
