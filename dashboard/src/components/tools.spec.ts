import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/api", () => ({
  getDownloadableModels: vi.fn(),
  getModelsList: vi.fn(),
}));

import { getDownloadableModels, getModelsList, type OllamaModelData } from "@/api";
import { aiModelsManager } from "@/components/tools";

function makeModel(overrides: Partial<OllamaModelData> = {}): OllamaModelData {
  return {
    family: "llama",
    name: "llama3:8b",
    parameters_size_b: 8,
    thinking: false,
    context_window: 4096,
    size_gb: 4.5,
    recommended: null,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  aiModelsManager.downloadable_models.value = [];
  aiModelsManager.installed_models.value = [];
});

describe("getModelsByFamily", () => {
  it("groups models by family, preserving first-appearance order of families and models within each group", () => {
    const a = makeModel({ name: "a", family: "llama" });
    const b = makeModel({ name: "b", family: "mistral" });
    const c = makeModel({ name: "c", family: "llama" });
    aiModelsManager.downloadable_models.value = [a, b, c];

    const grouped = aiModelsManager.getModelsByFamily();

    expect(Object.keys(grouped)).toEqual(["llama", "mistral"]);
    expect(grouped.llama).toEqual([a, c]);
    expect(grouped.mistral).toEqual([b]);
  });

  it("returns {} for an empty model list", () => {
    expect(aiModelsManager.getModelsByFamily()).toEqual({});
  });
});

describe("getRecommendedAgentModels / getRecommendedParsingModels", () => {
  it("filters by exact recommended value, excluding other/null/undefined values, preserving order", () => {
    const agentModel = makeModel({ name: "agent-1", recommended: "agent" });
    const parsingModel = makeModel({ name: "parsing-1", recommended: "parsing" });
    const nullRecommended = makeModel({ name: "none", recommended: null });
    const undefinedRecommended = makeModel({ name: "also-none" });
    delete (undefinedRecommended as { recommended?: unknown }).recommended;

    aiModelsManager.downloadable_models.value = [
      agentModel,
      nullRecommended,
      parsingModel,
      undefinedRecommended,
    ];

    expect(aiModelsManager.getRecommendedAgentModels()).toEqual([agentModel]);
    expect(aiModelsManager.getRecommendedParsingModels()).toEqual([parsingModel]);
  });
});

describe("refreshDownloadableModels vs refreshInstalledModels on API error (fixed: consistent)", () => {
  it("refreshDownloadableModels preserves the previous list on an API error", async () => {
    const previous = [makeModel({ name: "kept" })];
    aiModelsManager.downloadable_models.value = previous;
    vi.mocked(getDownloadableModels).mockResolvedValue({
      error: { detail: [] },
    } as never);

    await aiModelsManager.refreshDownloadableModels();

    expect(aiModelsManager.downloadable_models.value).toEqual(previous);
  });

  it("refreshInstalledModels preserves the previous list on an API error", async () => {
    const previous = [makeModel({ name: "was-installed" })];
    aiModelsManager.installed_models.value = previous;
    vi.mocked(getModelsList).mockResolvedValue({
      error: { detail: [] },
    } as never);

    await aiModelsManager.refreshInstalledModels();

    expect(aiModelsManager.installed_models.value).toEqual(previous);
  });
});
