import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, DOMWrapper } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import ProjectDialog from "./ProjectDialog.vue";
import { useMomosStore } from "@/store/momos_store";
import type { OllamaModelData } from "@/api";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
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
  getDownloadableModels: vi.fn(),
  getModelsList: vi.fn(),
}));

import { getDownloadableModels, getModelsList } from "@/api";

const AGENT_MODEL: OllamaModelData = {
  name: "agent-model-1",
  family: "test-family",
  parameters_size_b: 7,
  thinking: false,
  context_window: 4000,
  size_gb: 4,
  recommended: "agent",
};

const PARSING_MODEL: OllamaModelData = {
  name: "parsing-model-1",
  family: "test-family",
  parameters_size_b: 3,
  thinking: false,
  context_window: 4000,
  size_gb: 2,
  recommended: "parsing",
};

function mountDialog() {
  const pinia = createTestingPinia({ stubActions: true });
  const store = useMomosStore(pinia);
  vi.mocked(store.addProject).mockResolvedValue(undefined as never);

  const wrapper = mount(ProjectDialog, {
    props: { modelValue: true },
    global: {
      plugins: [pinia],
      mocks: { $t: (key: string) => key },
    },
  });

  // Dialog.vue teleports its whole slot content to document.body, so none
  // of this dialog's fields are reachable through the mounted wrapper's own
  // element tree - every query here goes through document.body, same as
  // TargetSettingsDialog.spec.ts.
  const body = new DOMWrapper(document.body);

  function inputByLabel(labelText: string) {
    const group = body
      .findAll(".input-wrapper")
      .find((g) => g.find(".floating-label").text() === labelText);
    if (!group) throw new Error(`No .input-wrapper with label "${labelText}"`);
    return group.find("input");
  }

  function aiBoxByModelName(modelName: string) {
    const box = body
      .findAll(".ai-box")
      .find((b) => b.find(".model-name").text() === modelName);
    if (!box) throw new Error(`No .ai-box for model "${modelName}"`);
    return box;
  }

  function addButton() {
    return body.findAll("button").find((b) => b.text() === "universal.add")!;
  }

  return { wrapper, store, inputByLabel, aiBoxByModelName, addButton };
}

async function fillValidNameAndModels(ctx: ReturnType<typeof mountDialog>) {
  await ctx.inputByLabel("project.name").setValue("My Project");
  await ctx.aiBoxByModelName(AGENT_MODEL.name).trigger("click");
  await ctx.aiBoxByModelName(PARSING_MODEL.name).trigger("click");
}

beforeEach(() => {
  vi.mocked(getDownloadableModels).mockResolvedValue({
    data: { models: [AGENT_MODEL, PARSING_MODEL] },
  } as never);
  vi.mocked(getModelsList).mockResolvedValue({
    data: { models: [AGENT_MODEL, PARSING_MODEL] },
  } as never);
});

afterEach(() => {
  // Dialog.vue teleports to document.body, and jsdom's document persists
  // across tests within this file.
  document.body.innerHTML = "";
});

describe("ProjectDialog scope range wiring", () => {
  it("calls store.addProject with the entered name, models and scope range in order", async () => {
    const ctx = mountDialog();
    const { wrapper, store } = ctx;
    await wrapper.vm.$nextTick();
    await Promise.resolve();
    await Promise.resolve();

    await fillValidNameAndModels(ctx);
    await ctx.inputByLabel("project.host_range").setValue("192.168.1.0/24");
    await ctx.inputByLabel("project.port_range_start").setValue(80);
    await ctx.inputByLabel("project.port_range_end").setValue(443);

    await ctx.addButton().trigger("click");
    await wrapper.vm.$nextTick();

    expect(store.addProject).toHaveBeenCalledTimes(1);
    expect(store.addProject).toHaveBeenCalledWith(
      "My Project",
      AGENT_MODEL.name,
      PARSING_MODEL.name,
      "192.168.1.0/24",
      80,
      443,
    );
  });

  it("blocks submission when the host range is empty, even with a valid name and models", async () => {
    const ctx = mountDialog();
    const { wrapper, store } = ctx;
    await wrapper.vm.$nextTick();
    await Promise.resolve();
    await Promise.resolve();

    await fillValidNameAndModels(ctx);
    // host range left at its default empty value

    expect(ctx.addButton().attributes("disabled")).toBeDefined();

    await ctx.addButton().trigger("click");
    await wrapper.vm.$nextTick();

    expect(store.addProject).not.toHaveBeenCalled();
  });

  it("allows submission once a host range is filled in", async () => {
    const ctx = mountDialog();
    const { wrapper, store } = ctx;
    await wrapper.vm.$nextTick();
    await Promise.resolve();
    await Promise.resolve();

    await fillValidNameAndModels(ctx);
    await ctx.inputByLabel("project.host_range").setValue("10.0.0.0/24");

    expect(ctx.addButton().attributes("disabled")).toBeUndefined();

    await ctx.addButton().trigger("click");
    await wrapper.vm.$nextTick();

    expect(store.addProject).toHaveBeenCalledTimes(1);
  });
});
