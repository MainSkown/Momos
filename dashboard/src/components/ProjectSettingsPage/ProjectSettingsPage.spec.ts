import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises, type VueWrapper } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import ProjectSettingsPage from "./ProjectSettingsPage.vue";
import { useMomosStore } from "@/store/momos_store";
import type { ProjectSettings } from "@/api";

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
  getProjectSettings: vi.fn(),
  updateProjectSettings: vi.fn(),
}));

import { getProjectSettings, updateProjectSettings } from "@/api";

function makeSettings(overrides: Partial<ProjectSettings> = {}): ProjectSettings {
  return {
    project_id: "project-a",
    should_interrupt: false,
    starting_prompt: "",
    base_model_name: "",
    parsing_model_name: "",
    pipeline_mode: "single_agent",
    ...overrides,
  };
}

function mountPage(
  openedProject = "project-a",
  momosOverrides: { user_settings?: { global_max_concurrent_agents?: number } | null } = {},
  // Invoked right after the store exists but before mount, so a test can
  // mock a store action (e.g. getAcknowledgmentStatus) before the
  // component's onMounted hook ever calls it - mocking it only after
  // mountPage returns would be too late for that first call.
  setupStore: (store: ReturnType<typeof useMomosStore>) => void = () => {},
) {
  // ProjectSettingsPage teleports its save-status text into this element
  // (see its <Teleport to="#context-header-extra"> at the top of the
  // template) - it must exist in the DOM or Vue warns and renders nothing
  // there, though the rest of the page is unaffected either way.
  document.getElementById("context-header-extra")?.remove();
  const teleportTarget = document.createElement("div");
  teleportTarget.id = "context-header-extra";
  document.body.appendChild(teleportTarget);

  const pinia = createTestingPinia({
    stubActions: true,
    initialState: {
      momos: { openedProject, running_targets: {}, projects: [], ...momosOverrides },
    },
  });
  const store = useMomosStore(pinia);

  // Stubbed by default (stubActions: true) means this would otherwise be a
  // bare vi.fn() returning undefined - the component's own onMounted calls
  // `.catch()` on the result, which would throw against that. Tests that
  // care about failure instead override this per-call.
  vi.mocked(store.loadUserSettings).mockResolvedValue(undefined);

  setupStore(store);

  const wrapper = mount(ProjectSettingsPage, {
    global: {
      plugins: [pinia],
      // ProjectSettingsPage.vue's template calls the global $t injected by
      // the app's i18n plugin directly (not the local `t` from its own
      // useI18n() call) - mirrors TargetSettingsDialog.spec.ts's pattern.
      // Params are serialized (not just dropped) so interpolated values
      // (e.g. the capped-globally note's {cap}) are actually assertable.
      mocks: {
        $t: (key: string, params?: Record<string, unknown>) =>
          params ? `${key}::${JSON.stringify(params)}` : key,
      },
    },
  });

  return { wrapper, store };
}

// Both the base-model button and the "choose tools" button share the same
// .model-select-button styling class, so locating by class alone is
// ambiguous - this finds a field by its label text instead, same as
// querying by a form field's accessible name would in a real browser.
function fieldGroupControl(wrapper: VueWrapper, labelText: string, selector: string) {
  const group = wrapper
    .findAll(".field-group")
    .find((g) => g.find("label").text() === labelText);
  if (!group) throw new Error(`No .field-group with label "${labelText}"`);
  return group.find(selector);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(getProjectSettings).mockReset();
  vi.mocked(updateProjectSettings).mockReset().mockResolvedValue({ data: {} } as never);
});

afterEach(() => {
  vi.useRealTimers();
  document.body.innerHTML = "";
});

describe("ProjectSettingsPage load_settings out-of-order race (fixed)", () => {
  it("project A's late-resolving fetch no longer overwrites project B's just-loaded settings after a mid-flight switch", async () => {
    let resolveA!: (value: unknown) => void;

    vi.mocked(getProjectSettings).mockImplementation(
      (({ path }: { path: { project_id: string } }) => {
        if (path.project_id === "project-a") {
          return new Promise((resolve) => {
            resolveA = resolve;
          });
        }
        return Promise.resolve({
          data: makeSettings({
            project_id: "project-b",
            base_model_name: "project-b-model",
          }),
        });
      }) as never,
    );

    const { wrapper, store } = mountPage("project-a");
    await flushPromises();

    // Project A's own fetch is still pending (resolveA not yet called) when
    // the user switches to project B.
    store.openedProject = "project-b";
    await flushPromises();

    // Sanity: project B's own (immediately-resolving) fetch has landed
    // correctly before A's stale response arrives.
    expect(
      fieldGroupControl(wrapper, "models.base_model", "button").text(),
    ).toBe("project-b-model");

    // Now project A's fetch, requested first but resolving last, comes
    // back - well after the user has moved on to project B.
    resolveA({
      data: makeSettings({
        project_id: "project-a",
        base_model_name: "project-a-model",
      }),
    });
    await flushPromises();

    // Fixed: load_settings now bails out when `projectID` no longer
    // equals store.openedProject after the await, so A's stale data never
    // overwrites project_settings - project B's page keeps showing its own
    // base model.
    expect(
      fieldGroupControl(wrapper, "models.base_model", "button").text(),
    ).toBe("project-b-model");

    // The deeper consequence is fixed too: the next edit still autosaves
    // under B's id, and now the body it sends is genuinely B's own
    // settings (with just this edit applied), not A's stale object.
    await fieldGroupControl(wrapper, "settings.should_interrupt", "input").setValue(true);
    await vi.advanceTimersByTimeAsync(800);

    expect(updateProjectSettings).toHaveBeenCalledTimes(1);
    const call = vi.mocked(updateProjectSettings).mock.calls[0]![0] as {
      path: { project_id: string };
      body: ProjectSettings;
    };
    expect(call.path.project_id).toBe("project-b");
    expect(call.body.base_model_name).toBe("project-b-model");
    expect(call.body.should_interrupt).toBe(true);
  });
});

describe("ProjectSettingsPage global concurrency cap note", () => {
  function mockMultiAgentSettings(maxConcurrentAgents: number) {
    vi.mocked(getProjectSettings).mockResolvedValue({
      data: makeSettings({
        pipeline_mode: "multi_agent",
        max_concurrent_agents: maxConcurrentAgents,
      }),
    } as never);
  }

  function cappedNote(wrapper: VueWrapper) {
    return wrapper.find(".capped-globally-note");
  }

  it("shows the note with the cap interpolated when the project's value strictly exceeds the global cap", async () => {
    mockMultiAgentSettings(5);
    const { wrapper } = mountPage("project-a", {
      user_settings: { global_max_concurrent_agents: 2 },
    });
    await flushPromises();

    const note = cappedNote(wrapper);
    expect(note.exists()).toBe(true);
    expect(note.text()).toContain("settings.capped_globally_note");
    expect(note.text()).toContain('"cap":2');
  });

  it("does not show the note when the project's value exactly equals the global cap", async () => {
    mockMultiAgentSettings(2);
    const { wrapper } = mountPage("project-a", {
      user_settings: { global_max_concurrent_agents: 2 },
    });
    await flushPromises();

    expect(cappedNote(wrapper).exists()).toBe(false);
  });

  it("does not show the note when the project's value is below the global cap", async () => {
    mockMultiAgentSettings(1);
    const { wrapper } = mountPage("project-a", {
      user_settings: { global_max_concurrent_agents: 2 },
    });
    await flushPromises();

    expect(cappedNote(wrapper).exists()).toBe(false);
  });

  it("shows the note immediately on mount, before any field edit", async () => {
    mockMultiAgentSettings(10);
    const { wrapper } = mountPage("project-a", {
      user_settings: { global_max_concurrent_agents: 3 },
    });
    await flushPromises();

    expect(cappedNote(wrapper).exists()).toBe(true);
  });

  it("shows no note and triggers loadUserSettings when user_settings has not loaded yet", async () => {
    mockMultiAgentSettings(5);
    const { wrapper, store } = mountPage("project-a", { user_settings: null });
    await flushPromises();

    expect(cappedNote(wrapper).exists()).toBe(false);
    expect(store.loadUserSettings).toHaveBeenCalledTimes(1);
  });

  it("does not call loadUserSettings again when user_settings is already populated before mount", async () => {
    mockMultiAgentSettings(5);
    const { store } = mountPage("project-a", {
      user_settings: { global_max_concurrent_agents: 2 },
    });
    await flushPromises();

    expect(store.loadUserSettings).not.toHaveBeenCalled();
  });
});

describe("ProjectSettingsPage scope & authorization status badge", () => {
  beforeEach(() => {
    vi.mocked(getProjectSettings).mockResolvedValue({ data: makeSettings() } as never);
  });

  it("shows the acknowledged status when the project's current scope is acknowledged", async () => {
    const { wrapper } = mountPage("project-a", {}, (store) => {
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValue(true);
    });
    await flushPromises();

    const badge = wrapper.find(".scope-status-badge");
    expect(badge.text()).toBe("project.acknowledged");
    expect(badge.classes()).toContain("text-active");
  });

  it("shows the needs-re-acknowledgment status when the project's current scope is not acknowledged", async () => {
    const { wrapper } = mountPage("project-a", {}, (store) => {
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValue(false);
    });
    await flushPromises();

    const badge = wrapper.find(".scope-status-badge");
    expect(badge.text()).toBe("project.needs_reacknowledgment");
    expect(badge.classes()).toContain("text-inactive");
  });

  it("opens the scope dialog on click, which loads the project's current scope", async () => {
    const { wrapper, store } = mountPage("project-a", {}, (store) => {
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValue(true);
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.0/24",
        port_range_start: 1,
        port_range_end: 1024,
      });
    });
    await flushPromises();

    await wrapper.find(".open-scope-dialog-button").trigger("click");
    await flushPromises();

    expect(store.getProjectScope).toHaveBeenCalledWith("project-a");
  });
});
