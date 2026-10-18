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

function mountPage(openedProject = "project-a") {
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
    initialState: { momos: { openedProject, running_targets: {}, projects: [] } },
  });
  const store = useMomosStore(pinia);

  const wrapper = mount(ProjectSettingsPage, {
    global: {
      plugins: [pinia],
      // ProjectSettingsPage.vue's template calls the global $t injected by
      // the app's i18n plugin directly (not the local `t` from its own
      // useI18n() call) - mirrors TargetSettingsDialog.spec.ts's pattern.
      mocks: { $t: (key: string) => key },
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
