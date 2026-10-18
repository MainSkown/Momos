import { beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import Vulnerabilities from "./Vulnerabilities.vue";
import { useMomosStore } from "@/store/momos_store";
import type { ResponseTarget, ResponseVulnerability } from "@/api";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

vi.mock("vue3-toastify", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
    POSITION: { TOP_CENTER: "top-center" },
  },
}));

vi.mock("@/api", () => ({
  getAllVulnerabilitiesInProject: vi.fn(),
  deleteVulnerability: vi.fn(),
  updateVulnerability: vi.fn(),
}));

import { getAllVulnerabilitiesInProject } from "@/api";

function makeVuln(overrides: Partial<ResponseVulnerability> = {}): ResponseVulnerability {
  return {
    id: "vuln-" + Math.random().toString(36).slice(2),
    name: "Generic vuln",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L",
    cvss4_score: 5,
    proof_of_concept: "poc",
    found_in: "target-a",
    related_to_project: "project-a",
    created_at: "2026-01-01T00:00:00Z",
    found_by_model: "gpt-4",
    severity: "medium",
    ...overrides,
  } as ResponseVulnerability;
}

function makeTarget(overrides: Partial<ResponseTarget> = {}): ResponseTarget {
  return {
    id: "target-a",
    project_id: "project-a",
    name: "Target",
    ipv4: null,
    ipv6: null,
    description: null,
    ports: null,
    task_duration: null,
    ...overrides,
  };
}

function mountComponent(
  opts: { openedProject?: string; targets?: ResponseTarget[] } = {},
) {
  const pinia = createTestingPinia({
    stubActions: true,
    initialState: {
      momos: {
        openedProject: opts.openedProject ?? "project-a",
        targets: opts.targets ?? [],
      },
    },
  });
  const store = useMomosStore(pinia);

  const wrapper = mount(Vulnerabilities, {
    global: { plugins: [pinia] },
  });

  return { wrapper, store };
}

function cardTitles(wrapper: ReturnType<typeof mountComponent>["wrapper"]) {
  return wrapper.findAll(".vuln-title .text-bold").map((n) => n.text());
}

describe("Vulnerabilities filters", () => {
  beforeEach(() => {
    vi.mocked(getAllVulnerabilitiesInProject).mockReset();
  });

  it("name filter is case-insensitive substring", async () => {
    vi.mocked(getAllVulnerabilitiesInProject).mockResolvedValue({
      data: [
        makeVuln({ id: "v1", name: "xABCx" }),
        makeVuln({ id: "v2", name: "something else" }),
      ],
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    await wrapper
      .find('input[placeholder="vulnerabilities.filter_name"]')
      .setValue("abc");

    expect(cardTitles(wrapper)).toEqual(["xABCx"]);
  });

  it("target filter matches by id, not name — two same-named targets don't collide", async () => {
    const targets = [
      makeTarget({ id: "target-1", name: "Shared Name" }),
      makeTarget({ id: "target-2", name: "Shared Name" }),
    ];
    vi.mocked(getAllVulnerabilitiesInProject).mockResolvedValue({
      data: [
        makeVuln({ id: "v1", name: "Vuln on target 1", found_in: "target-1" }),
        makeVuln({ id: "v2", name: "Vuln on target 2", found_in: "target-2" }),
      ],
    } as never);

    const { wrapper } = mountComponent({ targets });
    await flushPromises();

    await wrapper.findAll("select")[0]!.setValue("target-1");

    expect(cardTitles(wrapper)).toEqual(["Vuln on target 1"]);
  });

  it("model filter is an exact match, not a substring ('gpt-4' must not match 'gpt-4o')", async () => {
    vi.mocked(getAllVulnerabilitiesInProject).mockResolvedValue({
      data: [
        makeVuln({ id: "v1", name: "Exact model vuln", found_by_model: "gpt-4" }),
        makeVuln({ id: "v2", name: "Suffixed model vuln", found_by_model: "gpt-4o" }),
      ],
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    await wrapper.findAll("select")[1]!.setValue("gpt-4");

    expect(cardTitles(wrapper)).toEqual(["Exact model vuln"]);
  });

  it("fixed: targetFilter is reset on project switch, so switching projects no longer silently empties the list", async () => {
    const targets = [
      makeTarget({ id: "target-a", project_id: "project-a", name: "A" }),
      makeTarget({ id: "target-b", project_id: "project-b", name: "B" }),
    ];

    vi.mocked(getAllVulnerabilitiesInProject).mockImplementation(
      async ({ path }: { path: { project_id: string } }) => {
        if (path.project_id === "project-a") {
          return {
            data: [
              makeVuln({
                id: "va",
                name: "Vuln A",
                found_in: "target-a",
                related_to_project: "project-a",
              }),
            ],
          } as never;
        }
        return {
          data: [
            makeVuln({
              id: "vb",
              name: "Vuln B",
              found_in: "target-b",
              related_to_project: "project-b",
            }),
          ],
        } as never;
      },
    );

    const { wrapper, store } = mountComponent({
      openedProject: "project-a",
      targets,
    });
    await flushPromises();

    // Filter down to project A's own target - a perfectly normal action.
    await wrapper.findAll("select")[0]!.setValue("target-a");
    expect(cardTitles(wrapper)).toEqual(["Vuln A"]);

    // Switch to project B, which has its own real vulnerability.
    store.openedProject = "project-b";
    await flushPromises();

    // Fixed: the project-change watcher now resets targetFilter (along
    // with modelFilter/date range) back to "" before loading the new
    // project's vulnerabilities, so project B's own vulnerability
    // (found_in "target-b") is no longer excluded by a stale filter value
    // left over from project A.
    expect(cardTitles(wrapper)).toEqual(["Vuln B"]);
    expect(wrapper.find(".no-vulns").exists()).toBe(false);
  });

  it("fixed: a slow, stale response for the previously-open project no longer overwrites the current project's data", async () => {
    let resolveA!: (value: unknown) => void;
    let resolveB!: (value: unknown) => void;

    vi.mocked(getAllVulnerabilitiesInProject).mockImplementation(
      (({ path }: { path: { project_id: string } }) => {
        if (path.project_id === "project-a") {
          return new Promise((resolve) => {
            resolveA = resolve;
          });
        }
        return new Promise((resolve) => {
          resolveB = resolve;
        });
      }) as never,
    );

    const { wrapper, store } = mountComponent({ openedProject: "project-a" });
    await flushPromises();

    // Switch to project B before project A's (first-requested) response
    // has resolved at all.
    store.openedProject = "project-b";
    await flushPromises();

    // Resolve project B's (the now-current project's) request first.
    resolveB({ data: [makeVuln({ id: "vb", name: "Vuln B" })] });
    await flushPromises();
    expect(cardTitles(wrapper)).toEqual(["Vuln B"]);

    // Now resolve project A's request - requested first, but arriving
    // last, well after the user is looking at project B.
    resolveA({ data: [makeVuln({ id: "va", name: "Vuln A" })] });
    await flushPromises();

    // Fixed: loadVulnerabilities now bails out when store.openedProject no
    // longer matches the project this fetch was for, so project A's late,
    // stale response is discarded instead of overwriting project B's list.
    expect(cardTitles(wrapper)).toEqual(["Vuln B"]);
  });

  it("fixed: a backend {error} response shows a distinct error state, not the empty-vulnerabilities placeholder", async () => {
    vi.mocked(getAllVulnerabilitiesInProject).mockResolvedValue({
      data: undefined,
      error: { message: "boom" },
    } as never);

    const { wrapper } = mountComponent();
    await flushPromises();

    expect(wrapper.find(".no-vulns").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("vulnerabilities.no_vulnerabilities");
    expect(wrapper.text()).toContain("vulnerabilities.load_failed");
    expect(wrapper.find(".retry-button").exists()).toBe(true);
  });
});
