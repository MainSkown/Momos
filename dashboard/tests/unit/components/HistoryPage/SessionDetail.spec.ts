import { describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import SessionDetail from "@/components/HistoryPage/SessionDetail.vue";
import type { ResponseAttackVector, TestSessionDetailResponse } from "@/api";

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
  getTestSessionAttackVectors: vi.fn(),
}));

import { getTestSessionAttackVectors } from "@/api";

const SESSION_ID = "session-1";

function makeDetail(
  overrides: Partial<TestSessionDetailResponse> = {},
): TestSessionDetailResponse {
  return {
    id: SESSION_ID,
    project_id: "project-1",
    target_id: "target-1",
    pipeline_mode: "single_agent",
    max_concurrent_agents: 1,
    base_model_name: "model-a",
    orchestrator_model_name: "",
    scouting_model_name: "",
    pentesting_model_name: "",
    reporting_model_name: "",
    started_at: "2026-01-01T00:00:00Z",
    ended_at: "2026-01-01T01:00:00Z",
    active_seconds: 100,
    time_budget_seconds: null,
    outcome: "finished",
    vector_counts: {},
    vulnerability_count: 0,
    ...overrides,
  } as TestSessionDetailResponse;
}

// A real, named stub so AttackVectors' received props (specifically
// `vectors`) can be asserted directly, instead of mounting the full
// OverviewPage/AttackVectors.vue tree.
const AttackVectorsStub = {
  name: "AttackVectorsStub",
  props: ["vectors", "emptyText"],
  template: "<div class=\"av-stub\" />",
};

function mountDetail() {
  const pinia = createTestingPinia({
    stubActions: true,
    initialState: {
      momos: {
        session_detail: { [SESSION_ID]: makeDetail() },
        targets: [],
        openedProject: "project-1",
      },
    },
  });

  return mount(SessionDetail, {
    props: { sessionId: SESSION_ID },
    global: {
      plugins: [pinia],
      stubs: {
        AttackVectors: AttackVectorsStub,
        SessionLogs: true,
      },
    },
  });
}

describe("SessionDetail.loadVectors error handling (fixed)", () => {
  it("shows the error view on a real attack-vector API failure, instead of the same empty state as 'no attack vectors'", async () => {
    vi.mocked(getTestSessionAttackVectors).mockResolvedValue({
      data: undefined,
      error: { message: "backend exploded" },
    } as never);

    const wrapper = mountDetail();
    await flushPromises();

    // Fixed: loadVectors now throws on result.error, so loadSessionData's
    // existing catch block (which already handles loadSessionDetail/
    // loadTargets failing the same way) sets loadError and shows the
    // retry view instead of silently rendering an empty vector list.
    expect(wrapper.text()).toContain("history.load_failed");
    expect(wrapper.find(".retry-button").exists()).toBe(true);
    expect(wrapper.findComponent(AttackVectorsStub).exists()).toBe(false);
  });

  it("still renders normally for a genuinely empty vector list (proves the two are now distinguishable)", async () => {
    vi.mocked(getTestSessionAttackVectors).mockResolvedValue({
      data: [] as ResponseAttackVector[],
    } as never);

    const wrapper = mountDetail();
    await flushPromises();

    expect(wrapper.text()).not.toContain("history.load_failed");
    const av = wrapper.findComponent(AttackVectorsStub);
    expect(av.props("vectors")).toEqual([]);
  });
});
