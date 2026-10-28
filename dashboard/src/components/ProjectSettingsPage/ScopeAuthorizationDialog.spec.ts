import { afterEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises, DOMWrapper } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import ScopeAuthorizationDialog from "./ScopeAuthorizationDialog.vue";
import DiscoveryResults from "./DiscoveryResults.vue";
import { useMomosStore } from "@/store/momos_store";

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

// Dialog.vue teleports its whole slot content to document.body (see
// TargetSettingsDialog.spec.ts's own note on this), so none of this
// dialog's content is reachable through the mounted wrapper's own element
// tree - every query below goes through document.body instead.
const body = new DOMWrapper(document.body);
const hostRangeInput = () => body.find(".host-range-input");
const portRangeStartInput = () => body.find(".port-range-start-input");
const portRangeEndInput = () => body.find(".port-range-end-input");
const statusBadge = () => body.find(".acknowledgment-status-badge");
const saveScopeButton = () => body.find(".save-scope-button");
const acknowledgedByInput = () => body.find(".acknowledged-by-input");
const acknowledgmentDescriptionInput = () => body.find(".acknowledgment-description-input");
const submitAcknowledgmentButton = () => body.find(".submit-acknowledgment-button");
const scopeRangeWarning = () => body.find(".scope-range-warning");

// Store actions (getProjectScope/getAcknowledgmentStatus/etc.) must be
// mocked BEFORE mount - the dialog is mounted with visible already true in
// every test here, and its load watcher fires immediately on mount.
function mountDialog(
  projectId = "project-a",
  mockSetup: (store: ReturnType<typeof useMomosStore>) => void = () => {},
) {
  const pinia = createTestingPinia({ stubActions: true });
  const store = useMomosStore(pinia);
  mockSetup(store);

  const wrapper = mount(ScopeAuthorizationDialog, {
    props: { projectId, visible: true },
    global: { plugins: [pinia] },
  });

  return { store, wrapper };
}

afterEach(() => {
  // Dialog.vue teleports to document.body, and jsdom's document persists
  // across tests within this file - without this, an unmounted previous
  // test's teleported dialog stays the first DOM match for the next test's
  // query.
  document.body.innerHTML = "";
});

describe("ScopeAuthorizationDialog on open", () => {
  it("loads and displays the current scope and acknowledgment status", async () => {
    const { store } = mountDialog("project-a", (store) => {
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.0/24",
        port_range_start: 22,
        port_range_end: 8080,
      });
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValue(true);
    });
    await flushPromises();

    expect(store.getProjectScope).toHaveBeenCalledWith("project-a");
    expect((hostRangeInput().element as HTMLInputElement).value).toBe("10.0.0.0/24");
    expect((portRangeStartInput().element as HTMLInputElement).value).toBe("22");
    expect((portRangeEndInput().element as HTMLInputElement).value).toBe("8080");

    expect(statusBadge().text()).toBe("project.acknowledged");
    expect(statusBadge().classes()).toContain("text-active");
  });

  it("renders DiscoveryResults for this project, so discovery is actually reachable from the dialog", async () => {
    const { wrapper } = mountDialog("project-a", (store) => {
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.0/24",
        port_range_start: 1,
        port_range_end: 1024,
      });
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValue(true);
    });
    await flushPromises();

    const discovery = wrapper.findComponent(DiscoveryResults);
    expect(discovery.exists()).toBe(true);
    expect(discovery.props("projectId")).toBe("project-a");
  });
});

describe("ScopeAuthorizationDialog widening the scope", () => {
  it("flips the displayed status to needs-re-acknowledgment after saving a wider range", async () => {
    const { store } = mountDialog("project-a", (store) => {
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.1",
        port_range_start: 22,
        port_range_end: 22,
      });
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValueOnce(true);
    });
    await flushPromises();

    expect(statusBadge().text()).toBe("project.acknowledged");

    vi.mocked(store.updateProjectScope).mockResolvedValue({
      scope: {
        project_id: "project-a",
        host_range: "10.0.0.0/16",
        port_range_start: 1,
        port_range_end: 65535,
      },
      large_range_warning: false,
    });
    vi.mocked(store.getAcknowledgmentStatus).mockResolvedValueOnce(false);

    await saveScopeButton().trigger("click");
    await flushPromises();

    expect(store.updateProjectScope).toHaveBeenCalledWith("project-a", "10.0.0.1", 22, 22);
    expect(statusBadge().text()).toBe("project.needs_reacknowledgment");
    expect(statusBadge().classes()).toContain("text-inactive");
  });
});

describe("ScopeAuthorizationDialog submitting an acknowledgment", () => {
  it("flips the displayed status back to acknowledged after a successful submit", async () => {
    const { store } = mountDialog("project-a", (store) => {
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.0/24",
        port_range_start: 1,
        port_range_end: 1024,
      });
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValueOnce(false);
    });
    await flushPromises();

    expect(statusBadge().text()).toBe("project.needs_reacknowledgment");

    vi.mocked(store.submitAcknowledgment).mockResolvedValue({
      id: "ack-1",
      project_id: "project-a",
      acknowledged_by: "alice",
      description: "pentest engagement",
      acknowledged_host_range: "10.0.0.0/24",
      acknowledged_port_range_start: 1,
      acknowledged_port_range_end: 1024,
      created_at: "2026-10-28T00:00:00Z",
    });
    vi.mocked(store.getAcknowledgmentStatus).mockResolvedValueOnce(true);

    await acknowledgedByInput().setValue("alice");
    await acknowledgmentDescriptionInput().setValue("pentest engagement");
    await submitAcknowledgmentButton().trigger("click");
    await flushPromises();

    expect(store.submitAcknowledgment).toHaveBeenCalledWith(
      "project-a",
      "alice",
      "pentest engagement",
    );
    expect(statusBadge().text()).toBe("project.acknowledged");
    expect(statusBadge().classes()).toContain("text-active");
  });
});

describe("ScopeAuthorizationDialog narrowing the scope", () => {
  it("never shows needs-re-acknowledgment when the backend reports the acknowledgment still holds", async () => {
    const { store } = mountDialog("project-a", (store) => {
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.0/16",
        port_range_start: 1,
        port_range_end: 65535,
      });
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValueOnce(true);
    });
    await flushPromises();

    vi.mocked(store.updateProjectScope).mockResolvedValue({
      scope: {
        project_id: "project-a",
        host_range: "10.0.0.0/24",
        port_range_start: 1,
        port_range_end: 1024,
      },
      large_range_warning: false,
    });
    // Narrowing never invalidates the ack - this component doesn't compute
    // that itself (containment lives server-side), it just reflects
    // whatever the backend's own next status check reports.
    vi.mocked(store.getAcknowledgmentStatus).mockResolvedValueOnce(true);

    await saveScopeButton().trigger("click");
    await flushPromises();

    expect(statusBadge().text()).toBe("project.acknowledged");
    expect(statusBadge().classes()).toContain("text-active");
  });
});

describe("ScopeAuthorizationDialog large-range warning", () => {
  it("passes the large-range warning through to ScopeRangeInput after saving", async () => {
    const { store } = mountDialog("project-a", (store) => {
      vi.mocked(store.getProjectScope).mockResolvedValue({
        project_id: "project-a",
        host_range: "10.0.0.0/8",
        port_range_start: 1,
        port_range_end: 65535,
      });
      vi.mocked(store.getAcknowledgmentStatus).mockResolvedValue(false);
    });
    await flushPromises();

    expect(scopeRangeWarning().exists()).toBe(false);

    vi.mocked(store.updateProjectScope).mockResolvedValue({
      scope: {
        project_id: "project-a",
        host_range: "10.0.0.0/8",
        port_range_start: 1,
        port_range_end: 65535,
      },
      large_range_warning: true,
    });

    await saveScopeButton().trigger("click");
    await flushPromises();

    const warningEl = scopeRangeWarning();
    expect(warningEl.exists()).toBe(true);
    expect(warningEl.text().length).toBeGreaterThan(0);
  });
});
