import { describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createTestingPinia } from "@pinia/testing";
import DiscoveryResults from "./DiscoveryResults.vue";
import { useMomosStore } from "@/store/momos_store";
import type { DiscoveredHost } from "@/api";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

const PROJECT_ID = "project-a";

function mountResults() {
  const pinia = createTestingPinia({ stubActions: true });
  const store = useMomosStore(pinia);

  const wrapper = mount(DiscoveryResults, {
    props: { projectId: PROJECT_ID },
    global: { plugins: [pinia] },
  });

  return { wrapper, store };
}

function makeHosts(overrides: Partial<DiscoveredHost>[] = []): DiscoveredHost[] {
  return overrides.map((o) => ({ host: "10.0.0.1", in_scope: true, ...o }));
}

async function discoverButton(wrapper: ReturnType<typeof mountResults>["wrapper"]) {
  return wrapper.find(".discover-hosts-button");
}

describe("DiscoveryResults discovery sweep", () => {
  it("calls store.discoverHosts(projectId) and renders in-scope hosts as selectable, out-of-scope as disabled", async () => {
    const { wrapper, store } = mountResults();
    const hosts = makeHosts([
      { host: "10.0.0.5", in_scope: true },
      { host: "192.168.1.1", in_scope: false },
    ]);
    vi.mocked(store.discoverHosts).mockResolvedValue(hosts);

    await (await discoverButton(wrapper)).trigger("click");
    await flushPromises();

    expect(store.discoverHosts).toHaveBeenCalledOnce();
    expect(store.discoverHosts).toHaveBeenCalledWith(PROJECT_ID);

    const rows = wrapper.findAll(".discovery-host-row");
    expect(rows).toHaveLength(2);

    const inScopeCheckbox = wrapper.find('input[type="checkbox"][id*="10.0.0.5"]');
    expect(inScopeCheckbox.attributes("disabled")).toBeUndefined();

    const outOfScopeCheckbox = wrapper.find('input[type="checkbox"][id*="192.168.1.1"]');
    expect(outOfScopeCheckbox.attributes("disabled")).toBeDefined();
    expect(wrapper.text()).toContain("discovery.outside_scope");
  });

  it("shows the explicit empty-state message for an empty discovery result, not blank markup", async () => {
    const { wrapper, store } = mountResults();
    vi.mocked(store.discoverHosts).mockResolvedValue([]);

    await (await discoverButton(wrapper)).trigger("click");
    await flushPromises();

    expect(wrapper.find(".no-hosts-found").exists()).toBe(true);
    expect(wrapper.find(".discovery-host-row").exists()).toBe(false);
  });

  it("surfaces a visible error message when discoverHosts rejects, instead of throwing or rendering nothing", async () => {
    const { wrapper, store } = mountResults();
    vi.mocked(store.discoverHosts).mockRejectedValue(new Error("boom"));

    await expect((await discoverButton(wrapper)).trigger("click")).resolves.toBeUndefined();
    await flushPromises();

    const errorEl = wrapper.find(".discovery-error");
    expect(errorEl.exists()).toBe(true);
    expect(errorEl.text().length).toBeGreaterThan(0);
    expect(wrapper.find(".discovery-host-row").exists()).toBe(false);
  });
});

describe("DiscoveryResults add selected", () => {
  async function discoverWith(hosts: DiscoveredHost[]) {
    const { wrapper, store } = mountResults();
    vi.mocked(store.discoverHosts).mockResolvedValue(hosts);
    vi.mocked(store.addTarget2Project).mockResolvedValue(undefined);

    await (await discoverButton(wrapper)).trigger("click");
    await flushPromises();

    return { wrapper, store };
  }

  it("calls addTarget2Project once per selected in-scope host (not once total, not zero)", async () => {
    const { wrapper, store } = await discoverWith(
      makeHosts([
        { host: "10.0.0.5", in_scope: true },
        { host: "10.0.0.6", in_scope: true },
        { host: "192.168.1.1", in_scope: false },
      ]),
    );

    await wrapper.find('input[type="checkbox"][id*="10.0.0.5"]').setValue(true);
    await wrapper.find('input[type="checkbox"][id*="10.0.0.6"]').setValue(true);
    await flushPromises();

    await wrapper.find(".add-selected-button").trigger("click");
    await flushPromises();

    expect(store.addTarget2Project).toHaveBeenCalledTimes(2);
    expect(store.addTarget2Project).toHaveBeenCalledWith(
      "10.0.0.5",
      PROJECT_ID,
      "10.0.0.5",
      undefined,
    );
    expect(store.addTarget2Project).toHaveBeenCalledWith(
      "10.0.0.6",
      PROJECT_ID,
      "10.0.0.6",
      undefined,
    );
  });

  it("passes an ipv6 host as the ipv6 argument, not ipv4", async () => {
    const { wrapper, store } = await discoverWith(
      makeHosts([{ host: "fe80::1", in_scope: true }]),
    );

    await wrapper.find('input[type="checkbox"][id*="fe80::1"]').setValue(true);
    await flushPromises();

    await wrapper.find(".add-selected-button").trigger("click");
    await flushPromises();

    expect(store.addTarget2Project).toHaveBeenCalledWith(
      "fe80::1",
      PROJECT_ID,
      undefined,
      "fe80::1",
    );
  });

  it("never calls addTarget2Project for an out-of-scope host, even when its checkbox is force-checked", async () => {
    const { wrapper, store } = await discoverWith(
      makeHosts([
        { host: "10.0.0.5", in_scope: true },
        { host: "192.168.1.1", in_scope: false },
      ]),
    );

    const outOfScopeCheckbox = wrapper.find('input[type="checkbox"][id*="192.168.1.1"]');
    // Force the DOM element checked regardless of the disabled attribute,
    // the same way setValue does, to prove the component's own toggle
    // handler refuses the host - not just that the browser would block a
    // real click on a disabled input.
    await outOfScopeCheckbox.setValue(true);
    await flushPromises();

    await wrapper.find(".add-selected-button").trigger("click");
    await flushPromises();

    expect(store.addTarget2Project).not.toHaveBeenCalled();
    expect(store.addTarget2Project).not.toHaveBeenCalledWith("192.168.1.1", PROJECT_ID);
  });
});
