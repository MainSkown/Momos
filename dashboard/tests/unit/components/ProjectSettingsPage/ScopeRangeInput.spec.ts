import { describe, expect, it, vi } from "vitest";
import { mount } from "@vue/test-utils";
import ScopeRangeInput from "@/components/ProjectSettingsPage/ScopeRangeInput.vue";
import type { tScopeRange } from "@/types";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

function makeScope(overrides: Partial<tScopeRange> = {}): tScopeRange {
  return {
    host_range: "10.0.0.0/24",
    port_range_start: 1,
    port_range_end: 1024,
    ...overrides,
  };
}

function mountInput(modelValue: tScopeRange, warning: string | null = null) {
  return mount(ScopeRangeInput, {
    props: { modelValue, warning },
  });
}

describe("ScopeRangeInput initial values", () => {
  it("reflects the model's initial host range and port range in the rendered inputs", () => {
    const wrapper = mountInput(
      makeScope({ host_range: "192.168.1.5", port_range_start: 22, port_range_end: 8080 }),
    );

    expect((wrapper.find(".host-range-input").element as HTMLInputElement).value).toBe(
      "192.168.1.5",
    );
    expect((wrapper.find(".port-range-start-input").element as HTMLInputElement).value).toBe(
      "22",
    );
    expect((wrapper.find(".port-range-end-input").element as HTMLInputElement).value).toBe(
      "8080",
    );
  });
});

describe("ScopeRangeInput emitted payload", () => {
  it("emits the full {host_range, port_range_start, port_range_end} shape with the actually typed values", async () => {
    const wrapper = mountInput(
      makeScope({ host_range: "", port_range_start: 1, port_range_end: 1 }),
    );

    await wrapper.find(".host-range-input").setValue("192.168.1.0/24");
    await wrapper.find(".port-range-start-input").setValue(80);
    await wrapper.find(".port-range-end-input").setValue(443);

    const emitted = wrapper.emitted("update:modelValue");
    expect(emitted).toBeTruthy();
    const last = emitted![emitted!.length - 1]![0] as tScopeRange;

    expect(last).toEqual({
      host_range: "192.168.1.0/24",
      port_range_start: 80,
      port_range_end: 443,
    });
  });

  it("keeps the other fields intact when only the host range is edited", async () => {
    const wrapper = mountInput(makeScope({ port_range_start: 10, port_range_end: 20 }));

    await wrapper.find(".host-range-input").setValue("172.16.0.0/16");

    const emitted = wrapper.emitted("update:modelValue");
    const last = emitted![emitted!.length - 1]![0] as tScopeRange;

    expect(last).toEqual({
      host_range: "172.16.0.0/16",
      port_range_start: 10,
      port_range_end: 20,
    });
  });
});

describe("ScopeRangeInput warning prop", () => {
  it("renders the warning text when a non-null warning is passed", () => {
    const wrapper = mountInput(makeScope(), "This range resolves to more than 254 hosts");

    const warningEl = wrapper.find(".scope-range-warning");
    expect(warningEl.exists()).toBe(true);
    expect(warningEl.text()).toBe("This range resolves to more than 254 hosts");
  });

  it("renders no warning element when warning is null", () => {
    const wrapper = mountInput(makeScope(), null);

    expect(wrapper.find(".scope-range-warning").exists()).toBe(false);
  });

  it("renders no warning element when warning is not passed at all", () => {
    const wrapper = mount(ScopeRangeInput, { props: { modelValue: makeScope() } });

    expect(wrapper.find(".scope-range-warning").exists()).toBe(false);
  });
});

describe("ScopeRangeInput empty host-range hint", () => {
  it("flags the host-range input as invalid when it is empty", () => {
    const wrapper = mountInput(makeScope({ host_range: "" }));

    expect(wrapper.find(".host-range-input").classes()).toContain("is-invalid");
  });

  it("does not flag the host-range input when it has a value", () => {
    const wrapper = mountInput(makeScope({ host_range: "10.0.0.1" }));

    expect(wrapper.find(".host-range-input").classes()).not.toContain("is-invalid");
  });
});
