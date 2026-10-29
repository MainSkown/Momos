import { describe, it, expect, vi, afterEach } from "vitest";
import { mount } from "@vue/test-utils";
import LogEntryList from "./LogEntryList.vue";
import type { AgentLogResponse } from "@/api";

vi.mock("vue-i18n", async () => {
  const { en } = await import("@/i18n/locales/en");
  const lookup = (key: string) =>
    key.split(".").reduce<unknown>((node, part) => (node as Record<string, unknown>)?.[part], en) ??
    key;
  return { useI18n: () => ({ t: lookup }) };
});

function toolEntry(toolName: string): AgentLogResponse {
  return {
    id: `entry-${toolName}`,
    type: "tool",
    content: "tool output",
    tool_name: toolName,
    created_at: "2026-10-29T10:00:00Z",
    project_id: "project-1",
  } as AgentLogResponse;
}

function renderedToolName(toolName: string): string {
  const wrapper = mount(LogEntryList, {
    props: { entries: [toolEntry(toolName)] },
  });
  const text = wrapper.find(".tool-name").text();
  wrapper.unmount();
  return text;
}

describe("LogEntryList tool labels", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("renders the orchestration tool request_tool_access with its human label", () => {
    expect(renderedToolName("request_tool_access")).toBe("Tool Access Requested");
  });

  it("keeps rendering a milestone-2 binary tool as its raw snake_case name", () => {
    expect(renderedToolName("nikto_scan")).toBe("nikto_scan");
  });
});
