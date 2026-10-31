import { describe, it, expect, vi, afterEach } from "vitest";
import { mount } from "@vue/test-utils";
import LogEntryList from "@/components/reusable/LogEntryList.vue";
import type { AgentLogResponse } from "@/api";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

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
    expect(renderedToolName("request_tool_access")).toBe("agent_logs.tool_request_tool_access");
  });

  it("keeps rendering a milestone-2 binary tool as its raw snake_case name", () => {
    expect(renderedToolName("netexec_run")).toBe("netexec_run");
  });
});
