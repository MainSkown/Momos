import { describe, expect, it } from "vitest";
import { formatDuration } from "@/components/HistoryPage/historyUtils";

describe("formatDuration", () => {
  it("shows seconds under a minute without calling the translator", () => {
    const t = (key: string) => `unexpected:${key}`;

    expect(formatDuration(45.9, t)).toBe("45s");
  });

  it("splits 3725 seconds into zero-padded hours and minutes", () => {
    const t = (key: string, params?: Record<string, unknown>) =>
      `${key}|${params?.hours}h|${params?.minutes}m`;

    expect(formatDuration(3725, t)).toBe("time.hours_minutes|1h|02m");
  });
});
