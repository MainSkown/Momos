import { describe, expect, it } from "vitest";
import { isAddressValid } from "@/types";

describe("isAddressValid", () => {
  it("rejects out-of-range IPv4 octets instead of falling through to domainPattern (fixed)", () => {
    expect(isAddressValid("256.0.0.1")).toBe(false);
    expect(isAddressValid("999.999.999.999")).toBe(false);
  });

  it("accepts genuinely valid addresses", () => {
    expect(isAddressValid(undefined)).toBe(true);
    expect(isAddressValid("")).toBe(true);
    expect(isAddressValid("192.168.0.1")).toBe(true);
    expect(isAddressValid("255.255.255.255")).toBe(true);
    expect(isAddressValid("::1")).toBe(true);
    expect(isAddressValid("example.com")).toBe(true);
  });

  it("rejects genuinely invalid addresses", () => {
    expect(isAddressValid("   ")).toBe(false);
    expect(isAddressValid("foo..bar")).toBe(false);
    expect(isAddressValid("http://x.com")).toBe(false);
    expect(isAddressValid("1:2:3:4:5:6:7:8:9")).toBe(false);
  });
});
