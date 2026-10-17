import { describe, expect, it } from "vitest";
import { isAddressValid } from "@/types";

describe("isAddressValid", () => {
  it("accepts out-of-range IPv4 octets because they fall through to domainPattern (confirmed bug)", () => {
    expect(isAddressValid("256.0.0.1")).toBe(true);
    expect(isAddressValid("999.999.999.999")).toBe(true);
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
