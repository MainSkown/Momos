import type { ProjectResponse, ResponseTarget, ResponseVulnerability } from "./api";

export type tTool = {
  key: string;
  name: string;
  icon?: string;
};

export type tProject = ProjectResponse

export type tAddresses = {
  ipv4?: string;
  ipv6?: string;
  domain?: string;
};

export type tTarget = ResponseTarget

// Shared by ScopeRangeInput.vue and both of its planned parents
// (ProjectDialog.vue's creation form, ScopeAuthorizationDialog.vue's edit
// form - see docs/plans/milestone-1-project-scope-and-authorization.md's
// D1) - a standalone shape rather than a generated API type since the
// backend's ProjectScope schema (B1) doesn't exist yet.
export type tScopeRange = {
  host_range: string;
  port_range_start: number;
  port_range_end: number;
};

export type tVulnerability = ResponseVulnerability

// Ordered informational -> critical, matching backend SEVERITY_SCORES in
// vulnerability_scheme.py - drives both the edit-dialog severity picker
// and the severity filter dropdown.
export const SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"] as const;
export type tSeverity = (typeof SEVERITY_LEVELS)[number];

/* Those are not types, but still useful */

export function getTarget(target: tTarget): string {
  return target.ipv4 || target.ipv6 || /*target.domain ||*/ "";
}

export const ipv4Pattern =
  /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

export const ipv6Pattern =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

export const domainPattern = 
  /^(?!:\/\/)[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*(\.[a-zA-Z]{2,11})?$/;

function looksIPv4Shaped(t: string): boolean {
  const segments = t.split(".");
  return segments.length === 4 && segments.every((s) => /^\d+$/.test(s));
}

export function isAddressValid(t: string | undefined): boolean {
  if (!t) return true;

  // IPv4-shaped values (four dot-separated all-digit segments) must pass
  // ipv4Pattern's own range check (0-255 per octet) - otherwise they'd fall
  // through to domainPattern, which treats numeric labels like any other
  // domain label and would wrongly accept out-of-range octets (e.g. "256.0.0.1").
  if (looksIPv4Shaped(t)) {
    return ipv4Pattern.test(t);
  }

  return ipv4Pattern.test(t) || ipv6Pattern.test(t) || domainPattern.test(t);
}
