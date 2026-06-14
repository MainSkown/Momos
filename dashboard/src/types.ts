export type tTool = {
  id: number,
  name: string,
  icon?: string
}

export type tProject = {
    id: string,
    name: string,    
    createdAt?: string,
}

export type tAddresses = {
  ipv4?: string,
  ipv6?: string,
  domain?: string,
}

export type tTarget = tAddresses & { 
  name: string,
  projectID: string,
}

export function getTarget(target: tTarget): string {
  return target.ipv4 || target.ipv6 || target.domain || '';
}

export function TargetFactory(addr: tAddresses, projectID: string): tTarget{
  return {
    name: '',
    ...addr,
    projectID: projectID,
  }
}


/* Those are not types, but still useful */

export const ipv4Pattern =
  /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

export const ipv6Pattern =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

export const domainPattern =
  /^(?!:\/\/)[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*\.[a-zA-Z]{2,11}$/;

export function isAddressValid(t: string | undefined): boolean {
  if (!t) return true;

  return ipv4Pattern.test(t) || ipv6Pattern.test(t) || domainPattern.test(t);
}