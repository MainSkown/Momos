import ipaddress
from typing import List, Union

# Every entry is normalized to a network (a bare address becomes its own
# /32 or /128) so callers get one uniform type to run containment checks
# against (ProjectScopeService, not built yet, will use subnet_of/
# supernet_of on these) instead of juggling Address and Network separately.
HostRangeEntry = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_host_range(value: str) -> List[HostRangeEntry]:
    """Parses a `ProjectScope.host_range` free-text value into a list of
    `ipaddress` networks.

    Accepts a single IPv4/IPv6 address, a CIDR block, or a comma-separated
    mix of either - the one field, one code path the feature spec calls
    for (no separate mode selector). Raises ValueError on anything that
    isn't a parseable address or network, the same way
    target_service.py's own ipaddress-based field validation does.
    """
    entries = [entry.strip() for entry in value.split(",")]

    networks: List[HostRangeEntry] = []
    for entry in entries:
        try:
            # strict=False lets a host address with set bits past its
            # prefix length (e.g. a bare "10.0.0.1") parse as a /32
            # network instead of raising, which is exactly the
            # single-host case this field has to support.
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ValueError(f"Invalid host or CIDR block in host range: {entry!r}")

    return networks


def is_network_in_any(candidate: HostRangeEntry, allowed_networks: List[HostRangeEntry]) -> bool:
    """True if `candidate` is fully contained in at least one network in
    `allowed_networks` - same IP version AND a `subnet_of` relationship.

    This is the one containment primitive the feature's two authorization
    checks both need: ProjectScopeService checks every CURRENT scope entry
    against every ACKNOWLEDGED entry (is the scope still covered by what
    was authorized), while TargetService checks a single target address
    against every SCOPE entry (is this host inside what's authorized).
    Same subnet_of/version-guard reasoning, different callers - kept here
    once rather than reimplemented at each call site.
    """
    return any(
        candidate.version == allowed.version and candidate.subnet_of(allowed)
        for allowed in allowed_networks
    )


def host_count(value: str) -> int:
    """Total number of addresses implied by `host_range` - used for the
    large-range warning (>254 hosts, i.e. wider than a /24) on scope save.

    Counts every address in each network, network/broadcast included
    (ipaddress.Network.num_addresses's own definition) - a single address
    is its own /32 or /128 and counts as exactly 1, which is what matters
    for the warning threshold; a /24's own network/broadcast addresses
    don't change which side of 254 it falls on.
    """
    return sum(network.num_addresses for network in parse_host_range(value))
