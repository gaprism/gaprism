"""DNS resolver and strict Anti-SSRF egress screening gate."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable

# IPv4 forbidden ranges (private, loopback, link-local, cloud metadata, multicast, reserved)
FORBIDDEN_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),  # Current network (RFC 1122)
    ipaddress.IPv4Network("10.0.0.0/8"),  # Private RFC 1918
    ipaddress.IPv4Network("100.64.0.0/10"),  # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.IPv4Network("127.0.0.0/8"),  # Loopback (RFC 1122)
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.IPv4Network("172.16.0.0/12"),  # Private RFC 1918
    ipaddress.IPv4Network("192.0.0.0/24"),  # IETF Protocol Assignments (RFC 6890)
    ipaddress.IPv4Network("192.0.2.0/24"),  # Documentation TEST-NET-1 (RFC 5737)
    ipaddress.IPv4Network("192.88.99.0/24"),  # 6to4 Relay Anycast (RFC 7526)
    ipaddress.IPv4Network("192.168.0.0/16"),  # Private RFC 1918
    ipaddress.IPv4Network("198.18.0.0/15"),  # Benchmarking (RFC 2544)
    ipaddress.IPv4Network("198.51.100.0/24"),  # Documentation TEST-NET-2 (RFC 5737)
    ipaddress.IPv4Network("203.0.113.0/24"),  # Documentation TEST-NET-3 (RFC 5737)
    ipaddress.IPv4Network("224.0.0.0/4"),  # Multicast (RFC 5771)
    ipaddress.IPv4Network("240.0.0.0/4"),  # Reserved (RFC 1112)
    ipaddress.IPv4Network("255.255.255.255/32"),  # Limited Broadcast (RFC 919)
)

# IPv6 forbidden ranges (loopback, link-local, unique-local, multicast, documentation)
FORBIDDEN_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::/128"),  # Unspecified (RFC 4291)
    ipaddress.IPv6Network("::1/128"),  # Loopback (RFC 4291)
    ipaddress.IPv6Network("::ffff:0:0/96"),  # IPv4-mapped (RFC 4291)
    ipaddress.IPv6Network("64:ff9b::/96"),  # IPv4/IPv6 translation (RFC 6052)
    ipaddress.IPv6Network("100::/64"),  # Discard prefix (RFC 6666)
    ipaddress.IPv6Network("2001:db8::/32"),  # Documentation (RFC 3849)
    ipaddress.IPv6Network("fc00::/7"),  # Unique Local Address ULA (RFC 4193)
    ipaddress.IPv6Network("fe80::/10"),  # Link-Local Unicast (RFC 4291)
    ipaddress.IPv6Network("ff00::/8"),  # Multicast (RFC 4291)
)

IPAddressType = ipaddress.IPv4Address | ipaddress.IPv6Address


class SSRFBlockedError(Exception):
    """Raised when destination resolution resolves to a private or forbidden IP range."""


class DNSResolutionError(Exception):
    """Raised when DNS resolution fails or returns no records."""


def is_ip_public(ip: IPAddressType | str) -> bool:
    """Evaluate whether an IP address is a safe public target and not in forbidden subnets.

    Rejects:
    - IPv4 RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    - Loopback addresses (127.0.0.0/8, ::1).
    - Link-local and cloud metadata addresses (169.254.0.0/16, fe80::/10).
    - IPv4-mapped IPv6 representations of private addresses (e.g. ::ffff:127.0.0.1).
    - Multicast, broadcast, CGNAT, benchmark, and reserved ranges.
    """
    if isinstance(ip, str):
        try:
            ip_obj: IPAddressType = ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return False
    else:
        ip_obj = ip

    # 1. Handle IPv4
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False
        for net in FORBIDDEN_IPV4_NETWORKS:
            if ip_obj in net:
                return False
        return True

    # 2. Handle IPv6
    if isinstance(ip_obj, ipaddress.IPv6Address):
        # Extract IPv4 if IPv4-mapped
        if ip_obj.ipv4_mapped is not None:
            return is_ip_public(ip_obj.ipv4_mapped)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False

        for net_v6 in FORBIDDEN_IPV6_NETWORKS:
            if ip_obj in net_v6:
                return False

        return True

    return False


def ip_block_reason(ip: IPAddressType | str) -> str | None:
    """Name the category of an address that must not be connected to; ``None`` if it is public.

    Informational only (it labels what ``is_ip_public`` already refuses, e.g. for a DNS record
    set that points at a private address); the gate itself stays ``is_ip_public``.
    """
    if is_ip_public(ip):
        return None
    try:
        parsed: IPAddressType = ipaddress.ip_address(ip.strip("[]") if isinstance(ip, str) else ip)
    except ValueError:
        return "invalid"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_reserved:  # before "private": Python counts 240.0.0.0/4 as both
        return "reserved"
    if parsed.is_private:
        return "private"
    return "special_use"


def resolve_and_screen(
    hostname: str,
    resolver_fn: Callable[[str], list[str]] | None = None,
) -> list[IPAddressType]:
    """Resolve a target hostname and strictly screen every returned IP address.

    Enforces invariants:
    - Blocks private IPv4/IPv6, loopback, link-local, and cloud metadata (169.254.169.254).
    - Rejects mixed answer sets containing any forbidden IP (Anti-SSRF gate).
    - Returns deduplicated list of screened, validated public IPs for connection pinning.
    """
    cleaned = hostname.strip().rstrip(".").lower()
    if not cleaned:
        raise DNSResolutionError("Hostname cannot be empty.")

    # Rejection of explicit localhost keywords
    if cleaned in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        raise SSRFBlockedError(
            f"Destination '{hostname}' resolves to loopback/local address and is blocked."
        )

    # Check if input is a raw IP literal
    try:
        raw_ip = ipaddress.ip_address(cleaned.strip("[]"))
        if not is_ip_public(raw_ip):
            raise SSRFBlockedError(
                f"Destination IP literal '{raw_ip}' is in a private/forbidden address range."
            )
        return [raw_ip]
    except ValueError:
        pass  # It is a domain name, proceed to resolution

    raw_ip_strings: list[str] = []

    if resolver_fn is not None:
        raw_ip_strings = resolver_fn(cleaned)
    else:
        try:
            # Query system DNS for TCP streaming endpoints
            addr_info = socket.getaddrinfo(
                cleaned,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            for item in addr_info:
                sockaddr = item[4]
                ip_str = str(sockaddr[0])
                if ip_str not in raw_ip_strings:
                    raw_ip_strings.append(ip_str)
        except socket.gaierror as e:
            raise DNSResolutionError(f"DNS lookup failed for '{cleaned}': {e}") from e
        except Exception as e:
            raise DNSResolutionError(f"DNS resolution error for '{cleaned}': {e}") from e

    if not raw_ip_strings:
        raise DNSResolutionError(f"DNS lookup returned no A or AAAA records for '{cleaned}'.")

    validated_ips: list[IPAddressType] = []

    for ip_str in raw_ip_strings:
        try:
            parsed_ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise DNSResolutionError(f"DNS returned invalid IP address '{ip_str}': {e}") from e

        # Anti-SSRF Rule: If ANY address in the answer set is private, REJECT THE ENTIRE ANSWER SET
        if not is_ip_public(parsed_ip):
            raise SSRFBlockedError(
                f"DNS resolution for '{cleaned}' returned forbidden destination IP: {parsed_ip}"
            )

        if parsed_ip not in validated_ips:
            validated_ips.append(parsed_ip)

    return validated_ips
