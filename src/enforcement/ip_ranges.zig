// OpenClaw Shield — L7: IP Range Classification
//
// Classifies IP addresses into security-relevant categories:
// RFC1918 (private), localhost, link-local, cloud metadata endpoints.
// Used by net.zig to enforce network boundary policies.

const std = @import("std");

/// Classification result for an IP address.
pub const IpClass = enum {
    public,
    rfc1918, // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    localhost, // 127.0.0.0/8, ::1
    link_local, // 169.254.0.0/16, fe80::/10
    metadata, // 169.254.169.254, fd00:ec2::254
};

/// Parsed IPv4 address as 4 octets.
pub const Ipv4 = struct {
    octets: [4]u8,

    pub fn toU32(self: Ipv4) u32 {
        return (@as(u32, self.octets[0]) << 24) |
            (@as(u32, self.octets[1]) << 16) |
            (@as(u32, self.octets[2]) << 8) |
            @as(u32, self.octets[3]);
    }
};

/// Attempt to parse a string as an IPv4 address.
/// Returns null if the string is not a valid IPv4 literal.
pub fn parseIpv4(host: []const u8) ?Ipv4 {
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var current: u16 = 0;
    var digit_count: u8 = 0;

    for (host) |c| {
        if (c == '.') {
            if (digit_count == 0 or current > 255) return null;
            if (octet_idx >= 3) return null;
            octets[octet_idx] = @intCast(current);
            octet_idx += 1;
            current = 0;
            digit_count = 0;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            digit_count += 1;
            if (digit_count > 3) return null;
        } else {
            return null; // Invalid character
        }
    }

    // Final octet
    if (digit_count == 0 or current > 255) return null;
    if (octet_idx != 3) return null;
    octets[octet_idx] = @intCast(current);

    return Ipv4{ .octets = octets };
}

/// Best-effort IP parsing. Returns the classification or null for non-IP hosts.
pub fn parseIp(host: []const u8) ?IpClass {
    // Try IPv4
    if (parseIpv4(host)) |ipv4| {
        return classifyIpv4(ipv4);
    }

    // Try IPv6 (simplified: handle common forms)
    if (isIpv6Localhost(host)) return .localhost;
    if (isIpv6LinkLocal(host)) return .link_local;
    if (isIpv6Metadata(host)) return .metadata;

    // Check for bracketed IPv6 (e.g., [::1])
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        const inner = host[1 .. host.len - 1];
        if (isIpv6Localhost(inner)) return .localhost;
        if (isIpv6LinkLocal(inner)) return .link_local;
        if (isIpv6Metadata(inner)) return .metadata;
    }

    return null; // Not an IP literal — domain-based enforcement needed
}

/// Classify an IPv4 address.
pub fn classifyIpv4(ip: Ipv4) IpClass {
    // Metadata: 169.254.169.254 (AWS/GCP IMDS)
    if (ip.octets[0] == 169 and ip.octets[1] == 254 and
        ip.octets[2] == 169 and ip.octets[3] == 254)
    {
        return .metadata;
    }

    // Localhost: 127.0.0.0/8
    if (ip.octets[0] == 127) {
        return .localhost;
    }

    // Link-local: 169.254.0.0/16
    if (ip.octets[0] == 169 and ip.octets[1] == 254) {
        return .link_local;
    }

    // RFC1918: 10.0.0.0/8
    if (ip.octets[0] == 10) {
        return .rfc1918;
    }

    // RFC1918: 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
    if (ip.octets[0] == 172 and ip.octets[1] >= 16 and ip.octets[1] <= 31) {
        return .rfc1918;
    }

    // RFC1918: 192.168.0.0/16
    if (ip.octets[0] == 192 and ip.octets[1] == 168) {
        return .rfc1918;
    }

    return .public;
}

// ── Convenience predicates ────────────────────────────────────────────

pub fn isRFC1918(host: []const u8) bool {
    if (parseIpv4(host)) |ipv4| {
        return classifyIpv4(ipv4) == .rfc1918;
    }
    return false;
}

pub fn isLocalhost(host: []const u8) bool {
    if (parseIpv4(host)) |ipv4| {
        return classifyIpv4(ipv4) == .localhost;
    }
    if (isIpv6Localhost(host)) return true;
    // Bracketed form
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return isIpv6Localhost(host[1 .. host.len - 1]);
    }
    // Also check the hostname "localhost"
    return eqlLower(host, "localhost");
}

pub fn isLinkLocal(host: []const u8) bool {
    if (parseIpv4(host)) |ipv4| {
        return classifyIpv4(ipv4) == .link_local;
    }
    if (isIpv6LinkLocal(host)) return true;
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return isIpv6LinkLocal(host[1 .. host.len - 1]);
    }
    return false;
}

pub fn isMetadata(host: []const u8) bool {
    if (parseIpv4(host)) |ipv4| {
        return classifyIpv4(ipv4) == .metadata;
    }
    if (isIpv6Metadata(host)) return true;
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return isIpv6Metadata(host[1 .. host.len - 1]);
    }
    return false;
}

// ── IPv6 helpers (simplified common forms) ────────────────────────────

fn isIpv6Localhost(s: []const u8) bool {
    return eqlLower(s, "::1") or eqlLower(s, "0:0:0:0:0:0:0:1");
}

fn isIpv6LinkLocal(s: []const u8) bool {
    // fe80::/10 — starts with "fe80:" (case-insensitive)
    if (s.len < 5) return false;
    if (!eqlLowerAt(s[0..4], "fe80")) return false;
    return s[4] == ':';
}

fn isIpv6Metadata(s: []const u8) bool {
    // AWS IMDSv2 IPv6: fd00:ec2::254
    return eqlLower(s, "fd00:ec2::254");
}

fn eqlLower(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != std.ascii.toLower(bc)) return false;
    }
    return true;
}

fn eqlLowerAt(a: []const u8, b: []const u8) bool {
    if (a.len < b.len) return false;
    for (a[0..b.len], b) |ac, bc| {
        if (std.ascii.toLower(ac) != std.ascii.toLower(bc)) return false;
    }
    return true;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseIpv4 — valid addresses" {
    const ip1 = parseIpv4("10.0.0.1").?;
    try testing.expectEqual(@as(u8, 10), ip1.octets[0]);
    try testing.expectEqual(@as(u8, 0), ip1.octets[1]);
    try testing.expectEqual(@as(u8, 0), ip1.octets[2]);
    try testing.expectEqual(@as(u8, 1), ip1.octets[3]);

    const ip2 = parseIpv4("255.255.255.255").?;
    try testing.expectEqual(@as(u8, 255), ip2.octets[0]);

    const ip3 = parseIpv4("0.0.0.0").?;
    try testing.expectEqual(@as(u8, 0), ip3.octets[0]);
}

test "parseIpv4 — invalid addresses" {
    try testing.expect(parseIpv4("") == null);
    try testing.expect(parseIpv4("256.0.0.1") == null);
    try testing.expect(parseIpv4("10.0.0") == null);
    try testing.expect(parseIpv4("10.0.0.1.5") == null);
    try testing.expect(parseIpv4("abc.def.ghi.jkl") == null);
    try testing.expect(parseIpv4("api.openai.com") == null);
    try testing.expect(parseIpv4("10.0.0.1:8080") == null);
}

test "isRFC1918 — 10.0.0.0/8" {
    try testing.expect(isRFC1918("10.0.0.0"));
    try testing.expect(isRFC1918("10.0.0.1"));
    try testing.expect(isRFC1918("10.255.255.255"));
    try testing.expect(!isRFC1918("11.0.0.1"));
}

test "isRFC1918 — 172.16.0.0/12" {
    try testing.expect(isRFC1918("172.16.0.0"));
    try testing.expect(isRFC1918("172.16.0.1"));
    try testing.expect(isRFC1918("172.31.255.255"));
    try testing.expect(!isRFC1918("172.15.255.255"));
    try testing.expect(!isRFC1918("172.32.0.0"));
}

test "isRFC1918 — 192.168.0.0/16" {
    try testing.expect(isRFC1918("192.168.0.0"));
    try testing.expect(isRFC1918("192.168.1.1"));
    try testing.expect(isRFC1918("192.168.255.255"));
    try testing.expect(!isRFC1918("192.169.0.0"));
}

test "isLocalhost" {
    try testing.expect(isLocalhost("127.0.0.1"));
    try testing.expect(isLocalhost("127.0.0.0"));
    try testing.expect(isLocalhost("127.255.255.255"));
    try testing.expect(isLocalhost("::1"));
    try testing.expect(isLocalhost("[::1]"));
    try testing.expect(isLocalhost("0:0:0:0:0:0:0:1"));
    try testing.expect(isLocalhost("localhost"));
    try testing.expect(!isLocalhost("128.0.0.1"));
    try testing.expect(!isLocalhost("10.0.0.1"));
}

test "isLinkLocal" {
    try testing.expect(isLinkLocal("169.254.0.1"));
    try testing.expect(isLinkLocal("169.254.255.255"));
    try testing.expect(!isLinkLocal("169.255.0.1"));
    try testing.expect(isLinkLocal("fe80::1"));
    try testing.expect(isLinkLocal("[fe80::1]"));
}

test "isMetadata" {
    try testing.expect(isMetadata("169.254.169.254"));
    try testing.expect(isMetadata("fd00:ec2::254"));
    try testing.expect(isMetadata("[fd00:ec2::254]"));
    try testing.expect(!isMetadata("169.254.169.253"));
    try testing.expect(!isMetadata("10.0.0.1"));
}

test "parseIp — classification" {
    try testing.expectEqual(IpClass.rfc1918, parseIp("10.0.0.1").?);
    try testing.expectEqual(IpClass.localhost, parseIp("127.0.0.1").?);
    try testing.expectEqual(IpClass.link_local, parseIp("169.254.0.1").?);
    try testing.expectEqual(IpClass.metadata, parseIp("169.254.169.254").?);
    try testing.expectEqual(IpClass.public, parseIp("8.8.8.8").?);
    try testing.expectEqual(IpClass.localhost, parseIp("::1").?);
    try testing.expect(parseIp("api.openai.com") == null);
}

test "isRFC1918 — non-IP returns false" {
    try testing.expect(!isRFC1918("api.openai.com"));
    try testing.expect(!isRFC1918(""));
}

test "metadata — note: 169.254.169.254 is metadata, not just link-local" {
    // Metadata check must take priority over link-local
    const cls = parseIp("169.254.169.254").?;
    try testing.expectEqual(IpClass.metadata, cls);
}
