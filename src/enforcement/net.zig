// OpenClaw Shield — L7: Network Enforcement
//
// Top-level decision function for network connections.
// Evaluates host, port, and payload size against the policy capsule.
// Called from the TypeScript bridge before fetch/http.request/net.connect.
//
// Pure function — no I/O, no system calls, deterministic.

const std = @import("std");
const ip_ranges = @import("ip_ranges.zig");
const domain = @import("domain.zig");
const reason_codes = @import("reason_codes.zig");
const Decision = reason_codes.Decision;
const ReasonCode = reason_codes.ReasonCode;
const Risk = reason_codes.Risk;
const TaintState = reason_codes.TaintState;

/// Network policy settings (subset of PolicyCapsule).
pub const NetworkPolicy = struct {
    allowed_hosts: []const []const u8 = &.{},
    allowed_ports: []const u16 = &default_ports,
    block_rfc1918: bool = true,
    block_localhost: bool = true,
    block_link_local: bool = true,
    block_metadata: bool = true,
    max_egress_bytes_per_min: u64 = 10_485_760, // 10 MB

    const default_ports = [_]u16{ 80, 443 };
};

/// Evaluate a network connection attempt.
///
/// Checks in order (first deny wins):
/// 1. Quarantine state → block all
/// 2. Metadata IP → block (highest priority for cloud safety)
/// 3. Localhost → block if configured
/// 4. Link-local → block if configured
/// 5. RFC1918 → block if configured
/// 6. Port not in allowlist → block
/// 7. Host not in domain allowlist → block
/// 8. Egress bytes over limit → block (caller must check externally)
///
/// Returns Decision with reason_code, risk, and optional taint_update.
pub fn decideNetConnect(
    policy: NetworkPolicy,
    host: []const u8,
    port: u16,
    taint_state: TaintState,
) Decision {
    // Quarantined sessions: block everything
    if (taint_state == .quarantined) {
        return Decision.quarantine();
    }

    // Check IP classification
    if (ip_ranges.parseIp(host)) |ip_class| {
        switch (ip_class) {
            .metadata => {
                if (policy.block_metadata) {
                    return Decision.blocked(.net_metadata_blocked, .high);
                }
            },
            .localhost => {
                if (policy.block_localhost) {
                    return Decision.blocked(.net_localhost_blocked, .medium);
                }
            },
            .link_local => {
                if (policy.block_link_local) {
                    return Decision.blocked(.net_link_local_blocked, .medium);
                }
            },
            .rfc1918 => {
                if (policy.block_rfc1918) {
                    return Decision.blocked(.net_rfc1918_blocked, .medium);
                }
            },
            .public => {}, // Fall through to port/domain checks
        }
    } else {
        // Not an IP literal — also check "localhost" hostname
        if (ip_ranges.isLocalhost(host) and policy.block_localhost) {
            return Decision.blocked(.net_localhost_blocked, .medium);
        }
    }

    // Port check
    if (!isPortAllowed(port, policy.allowed_ports)) {
        return Decision.blocked(.net_port_not_allowed, .medium);
    }

    // Domain allowlist check (only for non-IP hosts or if IP passed earlier checks)
    if (!domain.isAllowed(host, policy.allowed_hosts)) {
        return Decision.blocked(.net_domain_not_allowed, .medium);
    }

    return Decision.allowed();
}

/// Check egress bytes against rate limit.
/// This is separate from decideNetConnect because the counter state
/// is managed externally (in CounterManager).
pub fn checkEgressLimit(current_bytes: u64, max_bytes_per_min: u64) Decision {
    if (current_bytes >= max_bytes_per_min) {
        return Decision.blocked(.net_egress_rate_limit, .high);
    }
    return Decision.allowed();
}

fn isPortAllowed(port: u16, allowed: []const u16) bool {
    for (allowed) |p| {
        if (p == port) return true;
    }
    return false;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "decideNetConnect — allowed host and port" {
    const hosts = [_][]const u8{"api.openai.com"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts };

    const d = decideNetConnect(policy, "api.openai.com", 443, .clean);
    try testing.expect(d.allow);
    try testing.expectEqual(ReasonCode.none, d.reason_code);
}

test "decideNetConnect — blocked RFC1918" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_rfc1918 = true };

    const d = decideNetConnect(policy, "10.0.0.5", 8080, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_rfc1918_blocked, d.reason_code);
    try testing.expectEqual(Risk.medium, d.risk);
}

test "decideNetConnect — blocked localhost" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_localhost = true };

    const d = decideNetConnect(policy, "127.0.0.1", 3000, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_localhost_blocked, d.reason_code);
}

test "decideNetConnect — blocked localhost hostname" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_localhost = true };

    const d = decideNetConnect(policy, "localhost", 3000, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_localhost_blocked, d.reason_code);
}

test "decideNetConnect — blocked link-local" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_link_local = true };

    const d = decideNetConnect(policy, "169.254.0.1", 80, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_link_local_blocked, d.reason_code);
}

test "decideNetConnect — blocked metadata" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_metadata = true };

    const d = decideNetConnect(policy, "169.254.169.254", 80, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_metadata_blocked, d.reason_code);
    try testing.expectEqual(Risk.high, d.risk);
}

test "decideNetConnect — blocked port" {
    const hosts = [_][]const u8{"api.openai.com"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts };

    const d = decideNetConnect(policy, "api.openai.com", 8080, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_port_not_allowed, d.reason_code);
}

test "decideNetConnect — blocked domain" {
    const hosts = [_][]const u8{"api.openai.com"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts };

    const d = decideNetConnect(policy, "evil.com", 443, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_domain_not_allowed, d.reason_code);
}

test "decideNetConnect — quarantined blocks everything" {
    const hosts = [_][]const u8{"*"};
    const ports = [_]u16{ 80, 443, 8080 };
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .allowed_ports = &ports };

    const d = decideNetConnect(policy, "api.openai.com", 443, .quarantined);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.quarantined, d.reason_code);
    try testing.expectEqual(Risk.high, d.risk);
}

test "decideNetConnect — metadata blocked even with wildcard hosts" {
    const hosts = [_][]const u8{"*"};
    const ports = [_]u16{ 80, 443 };
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .allowed_ports = &ports };

    const d = decideNetConnect(policy, "169.254.169.254", 80, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_metadata_blocked, d.reason_code);
}

test "decideNetConnect — RFC1918 allowed when block_rfc1918 is false" {
    const hosts = [_][]const u8{"*"};
    const ports = [_]u16{ 80, 443, 8080 };
    const policy = NetworkPolicy{
        .allowed_hosts = &hosts,
        .allowed_ports = &ports,
        .block_rfc1918 = false,
    };

    const d = decideNetConnect(policy, "10.0.0.5", 8080, .clean);
    try testing.expect(d.allow);
}

test "decideNetConnect — IPv6 localhost blocked" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_localhost = true };

    const d = decideNetConnect(policy, "::1", 443, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_localhost_blocked, d.reason_code);
}

test "decideNetConnect — IPv6 metadata blocked" {
    const hosts = [_][]const u8{"*"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts, .block_metadata = true };

    const d = decideNetConnect(policy, "fd00:ec2::254", 80, .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_metadata_blocked, d.reason_code);
}

test "decideNetConnect — wildcard host with standard ports" {
    const hosts = [_][]const u8{"*.anthropic.com"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts };

    const d1 = decideNetConnect(policy, "api.anthropic.com", 443, .clean);
    try testing.expect(d1.allow);

    const d2 = decideNetConnect(policy, "docs.anthropic.com", 80, .clean);
    try testing.expect(d2.allow);

    const d3 = decideNetConnect(policy, "evil.com", 443, .clean);
    try testing.expect(!d3.allow);
}

test "checkEgressLimit — under limit" {
    const d = checkEgressLimit(1000, 10_485_760);
    try testing.expect(d.allow);
}

test "checkEgressLimit — over limit" {
    const d = checkEgressLimit(10_485_760, 10_485_760);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_egress_rate_limit, d.reason_code);
}

test "decideNetConnect — tainted session still allowed if passes checks" {
    const hosts = [_][]const u8{"api.openai.com"};
    const policy = NetworkPolicy{ .allowed_hosts = &hosts };

    const d = decideNetConnect(policy, "api.openai.com", 443, .tainted);
    try testing.expect(d.allow);
}
