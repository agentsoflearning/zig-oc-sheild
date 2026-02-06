// OpenClaw Shield — L7: Stable Reason Codes
//
// Single source of truth for numeric reason codes used in audit logging.
// These codes NEVER change meaning across versions — operators can build
// alerting and dashboards on them.

const std = @import("std");

/// Stable reason codes for L7 enforcement decisions.
/// Codes are grouped by category:
///   1000–1099: Network enforcement
///   1100–1199: Process enforcement
///   1200–1299: Rate limiting
///   1300–1399: Taint / quarantine
///   1400–1499: Filesystem (v1.1+)
///   0:         No specific reason (allowed)
pub const ReasonCode = enum(u32) {
    none = 0,

    // ── Network (1000–1099) ─────────────────────────────────────────────
    net_rfc1918_blocked = 1001,
    net_localhost_blocked = 1002,
    net_link_local_blocked = 1003,
    net_metadata_blocked = 1004,
    net_domain_not_allowed = 1005,
    net_port_not_allowed = 1006,
    net_egress_rate_limit = 1007,

    // ── Process (1100–1199) ──────────────────────────────────────────────
    proc_spawn_denied = 1101,
    proc_shell_denied = 1102,
    proc_binary_not_allowed = 1103,

    // ── Rate limiting (1200–1299) ────────────────────────────────────────
    rate_limit_exceeded = 1201,

    // ── Taint / quarantine (1300–1399) ───────────────────────────────────
    taint_escalated = 1301,
    quarantined = 1302,

    // ── Filesystem (1400–1499, v1.1+) ────────────────────────────────────
    fs_write_outside_root = 1401,
    fs_dotfile_denied = 1402,

    /// Return the human-readable label for this reason code.
    pub fn label(self: ReasonCode) []const u8 {
        return switch (self) {
            .none => "ALLOWED",
            .net_rfc1918_blocked => "NET_RFC1918_BLOCKED",
            .net_localhost_blocked => "NET_LOCALHOST_BLOCKED",
            .net_link_local_blocked => "NET_LINK_LOCAL_BLOCKED",
            .net_metadata_blocked => "NET_METADATA_BLOCKED",
            .net_domain_not_allowed => "NET_DOMAIN_NOT_ALLOWED",
            .net_port_not_allowed => "NET_PORT_NOT_ALLOWED",
            .net_egress_rate_limit => "NET_EGRESS_RATE_LIMIT",
            .proc_spawn_denied => "PROC_SPAWN_DENIED",
            .proc_shell_denied => "PROC_SHELL_DENIED",
            .proc_binary_not_allowed => "PROC_BINARY_NOT_ALLOWED",
            .rate_limit_exceeded => "RATE_LIMIT_EXCEEDED",
            .taint_escalated => "TAINT_ESCALATED",
            .quarantined => "QUARANTINED",
            .fs_write_outside_root => "FS_WRITE_OUTSIDE_ROOT",
            .fs_dotfile_denied => "FS_DOTFILE_DENIED",
        };
    }

    /// Return a user-friendly description for actionable error messages.
    pub fn description(self: ReasonCode) []const u8 {
        return switch (self) {
            .none => "Operation allowed",
            .net_rfc1918_blocked => "Connection to RFC1918 private network address blocked",
            .net_localhost_blocked => "Connection to localhost/loopback address blocked",
            .net_link_local_blocked => "Connection to link-local address blocked",
            .net_metadata_blocked => "Connection to cloud metadata endpoint blocked",
            .net_domain_not_allowed => "Connection to non-allowlisted domain blocked",
            .net_port_not_allowed => "Connection to non-allowlisted port blocked",
            .net_egress_rate_limit => "Outbound data rate limit exceeded",
            .proc_spawn_denied => "Subprocess spawning is disabled",
            .proc_shell_denied => "Shell execution is denied",
            .proc_binary_not_allowed => "Binary is not in the allowed list",
            .rate_limit_exceeded => "Operation rate limit exceeded",
            .taint_escalated => "Session taint level escalated",
            .quarantined => "Session is quarantined — all side-effects blocked",
            .fs_write_outside_root => "File write outside permitted root directories",
            .fs_dotfile_denied => "Access to dotfiles/hidden files denied",
        };
    }

    /// Return the numeric code as a u32.
    pub fn code(self: ReasonCode) u32 {
        return @intFromEnum(self);
    }
};

/// Risk level for a decision.
pub const Risk = enum {
    low,
    medium,
    high,
};

/// Taint states for session tracking.
pub const TaintState = enum {
    clean,
    tainted,
    quarantined,
};

/// The result of an L7 enforcement decision.
pub const Decision = struct {
    allow: bool,
    reason_code: ReasonCode,
    risk: Risk,
    taint_update: ?TaintState,

    pub fn allowed() Decision {
        return .{
            .allow = true,
            .reason_code = .none,
            .risk = .low,
            .taint_update = null,
        };
    }

    pub fn blocked(reason: ReasonCode, risk: Risk) Decision {
        return .{
            .allow = false,
            .reason_code = reason,
            .risk = risk,
            .taint_update = .tainted,
        };
    }

    pub fn quarantine() Decision {
        return .{
            .allow = false,
            .reason_code = .quarantined,
            .risk = .high,
            .taint_update = .quarantined,
        };
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "ReasonCode — labels are stable strings" {
    try testing.expectEqualStrings("NET_RFC1918_BLOCKED", ReasonCode.net_rfc1918_blocked.label());
    try testing.expectEqualStrings("PROC_SHELL_DENIED", ReasonCode.proc_shell_denied.label());
    try testing.expectEqualStrings("QUARANTINED", ReasonCode.quarantined.label());
    try testing.expectEqualStrings("ALLOWED", ReasonCode.none.label());
}

test "ReasonCode — numeric codes" {
    try testing.expectEqual(@as(u32, 1001), ReasonCode.net_rfc1918_blocked.code());
    try testing.expectEqual(@as(u32, 1101), ReasonCode.proc_spawn_denied.code());
    try testing.expectEqual(@as(u32, 1302), ReasonCode.quarantined.code());
    try testing.expectEqual(@as(u32, 0), ReasonCode.none.code());
}

test "ReasonCode — descriptions are non-empty" {
    const codes = [_]ReasonCode{
        .none,
        .net_rfc1918_blocked,
        .net_localhost_blocked,
        .net_link_local_blocked,
        .net_metadata_blocked,
        .net_domain_not_allowed,
        .net_port_not_allowed,
        .net_egress_rate_limit,
        .proc_spawn_denied,
        .proc_shell_denied,
        .proc_binary_not_allowed,
        .rate_limit_exceeded,
        .taint_escalated,
        .quarantined,
    };
    for (codes) |c| {
        try testing.expect(c.description().len > 0);
        try testing.expect(c.label().len > 0);
    }
}

test "Decision — allowed factory" {
    const d = Decision.allowed();
    try testing.expect(d.allow);
    try testing.expectEqual(ReasonCode.none, d.reason_code);
    try testing.expectEqual(Risk.low, d.risk);
    try testing.expect(d.taint_update == null);
}

test "Decision — blocked factory" {
    const d = Decision.blocked(.net_rfc1918_blocked, .high);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.net_rfc1918_blocked, d.reason_code);
    try testing.expectEqual(Risk.high, d.risk);
    try testing.expectEqual(TaintState.tainted, d.taint_update.?);
}

test "Decision — quarantine factory" {
    const d = Decision.quarantine();
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.quarantined, d.reason_code);
    try testing.expectEqual(TaintState.quarantined, d.taint_update.?);
}
