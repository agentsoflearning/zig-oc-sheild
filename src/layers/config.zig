// OpenClaw Shield — Shared Layer Configuration
//
// Configuration types shared across all defense layers (L1–L7).

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const RedactStrategy = pattern.RedactStrategy;
const reason_codes = @import("../enforcement/reason_codes.zig");
pub const TaintState = reason_codes.TaintState;

/// Top-level shield configuration, mirroring the OpenClaw plugin config schema.
pub const ShieldConfig = struct {
    mode: Mode = .enforce,
    profile: Profile = .prod,
    layers: LayerFlags = .{},
    redaction: RedactionConfig = .{},
    entropy: EntropySettings = .{},
    rate_limits: RateLimitSettings = .{},
    network: NetworkSettings = .{},
    process: ProcessSettings = .{},
    taint: TaintSettings = .{},

    pub const Mode = enum {
        enforce, // Block and redact
        audit, // Log only, no blocking
    };
};

/// Deployment profiles — presets for different environments.
pub const Profile = enum {
    home_lab,
    corp_dev,
    prod,
    research,
};

pub const LayerFlags = struct {
    prompt_guard: bool = true,
    output_scanner: bool = true,
    tool_blocker: bool = true,
    input_audit: bool = true,
    security_gate: bool = true,
    rate_limiter: bool = true,
    preventive_enforcement: bool = true,
};

pub const RedactionConfig = struct {
    strategy: RedactStrategy = .mask,
    tag: []const u8 = "REDACTED",
    partial_chars: usize = 4,
};

pub const EntropySettings = struct {
    enabled: bool = true,
    base64_threshold: f64 = 4.5,
    hex_threshold: f64 = 3.5,
};

pub const RateLimitSettings = struct {
    exec_per_minute: u32 = 10,
    sensitive_read_per_minute: u32 = 5,
    window_seconds: u32 = 60,
};

// ── L7: Network Settings ──────────────────────────────────────────────

pub const NetworkSettings = struct {
    allowed_hosts: []const []const u8 = &.{},
    allowed_ports: []const u16 = &default_ports,
    block_rfc1918: bool = true,
    block_localhost: bool = true,
    block_link_local: bool = true,
    block_metadata: bool = true,
    max_egress_bytes_per_min: u64 = 10_485_760, // 10 MB

    const default_ports = [_]u16{ 80, 443 };
};

// ── L7: Process Settings ──────────────────────────────────────────────

pub const ProcessSettings = struct {
    allow_spawn: bool = false,
    allowed_binaries: []const []const u8 = &.{},
    deny_shells: bool = true,
    max_exec_per_min: u32 = 10,
};

// ── L7: Taint Settings ───────────────────────────────────────────────

pub const TaintSettings = struct {
    auto_escalate: bool = true,
    quarantine_threshold: u32 = 5,
    cool_down_seconds: u64 = 300,
};

/// Convert ShieldConfig.redaction to the RedactOptions used by the scanner.
pub fn toRedactOptions(config: ShieldConfig) pattern.RedactOptions {
    return .{
        .strategy = config.redaction.strategy,
        .tag = config.redaction.tag,
        .partial_chars = config.redaction.partial_chars,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "default config" {
    const config = ShieldConfig{};
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, config.mode);
    try std.testing.expectEqual(Profile.prod, config.profile);
    try std.testing.expect(config.layers.prompt_guard);
    try std.testing.expect(config.layers.rate_limiter);
    try std.testing.expect(config.layers.preventive_enforcement);
    try std.testing.expectEqual(RedactStrategy.mask, config.redaction.strategy);
}

test "default network settings" {
    const config = ShieldConfig{};
    try std.testing.expect(config.network.block_rfc1918);
    try std.testing.expect(config.network.block_localhost);
    try std.testing.expect(config.network.block_metadata);
    try std.testing.expectEqual(@as(u64, 10_485_760), config.network.max_egress_bytes_per_min);
}

test "default process settings" {
    const config = ShieldConfig{};
    try std.testing.expect(!config.process.allow_spawn);
    try std.testing.expect(config.process.deny_shells);
    try std.testing.expectEqual(@as(u32, 10), config.process.max_exec_per_min);
}

test "default taint settings" {
    const config = ShieldConfig{};
    try std.testing.expect(config.taint.auto_escalate);
    try std.testing.expectEqual(@as(u32, 5), config.taint.quarantine_threshold);
    try std.testing.expectEqual(@as(u64, 300), config.taint.cool_down_seconds);
}

test "toRedactOptions" {
    const config = ShieldConfig{ .redaction = .{ .strategy = .partial, .partial_chars = 6 } };
    const opts = toRedactOptions(config);
    try std.testing.expectEqual(RedactStrategy.partial, opts.strategy);
    try std.testing.expectEqual(@as(usize, 6), opts.partial_chars);
}
