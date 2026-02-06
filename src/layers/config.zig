// OpenClaw Shield — Shared Layer Configuration
//
// Configuration types shared across all defense layers.

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const RedactStrategy = pattern.RedactStrategy;

/// Top-level shield configuration, mirroring the OpenClaw plugin config schema.
pub const ShieldConfig = struct {
    mode: Mode = .enforce,
    layers: LayerFlags = .{},
    redaction: RedactionConfig = .{},
    entropy: EntropySettings = .{},
    rate_limits: RateLimitSettings = .{},

    pub const Mode = enum {
        enforce, // Block and redact
        audit, // Log only, no blocking
    };
};

pub const LayerFlags = struct {
    prompt_guard: bool = true,
    output_scanner: bool = true,
    tool_blocker: bool = true,
    input_audit: bool = true,
    security_gate: bool = true,
    rate_limiter: bool = true,
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
    try std.testing.expect(config.layers.prompt_guard);
    try std.testing.expect(config.layers.rate_limiter);
    try std.testing.expectEqual(RedactStrategy.mask, config.redaction.strategy);
}

test "toRedactOptions" {
    const config = ShieldConfig{ .redaction = .{ .strategy = .partial, .partial_chars = 6 } };
    const opts = toRedactOptions(config);
    try std.testing.expectEqual(RedactStrategy.partial, opts.strategy);
    try std.testing.expectEqual(@as(usize, 6), opts.partial_chars);
}
