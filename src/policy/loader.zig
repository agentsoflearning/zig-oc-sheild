// OpenClaw Shield — Policy Loader
//
// Parses JSON policy documents into ShieldConfig.
// Uses std.json with a flat intermediate representation.

const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("../layers/config.zig");
const ShieldConfig = config.ShieldConfig;
const Profile = config.Profile;
const RedactStrategy = @import("../core/pattern.zig").RedactStrategy;
const validator = @import("validator.zig");

// ── Errors ──────────────────────────────────────────────────────────

pub const LoadError = error{
    InvalidJson,
    UnknownField,
    InvalidProfile,
    InvalidMode,
    InvalidRedactStrategy,
    ValidationFailed,
    OutOfMemory,
};

// ── JSON Intermediate Types ─────────────────────────────────────────
// Zig's std.json.parseFromSlice needs struct definitions that mirror
// the JSON shape. We use optional fields everywhere so missing keys
// just become null (keeping the default).

const JsonEntropyConfig = struct {
    enabled: ?bool = null,
    base64_threshold: ?f64 = null,
    hex_threshold: ?f64 = null,
};

const JsonRateLimits = struct {
    exec_per_minute: ?u32 = null,
    sensitive_read_per_minute: ?u32 = null,
    window_seconds: ?u32 = null,
};

const JsonRedaction = struct {
    strategy: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    partial_chars: ?usize = null,
};

const JsonNetwork = struct {
    allowed_hosts: ?[]const []const u8 = null,
    allowed_ports: ?[]const u16 = null,
    block_rfc1918: ?bool = null,
    block_localhost: ?bool = null,
    block_link_local: ?bool = null,
    block_metadata: ?bool = null,
    max_egress_bytes_per_min: ?u64 = null,
};

const JsonProcess = struct {
    allow_spawn: ?bool = null,
    allowed_binaries: ?[]const []const u8 = null,
    deny_shells: ?bool = null,
    max_exec_per_min: ?u32 = null,
};

const JsonTaint = struct {
    auto_escalate: ?bool = null,
    quarantine_threshold: ?u32 = null,
    cool_down_seconds: ?u64 = null,
};

const JsonLayers = struct {
    prompt_guard: ?bool = null,
    output_scanner: ?bool = null,
    tool_blocker: ?bool = null,
    input_audit: ?bool = null,
    security_gate: ?bool = null,
    rate_limiter: ?bool = null,
    preventive_enforcement: ?bool = null,
};

const JsonPolicy = struct {
    mode: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    layers: ?JsonLayers = null,
    redaction: ?JsonRedaction = null,
    entropy: ?JsonEntropyConfig = null,
    rate_limits: ?JsonRateLimits = null,
    network: ?JsonNetwork = null,
    process: ?JsonProcess = null,
    taint: ?JsonTaint = null,
};

// ── Public API ──────────────────────────────────────────────────────

/// Parse a JSON string into a ShieldConfig, applying values over defaults.
/// The returned config is validated; returns ValidationFailed if invalid.
pub fn loadFromJson(allocator: Allocator, json_str: []const u8) LoadError!ShieldConfig {
    const parsed = std.json.parseFromSlice(
        JsonPolicy,
        allocator,
        json_str,
        .{ .ignore_unknown_fields = true },
    ) catch return LoadError.InvalidJson;
    defer parsed.deinit();

    return applyJsonPolicy(parsed.value);
}

/// Parse JSON and return the config WITHOUT validation (for testing).
pub fn loadFromJsonNoValidate(allocator: Allocator, json_str: []const u8) LoadError!ShieldConfig {
    const parsed = std.json.parseFromSlice(
        JsonPolicy,
        allocator,
        json_str,
        .{ .ignore_unknown_fields = true },
    ) catch return LoadError.InvalidJson;
    defer parsed.deinit();

    return applyJsonPolicyNoValidate(parsed.value);
}

// ── Apply JSON to Config ────────────────────────────────────────────

fn applyJsonPolicy(jp: JsonPolicy) LoadError!ShieldConfig {
    const cfg = applyJsonPolicyNoValidate(jp) catch |e| return e;

    // Validate the resulting config
    const result = validator.validate(cfg);
    if (!result.isValid()) return LoadError.ValidationFailed;

    return cfg;
}

fn applyJsonPolicyNoValidate(jp: JsonPolicy) LoadError!ShieldConfig {
    var cfg = ShieldConfig{};

    // Mode
    if (jp.mode) |mode_str| {
        cfg.mode = parseMode(mode_str) orelse return LoadError.InvalidMode;
    }

    // Profile
    if (jp.profile) |prof_str| {
        cfg.profile = parseProfile(prof_str) orelse return LoadError.InvalidProfile;
    }

    // Layers
    if (jp.layers) |layers| {
        if (layers.prompt_guard) |v| cfg.layers.prompt_guard = v;
        if (layers.output_scanner) |v| cfg.layers.output_scanner = v;
        if (layers.tool_blocker) |v| cfg.layers.tool_blocker = v;
        if (layers.input_audit) |v| cfg.layers.input_audit = v;
        if (layers.security_gate) |v| cfg.layers.security_gate = v;
        if (layers.rate_limiter) |v| cfg.layers.rate_limiter = v;
        if (layers.preventive_enforcement) |v| cfg.layers.preventive_enforcement = v;
    }

    // Redaction
    if (jp.redaction) |red| {
        if (red.strategy) |s| {
            cfg.redaction.strategy = parseRedactStrategy(s) orelse return LoadError.InvalidRedactStrategy;
        }
        if (red.tag) |t| cfg.redaction.tag = t;
        if (red.partial_chars) |pc| cfg.redaction.partial_chars = pc;
    }

    // Entropy
    if (jp.entropy) |ent| {
        if (ent.enabled) |v| cfg.entropy.enabled = v;
        if (ent.base64_threshold) |v| cfg.entropy.base64_threshold = v;
        if (ent.hex_threshold) |v| cfg.entropy.hex_threshold = v;
    }

    // Rate limits
    if (jp.rate_limits) |rl| {
        if (rl.exec_per_minute) |v| cfg.rate_limits.exec_per_minute = v;
        if (rl.sensitive_read_per_minute) |v| cfg.rate_limits.sensitive_read_per_minute = v;
        if (rl.window_seconds) |v| cfg.rate_limits.window_seconds = v;
    }

    // Network
    if (jp.network) |net| {
        if (net.allowed_hosts) |v| cfg.network.allowed_hosts = v;
        if (net.allowed_ports) |v| cfg.network.allowed_ports = v;
        if (net.block_rfc1918) |v| cfg.network.block_rfc1918 = v;
        if (net.block_localhost) |v| cfg.network.block_localhost = v;
        if (net.block_link_local) |v| cfg.network.block_link_local = v;
        if (net.block_metadata) |v| cfg.network.block_metadata = v;
        if (net.max_egress_bytes_per_min) |v| cfg.network.max_egress_bytes_per_min = v;
    }

    // Process
    if (jp.process) |proc| {
        if (proc.allow_spawn) |v| cfg.process.allow_spawn = v;
        if (proc.allowed_binaries) |v| cfg.process.allowed_binaries = v;
        if (proc.deny_shells) |v| cfg.process.deny_shells = v;
        if (proc.max_exec_per_min) |v| cfg.process.max_exec_per_min = v;
    }

    // Taint
    if (jp.taint) |taint| {
        if (taint.auto_escalate) |v| cfg.taint.auto_escalate = v;
        if (taint.quarantine_threshold) |v| cfg.taint.quarantine_threshold = v;
        if (taint.cool_down_seconds) |v| cfg.taint.cool_down_seconds = v;
    }

    return cfg;
}

// ── Parsers ─────────────────────────────────────────────────────────

fn parseMode(s: []const u8) ?ShieldConfig.Mode {
    if (std.mem.eql(u8, s, "enforce")) return .enforce;
    if (std.mem.eql(u8, s, "audit")) return .audit;
    return null;
}

fn parseProfile(s: []const u8) ?Profile {
    if (std.mem.eql(u8, s, "home-lab") or std.mem.eql(u8, s, "home_lab")) return .home_lab;
    if (std.mem.eql(u8, s, "corp-dev") or std.mem.eql(u8, s, "corp_dev")) return .corp_dev;
    if (std.mem.eql(u8, s, "prod")) return .prod;
    if (std.mem.eql(u8, s, "research")) return .research;
    return null;
}

fn parseRedactStrategy(s: []const u8) ?RedactStrategy {
    if (std.mem.eql(u8, s, "mask")) return .mask;
    if (std.mem.eql(u8, s, "partial")) return .partial;
    if (std.mem.eql(u8, s, "hash")) return .hash;
    if (std.mem.eql(u8, s, "drop")) return .drop;
    return null;
}

// ── Tests ───────────────────────────────────────────────────────────

test "load minimal JSON — empty object uses defaults" {
    const cfg = try loadFromJson(std.testing.allocator, "{}");
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, cfg.mode);
    try std.testing.expectEqual(Profile.prod, cfg.profile);
    try std.testing.expect(cfg.layers.prompt_guard);
}

test "load JSON with mode and profile" {
    const json_str =
        \\{"mode": "audit", "profile": "home-lab"}
    ;
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expectEqual(ShieldConfig.Mode.audit, cfg.mode);
    try std.testing.expectEqual(Profile.home_lab, cfg.profile);
}

test "load JSON with nested config" {
    const json_str =
        \\{
        \\  "entropy": {"enabled": false, "base64_threshold": 5.0},
        \\  "rate_limits": {"exec_per_minute": 20},
        \\  "taint": {"quarantine_threshold": 10, "cool_down_seconds": 600}
        \\}
    ;
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expect(!cfg.entropy.enabled);
    try std.testing.expectEqual(@as(f64, 5.0), cfg.entropy.base64_threshold);
    try std.testing.expectEqual(@as(u32, 20), cfg.rate_limits.exec_per_minute);
    try std.testing.expectEqual(@as(u32, 10), cfg.taint.quarantine_threshold);
    try std.testing.expectEqual(@as(u64, 600), cfg.taint.cool_down_seconds);
}

test "load JSON with layers" {
    const json_str =
        \\{"layers": {"prompt_guard": false, "rate_limiter": false}}
    ;
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expect(!cfg.layers.prompt_guard);
    try std.testing.expect(!cfg.layers.rate_limiter);
    try std.testing.expect(cfg.layers.output_scanner); // default still true
}

test "load JSON with redaction" {
    const json_str =
        \\{"redaction": {"strategy": "hash"}}
    ;
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expectEqual(RedactStrategy.hash, cfg.redaction.strategy);
}

test "load JSON with process settings" {
    const json_str =
        \\{"process": {"allow_spawn": true, "deny_shells": false, "max_exec_per_min": 50}}
    ;
    // Note: allow_spawn=true + deny_shells=false generates a warning but not error
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expect(cfg.process.allow_spawn);
    try std.testing.expect(!cfg.process.deny_shells);
    try std.testing.expectEqual(@as(u32, 50), cfg.process.max_exec_per_min);
}

test "load JSON — invalid mode returns error" {
    const result = loadFromJson(std.testing.allocator, "{\"mode\": \"invalid\"}");
    try std.testing.expectError(LoadError.InvalidMode, result);
}

test "load JSON — invalid profile returns error" {
    const result = loadFromJson(std.testing.allocator, "{\"profile\": \"staging\"}");
    try std.testing.expectError(LoadError.InvalidProfile, result);
}

test "load JSON — invalid redact strategy returns error" {
    const json_str =
        \\{"redaction": {"strategy": "encrypt"}}
    ;
    const result = loadFromJson(std.testing.allocator, json_str);
    try std.testing.expectError(LoadError.InvalidRedactStrategy, result);
}

test "load JSON — malformed JSON returns error" {
    const result = loadFromJson(std.testing.allocator, "{bad json");
    try std.testing.expectError(LoadError.InvalidJson, result);
}

test "load JSON — validation failure returns error" {
    const json_str =
        \\{"taint": {"quarantine_threshold": 0}}
    ;
    const result = loadFromJson(std.testing.allocator, json_str);
    try std.testing.expectError(LoadError.ValidationFailed, result);
}

test "load JSON — unknown fields are ignored" {
    const json_str =
        \\{"mode": "audit", "future_field": true, "nested": {"x": 1}}
    ;
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expectEqual(ShieldConfig.Mode.audit, cfg.mode);
}

test "loadFromJsonNoValidate allows invalid configs" {
    const json_str =
        \\{"taint": {"quarantine_threshold": 0}}
    ;
    const cfg = try loadFromJsonNoValidate(std.testing.allocator, json_str);
    try std.testing.expectEqual(@as(u32, 0), cfg.taint.quarantine_threshold);
}

test "load JSON with network booleans" {
    const json_str =
        \\{"network": {"block_rfc1918": false, "block_metadata": false, "max_egress_bytes_per_min": 52428800}}
    ;
    const cfg = try loadFromJson(std.testing.allocator, json_str);
    try std.testing.expect(!cfg.network.block_rfc1918);
    try std.testing.expect(!cfg.network.block_metadata);
    try std.testing.expectEqual(@as(u64, 52428800), cfg.network.max_egress_bytes_per_min);
}
