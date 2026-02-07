// OpenClaw Shield — Policy Engine
//
// Resolves policies from profile defaults + per-session overrides.
// Produces immutable PolicyCapsule snapshots for decision functions.
// All operations are pure — no I/O, no side effects.

const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("../layers/config.zig");
const ShieldConfig = config.ShieldConfig;
const Profile = config.Profile;
const types = @import("types.zig");
const PolicyCapsule = types.PolicyCapsule;
const PolicyVersion = types.PolicyVersion;
const PatternOverrides = types.PatternOverrides;
const RegionConfig = types.RegionConfig;
const validator = @import("validator.zig");

// ── Profile Defaults ────────────────────────────────────────────────
// These mirror Appendix C of PLAN.md and the TS bridge defaults.

const default_ports_web = [_]u16{ 80, 443 };
const default_ports_dev = [_]u16{ 80, 443, 8080, 3000 };
const default_ports_strict = [_]u16{443};

const homelab_hosts = [_][]const u8{"*"};
const corpdev_hosts = [_][]const u8{"*.internal.corp"};
const research_hosts = [_][]const u8{"*"};

const wildcard_bins = [_][]const u8{"*"};
const corpdev_bins = [_][]const u8{ "git", "node", "npx", "python" };
const research_bins = [_][]const u8{ "git", "node", "npx", "python", "pip" };

pub fn profileDefaults(profile: Profile) ShieldConfig {
    return switch (profile) {
        .home_lab => .{
            .mode = .audit,
            .profile = .home_lab,
            .network = .{
                .allowed_hosts = &homelab_hosts,
                .allowed_ports = &default_ports_dev,
                .block_rfc1918 = false,
                .block_localhost = false,
                .block_link_local = false,
                .block_metadata = true,
                .max_egress_bytes_per_min = 104_857_600, // 100 MB
            },
            .process = .{
                .allow_spawn = true,
                .allowed_binaries = &wildcard_bins,
                .deny_shells = false,
                .max_exec_per_min = 100,
            },
            .taint = .{
                .auto_escalate = false,
                .quarantine_threshold = 999,
                .cool_down_seconds = 60,
            },
        },
        .corp_dev => .{
            .mode = .enforce,
            .profile = .corp_dev,
            .network = .{
                .allowed_hosts = &corpdev_hosts,
                .allowed_ports = &default_ports_web,
                .block_rfc1918 = true,
                .block_localhost = false,
                .block_link_local = true,
                .block_metadata = true,
                .max_egress_bytes_per_min = 52_428_800, // 50 MB
            },
            .process = .{
                .allow_spawn = true,
                .allowed_binaries = &corpdev_bins,
                .deny_shells = true,
                .max_exec_per_min = 30,
            },
            .taint = .{
                .auto_escalate = true,
                .quarantine_threshold = 10,
                .cool_down_seconds = 300,
            },
        },
        .prod => ShieldConfig{}, // Default config IS prod
        .research => .{
            .mode = .enforce,
            .profile = .research,
            .network = .{
                .allowed_hosts = &research_hosts,
                .allowed_ports = &default_ports_web,
                .block_rfc1918 = true,
                .block_localhost = true,
                .block_link_local = true,
                .block_metadata = true,
                .max_egress_bytes_per_min = 52_428_800, // 50 MB
            },
            .process = .{
                .allow_spawn = true,
                .allowed_binaries = &research_bins,
                .deny_shells = true,
                .max_exec_per_min = 30,
            },
            .taint = .{
                .auto_escalate = true,
                .quarantine_threshold = 10,
                .cool_down_seconds = 300,
            },
        },
    };
}

// ── Policy Engine ───────────────────────────────────────────────────

/// Policy engine that resolves configs and tracks per-session overrides.
pub const PolicyEngine = struct {
    allocator: Allocator,
    base_config: ShieldConfig,
    version: PolicyVersion,
    /// Per-session config overrides (session_id → override config).
    session_overrides: std.StringHashMap(ShieldConfig),

    pub fn init(allocator: Allocator, base_config: ShieldConfig) PolicyEngine {
        return .{
            .allocator = allocator,
            .base_config = base_config,
            .version = PolicyVersion{},
            .session_overrides = std.StringHashMap(ShieldConfig).init(allocator),
        };
    }

    pub fn deinit(self: *PolicyEngine) void {
        self.session_overrides.deinit();
    }

    /// Get the base config (no session overrides applied).
    pub fn getBaseConfig(self: PolicyEngine) ShieldConfig {
        return self.base_config;
    }

    /// Update the base config. Bumps the version.
    pub fn setBaseConfig(self: *PolicyEngine, new_config: ShieldConfig) void {
        self.base_config = new_config;
        self.version = self.version.bump();
    }

    /// Switch to a different profile. Replaces the base config with profile defaults.
    pub fn setProfile(self: *PolicyEngine, profile: Profile) void {
        self.base_config = profileDefaults(profile);
        self.version = self.version.bump();
    }

    /// Set a per-session config override.
    pub fn setSessionOverride(self: *PolicyEngine, session_id: []const u8, override: ShieldConfig) !void {
        try self.session_overrides.put(session_id, override);
        self.version = self.version.bump();
    }

    /// Remove a per-session override.
    pub fn clearSessionOverride(self: *PolicyEngine, session_id: []const u8) void {
        _ = self.session_overrides.remove(session_id);
    }

    /// Resolve the effective config for a session.
    /// Priority: session override → base config (profile defaults are baked into base).
    pub fn resolve(self: PolicyEngine, session_id: []const u8) ShieldConfig {
        if (self.session_overrides.get(session_id)) |override| {
            return override;
        }
        return self.base_config;
    }

    /// Create an immutable PolicyCapsule for a session. This is what
    /// gets passed to all decision functions.
    pub fn createCapsule(
        self: PolicyEngine,
        session_id: []const u8,
        pattern_overrides: PatternOverrides,
        pii_regions: RegionConfig,
    ) PolicyCapsule {
        return .{
            .version = self.version,
            .config = self.resolve(session_id),
            .pattern_overrides = pattern_overrides,
            .pii_regions = pii_regions,
            .session_id = session_id,
            .created_at = std.time.timestamp(),
        };
    }

    /// Validate the current base config.
    pub fn validateBase(self: PolicyEngine) validator.ValidationResult {
        return validator.validate(self.base_config);
    }

    /// Get the current policy version.
    pub fn getVersion(self: PolicyEngine) PolicyVersion {
        return self.version;
    }
};

// ── Merge Utility ───────────────────────────────────────────────────

/// Merge override values onto a base config. Only non-default fields
/// in the override are applied (since we can't distinguish "explicitly
/// set to default" from "not set" in Zig structs, this is a full
/// replacement — callers should only provide complete overrides).
pub fn mergeConfigs(base: ShieldConfig, override: ShieldConfig) ShieldConfig {
    // For now, override wins completely. A field-by-field selective
    // merge would require Option<T> wrappers or sentinel values,
    // which adds complexity without clear benefit.
    _ = base;
    return override;
}

// ── Tests ───────────────────────────────────────────────────────────

test "profileDefaults — home_lab is audit mode" {
    const cfg = profileDefaults(.home_lab);
    try std.testing.expectEqual(ShieldConfig.Mode.audit, cfg.mode);
    try std.testing.expect(!cfg.network.block_rfc1918);
    try std.testing.expect(cfg.process.allow_spawn);
    try std.testing.expect(!cfg.process.deny_shells);
    try std.testing.expect(!cfg.taint.auto_escalate);
}

test "profileDefaults — prod is strict enforce" {
    const cfg = profileDefaults(.prod);
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, cfg.mode);
    try std.testing.expect(cfg.network.block_rfc1918);
    try std.testing.expect(cfg.network.block_metadata);
    try std.testing.expect(!cfg.process.allow_spawn);
    try std.testing.expect(cfg.process.deny_shells);
    try std.testing.expectEqual(@as(u32, 5), cfg.taint.quarantine_threshold);
}

test "profileDefaults — corp_dev allows spawn with allowlist" {
    const cfg = profileDefaults(.corp_dev);
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, cfg.mode);
    try std.testing.expect(cfg.process.allow_spawn);
    try std.testing.expect(cfg.process.deny_shells);
    try std.testing.expect(cfg.process.allowed_binaries.len > 0);
}

test "profileDefaults — research allows public web" {
    const cfg = profileDefaults(.research);
    try std.testing.expect(cfg.network.block_rfc1918);
    try std.testing.expect(cfg.process.allow_spawn);
    try std.testing.expect(cfg.network.allowed_hosts.len > 0);
}

test "PolicyEngine — init, resolve, and version" {
    var engine = PolicyEngine.init(std.testing.allocator, profileDefaults(.prod));
    defer engine.deinit();

    const cfg = engine.resolve("sess-1");
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, cfg.mode);
    try std.testing.expectEqual(@as(u64, 0), engine.getVersion().sequence);
}

test "PolicyEngine — setProfile bumps version" {
    var engine = PolicyEngine.init(std.testing.allocator, profileDefaults(.prod));
    defer engine.deinit();

    engine.setProfile(.home_lab);
    try std.testing.expectEqual(@as(u64, 1), engine.getVersion().sequence);
    try std.testing.expectEqual(ShieldConfig.Mode.audit, engine.resolve("sess-1").mode);
}

test "PolicyEngine — session overrides" {
    var engine = PolicyEngine.init(std.testing.allocator, profileDefaults(.prod));
    defer engine.deinit();

    // Session override for sess-1
    var sess_cfg = profileDefaults(.home_lab);
    sess_cfg.taint.quarantine_threshold = 50;
    try engine.setSessionOverride("sess-1", sess_cfg);

    // sess-1 gets override
    const c1 = engine.resolve("sess-1");
    try std.testing.expectEqual(ShieldConfig.Mode.audit, c1.mode);
    try std.testing.expectEqual(@as(u32, 50), c1.taint.quarantine_threshold);

    // sess-2 gets base
    const c2 = engine.resolve("sess-2");
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, c2.mode);

    // Clear override
    engine.clearSessionOverride("sess-1");
    const c3 = engine.resolve("sess-1");
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, c3.mode);
}

test "PolicyEngine — createCapsule" {
    var engine = PolicyEngine.init(std.testing.allocator, profileDefaults(.corp_dev));
    defer engine.deinit();

    const capsule = engine.createCapsule("sess-1", .{}, .{});
    try std.testing.expectEqual(ShieldConfig.Mode.enforce, capsule.config.mode);
    try std.testing.expectEqualStrings("sess-1", capsule.session_id);
    try std.testing.expect(capsule.created_at > 0);
}

test "PolicyEngine — setBaseConfig" {
    var engine = PolicyEngine.init(std.testing.allocator, profileDefaults(.prod));
    defer engine.deinit();

    var new_cfg = profileDefaults(.prod);
    new_cfg.taint.quarantine_threshold = 20;
    engine.setBaseConfig(new_cfg);

    try std.testing.expectEqual(@as(u64, 1), engine.getVersion().sequence);
    try std.testing.expectEqual(@as(u32, 20), engine.resolve("s1").taint.quarantine_threshold);
}

test "PolicyEngine — validateBase" {
    var engine = PolicyEngine.init(std.testing.allocator, profileDefaults(.prod));
    defer engine.deinit();

    const result = engine.validateBase();
    try std.testing.expect(result.isValid());
}

test "all four profiles validate" {
    const profiles = [_]Profile{ .home_lab, .corp_dev, .prod, .research };
    for (profiles) |p| {
        const cfg = profileDefaults(p);
        try std.testing.expect(validator.isValid(cfg));
    }
}
