// OpenClaw Shield — Policy Types
//
// Immutable policy capsules, per-pattern configuration, and versioning.
// PolicyCapsule is the frozen snapshot passed to every decision function.

const std = @import("std");
const config = @import("../layers/config.zig");
const pat = @import("../core/pattern.zig");

pub const ShieldConfig = config.ShieldConfig;
pub const Profile = config.Profile;
pub const Mode = ShieldConfig.Mode;
pub const RedactStrategy = pat.RedactStrategy;
pub const Category = pat.Category;

// ── Policy Version ──────────────────────────────────────────────────

/// Monotonically increasing version number for policy snapshots.
/// Allows audit logs to reference which policy was active for each decision.
pub const PolicyVersion = struct {
    major: u16 = 0,
    minor: u16 = 1,
    sequence: u64 = 0, // Auto-incremented on each policy change

    pub fn bump(self: PolicyVersion) PolicyVersion {
        return .{
            .major = self.major,
            .minor = self.minor,
            .sequence = self.sequence + 1,
        };
    }

    pub fn format(self: PolicyVersion, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}", .{ self.major, self.minor, self.sequence });
    }
};

// ── Per-Pattern Configuration ───────────────────────────────────────

/// Per-pattern overrides: enable/disable individual patterns, change
/// their redaction strategy, or override severity.
pub const PatternOverride = struct {
    name: []const u8,
    enabled: bool = true,
    redact_strategy: ?RedactStrategy = null, // null = use global default
    severity_override: ?pat.Severity = null, // null = use pattern default
};

/// Lookup table keyed by pattern name.
pub const PatternOverrides = struct {
    entries: []const PatternOverride = &.{},

    /// Find override for a given pattern name. Returns null if no override.
    pub fn get(self: PatternOverrides, name: []const u8) ?PatternOverride {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry;
        }
        return null;
    }

    /// Check if a pattern is enabled (default: true if no override).
    pub fn isEnabled(self: PatternOverrides, name: []const u8) bool {
        if (self.get(name)) |entry| return entry.enabled;
        return true;
    }

    /// Get the redaction strategy for a pattern (null = use global).
    pub fn getRedactStrategy(self: PatternOverrides, name: []const u8) ?RedactStrategy {
        if (self.get(name)) |entry| return entry.redact_strategy;
        return null;
    }
};

// ── Region Configuration ────────────────────────────────────────────

/// Which PII regions to scan for.
pub const Region = enum {
    us,
    uk,
    eu,
    ca,
    au,
};

pub const RegionConfig = struct {
    regions: []const Region = &default_regions,

    const default_regions = [_]Region{ .us, .uk, .eu, .ca, .au };

    pub fn includes(self: RegionConfig, region: Region) bool {
        for (self.regions) |r| {
            if (r == region) return true;
        }
        return false;
    }
};

// ── Policy Capsule ──────────────────────────────────────────────────

/// Immutable policy snapshot — the single source of truth for any
/// decision function. Created once per policy resolution, then passed
/// by value (never mutated).
pub const PolicyCapsule = struct {
    version: PolicyVersion = .{},
    config: ShieldConfig = .{},
    pattern_overrides: PatternOverrides = .{},
    pii_regions: RegionConfig = .{},
    session_id: []const u8 = "",
    created_at: i64 = 0, // Unix timestamp

    /// Get the effective redaction strategy for a given pattern.
    pub fn effectiveRedactStrategy(self: PolicyCapsule, pattern_name: []const u8) RedactStrategy {
        // Per-pattern override takes priority over global
        if (self.pattern_overrides.getRedactStrategy(pattern_name)) |s| return s;
        return self.config.redaction.strategy;
    }

    /// Check whether a pattern should be active for this capsule.
    pub fn isPatternEnabled(self: PolicyCapsule, pattern_name: []const u8) bool {
        return self.pattern_overrides.isEnabled(pattern_name);
    }

    /// Is the capsule in audit mode (log-only, no blocking)?
    pub fn isAuditMode(self: PolicyCapsule) bool {
        return self.config.mode == .audit;
    }

    /// Is the capsule in enforce mode?
    pub fn isEnforceMode(self: PolicyCapsule) bool {
        return self.config.mode == .enforce;
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "PolicyVersion bump" {
    const v0 = PolicyVersion{};
    try std.testing.expectEqual(@as(u64, 0), v0.sequence);
    const v1 = v0.bump();
    try std.testing.expectEqual(@as(u64, 1), v1.sequence);
    const v2 = v1.bump();
    try std.testing.expectEqual(@as(u64, 2), v2.sequence);
}

test "PolicyVersion format" {
    const v = PolicyVersion{ .major = 1, .minor = 2, .sequence = 42 };
    var buf: [32]u8 = undefined;
    const s = try v.format(&buf);
    try std.testing.expectEqualStrings("1.2.42", s);
}

test "PatternOverrides — get and isEnabled" {
    const entries = [_]PatternOverride{
        .{ .name = "aws_access_key", .enabled = true, .redact_strategy = .hash },
        .{ .name = "email", .enabled = false },
    };
    const overrides = PatternOverrides{ .entries = &entries };

    // aws_access_key: enabled, hash redaction
    try std.testing.expect(overrides.isEnabled("aws_access_key"));
    try std.testing.expectEqual(RedactStrategy.hash, overrides.getRedactStrategy("aws_access_key").?);

    // email: disabled
    try std.testing.expect(!overrides.isEnabled("email"));

    // unknown: enabled by default, no redaction override
    try std.testing.expect(overrides.isEnabled("us_ssn"));
    try std.testing.expect(overrides.getRedactStrategy("us_ssn") == null);
}

test "RegionConfig includes" {
    const rc = RegionConfig{}; // default: all regions
    try std.testing.expect(rc.includes(.us));
    try std.testing.expect(rc.includes(.uk));
    try std.testing.expect(rc.includes(.au));

    // Custom regions
    const uk_only = [_]Region{.uk};
    const rc2 = RegionConfig{ .regions = &uk_only };
    try std.testing.expect(rc2.includes(.uk));
    try std.testing.expect(!rc2.includes(.us));
}

test "PolicyCapsule — effectiveRedactStrategy" {
    const entries = [_]PatternOverride{
        .{ .name = "email", .redact_strategy = .partial },
    };
    const capsule = PolicyCapsule{
        .config = .{ .redaction = .{ .strategy = .mask } },
        .pattern_overrides = .{ .entries = &entries },
    };

    // email has per-pattern override → partial
    try std.testing.expectEqual(RedactStrategy.partial, capsule.effectiveRedactStrategy("email"));
    // aws_access_key has no override → global mask
    try std.testing.expectEqual(RedactStrategy.mask, capsule.effectiveRedactStrategy("aws_access_key"));
}

test "PolicyCapsule — isPatternEnabled and mode" {
    const entries = [_]PatternOverride{
        .{ .name = "email", .enabled = false },
    };
    const capsule = PolicyCapsule{
        .config = .{ .mode = .audit },
        .pattern_overrides = .{ .entries = &entries },
    };

    try std.testing.expect(!capsule.isPatternEnabled("email"));
    try std.testing.expect(capsule.isPatternEnabled("us_ssn"));
    try std.testing.expect(capsule.isAuditMode());
    try std.testing.expect(!capsule.isEnforceMode());
}
