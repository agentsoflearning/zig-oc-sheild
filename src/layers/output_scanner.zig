// OpenClaw Shield — L2: Output Scanner
//
// Scans and redacts secrets/PII from tool output before persistence.
// Maps to the tool_result_persist hook in OpenClaw.
//
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const scanner = @import("../core/scanner.zig");
const pattern = @import("../core/pattern.zig");
const entropy_mod = @import("../core/entropy.zig");
const config_mod = @import("config.zig");
const ShieldConfig = config_mod.ShieldConfig;
const Match = pattern.Match;

// Re-import pattern sets
const secrets = @import("../patterns/secrets.zig");
const pii = @import("../patterns/pii.zig");
const destructive = @import("../patterns/destructive.zig");

const all_patterns = secrets.patterns ++ pii.patterns ++ destructive.patterns;

// ── Types ──────────────────────────────────────────────────────────────

pub const ScanOutcome = struct {
    redacted: []u8,
    matches: []Match,
    entropy_flags: []entropy_mod.EntropyFlag,
    was_modified: bool,
    allocator: Allocator,

    pub fn deinit(self: *ScanOutcome) void {
        self.allocator.free(self.redacted);
        self.allocator.free(self.matches);
        self.allocator.free(self.entropy_flags);
    }
};

// ── Main Entry Point ───────────────────────────────────────────────────

/// Scan a tool result string and redact sensitive content.
/// In audit mode, still scans but returns the original content unmodified.
pub fn scanToolOutput(
    allocator: Allocator,
    output: []const u8,
    config: ShieldConfig,
) !ScanOutcome {
    const redact_opts = config_mod.toRedactOptions(config);

    // Pattern matching
    const matches = try scanner.scan(allocator, output, &all_patterns);
    errdefer allocator.free(matches);

    // Entropy detection
    const entropy_flags = if (config.entropy.enabled)
        try entropy_mod.detectHighEntropy(allocator, output, .{
            .base64_threshold = config.entropy.base64_threshold,
            .hex_threshold = config.entropy.hex_threshold,
        })
    else
        try allocator.alloc(entropy_mod.EntropyFlag, 0);
    errdefer allocator.free(entropy_flags);

    const has_findings = matches.len > 0 or entropy_flags.len > 0;

    // In audit mode, return original content unchanged
    if (config.mode == .audit or !has_findings) {
        const copy = try allocator.dupe(u8, output);
        return ScanOutcome{
            .redacted = copy,
            .matches = matches,
            .entropy_flags = entropy_flags,
            .was_modified = false,
            .allocator = allocator,
        };
    }

    // Enforce mode: redact
    const redacted = try scanner.redact(allocator, output, matches, redact_opts);
    return ScanOutcome{
        .redacted = redacted,
        .matches = matches,
        .entropy_flags = entropy_flags,
        .was_modified = true,
        .allocator = allocator,
    };
}

/// Scan a tool result that is JSON-encoded. Walks all string values.
pub fn scanToolOutputJson(
    allocator: Allocator,
    json_output: []const u8,
    config: ShieldConfig,
) !ScanOutcome {
    const redact_opts = config_mod.toRedactOptions(config);

    // For JSON, we walk and redact in one step
    var walk_result = try scanner.walkJsonAndRedact(allocator, json_output, &all_patterns, redact_opts);

    // Also collect flat matches for reporting
    const matches = try scanner.scan(allocator, json_output, &all_patterns);
    errdefer allocator.free(matches);

    const entropy_flags = try allocator.alloc(entropy_mod.EntropyFlag, 0);

    const was_modified = walk_result.match_count > 0;

    if (config.mode == .audit or !was_modified) {
        // Return original in audit mode
        walk_result.deinit();
        const copy = try allocator.dupe(u8, json_output);
        return ScanOutcome{
            .redacted = copy,
            .matches = matches,
            .entropy_flags = entropy_flags,
            .was_modified = false,
            .allocator = allocator,
        };
    }

    return ScanOutcome{
        .redacted = walk_result.output,
        .matches = matches,
        .entropy_flags = entropy_flags,
        .was_modified = true,
        .allocator = allocator,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "scanToolOutput — detects and redacts secret" {
    const output = "Result: AKIA1234567890ABCDEF found";
    var outcome = try scanToolOutput(testing.allocator, output, .{});
    defer outcome.deinit();

    try testing.expect(outcome.was_modified);
    try testing.expectEqual(@as(usize, 1), outcome.matches.len);
    try testing.expect(std.mem.indexOf(u8, outcome.redacted, "[REDACTED:aws_access_key]") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.redacted, "AKIA") == null);
}

test "scanToolOutput — audit mode preserves content" {
    const output = "Result: AKIA1234567890ABCDEF found";
    var outcome = try scanToolOutput(testing.allocator, output, .{ .mode = .audit });
    defer outcome.deinit();

    try testing.expect(!outcome.was_modified);
    try testing.expectEqual(@as(usize, 1), outcome.matches.len);
    try testing.expectEqualStrings(output, outcome.redacted);
}

test "scanToolOutput — clean content unchanged" {
    const output = "All good, no secrets here";
    var outcome = try scanToolOutput(testing.allocator, output, .{});
    defer outcome.deinit();

    try testing.expect(!outcome.was_modified);
    try testing.expectEqual(@as(usize, 0), outcome.matches.len);
}

test "scanToolOutput — partial redaction strategy" {
    const output = "key: AKIA1234567890ABCDEF";
    var config = ShieldConfig{};
    config.redaction.strategy = .partial;
    config.redaction.partial_chars = 4;
    var outcome = try scanToolOutput(testing.allocator, output, config);
    defer outcome.deinit();

    try testing.expect(outcome.was_modified);
    try testing.expect(std.mem.indexOf(u8, outcome.redacted, "AKIA...CDEF") != null);
}
