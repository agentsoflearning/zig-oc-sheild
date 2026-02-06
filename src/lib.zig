// OpenClaw Shield — Library Root
//
// Zig-native security guardrail plugin for OpenClaw.
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0
//
// Public API surface for the scanning engine.

const std = @import("std");

// ── Core Modules ───────────────────────────────────────────────────────

pub const pattern = @import("core/pattern.zig");
pub const scanner = @import("core/scanner.zig");
pub const entropy = @import("core/entropy.zig");

// ── Pattern Modules ────────────────────────────────────────────────────

pub const secrets = @import("patterns/secrets.zig");
pub const pii = @import("patterns/pii.zig");
pub const destructive = @import("patterns/destructive.zig");
pub const sensitive_files = @import("patterns/sensitive_files.zig");

// ── Re-exported Types ──────────────────────────────────────────────────

pub const Pattern = pattern.Pattern;
pub const Match = pattern.Match;
pub const Category = pattern.Category;
pub const Severity = pattern.Severity;
pub const RedactOptions = pattern.RedactOptions;
pub const RedactStrategy = pattern.RedactStrategy;

pub const scan = scanner.scan;
pub const redact = scanner.redact;
pub const scanAndRedact = scanner.scanAndRedact;
pub const walkJsonAndRedact = scanner.walkJsonAndRedact;

pub const shannonEntropy = entropy.shannonEntropy;
pub const detectHighEntropy = entropy.detectHighEntropy;
pub const EntropyConfig = entropy.EntropyConfig;
pub const EntropyFlag = entropy.EntropyFlag;

pub const isSensitivePath = sensitive_files.isSensitivePath;
pub const matchSensitivePath = sensitive_files.matchSensitivePath;

// ── Convenience: All Text Patterns ─────────────────────────────────────

/// All text-scanning patterns combined (secrets + PII + destructive commands).
/// Use this with scan() / scanAndRedact() for comprehensive scanning.
pub fn allPatterns() []const Pattern {
    return &all_patterns_array;
}

/// Only secret detection patterns.
pub fn secretPatterns() []const Pattern {
    return &secrets.patterns;
}

/// Only PII detection patterns.
pub fn piiPatterns() []const Pattern {
    return &pii.patterns;
}

/// Only destructive command patterns.
pub fn destructivePatterns() []const Pattern {
    return &destructive.patterns;
}

const all_patterns_array = secrets.patterns ++ pii.patterns ++ destructive.patterns;

// ── Version ────────────────────────────────────────────────────────────

pub const version = "0.2.0";
pub const name = "OpenClaw Shield (Zig)";

// ── Tests ──────────────────────────────────────────────────────────────
// Pull in all module tests via @import references above.

test {
    // Force all referenced modules' tests to run
    _ = pattern;
    _ = scanner;
    _ = entropy;
    _ = secrets;
    _ = pii;
    _ = destructive;
    _ = sensitive_files;
}

// ── Integration Tests ──────────────────────────────────────────────────

test "all patterns scan — combined secret and PII" {
    const input =
        \\Contact: user@example.com
        \\AWS Key: AKIA1234567890ABCDEF
        \\SSN: 123-45-6789
    ;
    const matches = try scan(std.testing.allocator, input, allPatterns());
    defer std.testing.allocator.free(matches);

    // Should find email, AWS key, and SSN
    try std.testing.expectEqual(@as(usize, 3), matches.len);

    // Verify categories
    var found_secret = false;
    var found_pii = false;
    for (matches) |m| {
        if (m.category == .secret) found_secret = true;
        if (m.category == .pii) found_pii = true;
    }
    try std.testing.expect(found_secret);
    try std.testing.expect(found_pii);
}

test "all patterns scan — destructive command" {
    const input = "please run rm -rf /tmp/cache";
    const matches = try scan(std.testing.allocator, input, allPatterns());
    defer std.testing.allocator.free(matches);

    try std.testing.expect(matches.len >= 1);
    try std.testing.expectEqualStrings("cmd_rm", matches[0].pattern_name);
}

test "all patterns scan — clean text" {
    const input = "The quick brown fox jumps over the lazy dog.";
    const matches = try scan(std.testing.allocator, input, allPatterns());
    defer std.testing.allocator.free(matches);

    try std.testing.expectEqual(@as(usize, 0), matches.len);
}

test "sensitive path check" {
    try std.testing.expect(isSensitivePath("/home/user/.env"));
    try std.testing.expect(isSensitivePath("/home/user/.ssh/id_rsa"));
    try std.testing.expect(!isSensitivePath("/home/user/src/main.zig"));
}

test "redact combined secrets and PII" {
    const input = "email: user@example.com key: AKIA1234567890ABCDEF";
    var result = try scanAndRedact(std.testing.allocator, input, allPatterns(), .{});
    defer result.deinit();

    try std.testing.expect(result.matches.len == 2);
    try std.testing.expect(std.mem.indexOf(u8, result.redacted, "[REDACTED:email]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.redacted, "[REDACTED:aws_access_key]") != null);
}
