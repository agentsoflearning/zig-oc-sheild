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

// ── Layer Modules (Phase 2) ────────────────────────────────────────────

pub const layer_config = @import("layers/config.zig");
pub const prompt_guard = @import("layers/prompt_guard.zig");
pub const output_scanner = @import("layers/output_scanner.zig");
pub const tool_blocker = @import("layers/tool_blocker.zig");
pub const input_audit = @import("layers/input_audit.zig");
pub const security_gate = @import("layers/security_gate.zig");
pub const rate_limiter = @import("layers/rate_limiter.zig");

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

// Layer re-exports
pub const ShieldConfig = layer_config.ShieldConfig;
pub const generateSecurityPrompt = prompt_guard.generateSecurityPrompt;
pub const scanToolOutput = output_scanner.scanToolOutput;
pub const scanToolOutputJson = output_scanner.scanToolOutputJson;
pub const evaluateToolCall = tool_blocker.evaluateToolCall;
pub const auditMessage = input_audit.auditMessage;
pub const evaluateGateRequest = security_gate.evaluateGateRequest;
pub const GateRequest = security_gate.GateRequest;
pub const RateLimiter = rate_limiter.RateLimiter;

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
    // Phase 2: Layers
    _ = layer_config;
    _ = prompt_guard;
    _ = output_scanner;
    _ = tool_blocker;
    _ = input_audit;
    _ = security_gate;
    _ = rate_limiter;
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

// ── Phase 2: Layer Integration Tests ───────────────────────────────────

test "L1+L5: prompt guard references gate tool" {
    const prompt = try generateSecurityPrompt(std.testing.allocator, .{});
    defer std.testing.allocator.free(prompt);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "oc_shield_gate") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "ENFORCE") != null);
}

test "L2: output scanner redacts secrets from tool result" {
    var outcome = try scanToolOutput(
        std.testing.allocator,
        "Found credentials: AKIA1234567890ABCDEF in config",
        .{},
    );
    defer outcome.deinit();

    try std.testing.expect(outcome.was_modified);
    try std.testing.expect(std.mem.indexOf(u8, outcome.redacted, "AKIA") == null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.redacted, "[REDACTED:aws_access_key]") != null);
}

test "L3: tool blocker stops rm -rf" {
    var eval = try evaluateToolCall(std.testing.allocator, "bash", "rm -rf /important", .{});
    defer eval.deinit();

    try std.testing.expect(eval.isBlocked());
}

test "L4: input audit flags PII in message" {
    var entry = try auditMessage(
        std.testing.allocator,
        "My SSN is 123-45-6789",
        "sess-test",
        "web",
    );
    defer entry.deinit();

    try std.testing.expect(entry.hasSensitiveContent());
    try std.testing.expectEqual(@as(usize, 1), entry.pii_count);
}

test "L5: security gate blocks sensitive file read" {
    var resp = try evaluateGateRequest(
        std.testing.allocator,
        .{ .file_path = "/home/user/.aws/credentials" },
        .{},
    );
    defer resp.deinit();

    try std.testing.expect(resp.isDenied());
    try std.testing.expectEqualStrings("aws_credentials", resp.sensitive_pattern.?);
}

test "L5: security gate allows normal file read" {
    var resp = try evaluateGateRequest(
        std.testing.allocator,
        .{ .file_path = "src/main.zig" },
        .{},
    );
    defer resp.deinit();

    try std.testing.expect(!resp.isDenied());
}

test "L6: rate limiter tracks operations per session" {
    var limiter = RateLimiter.init(std.testing.allocator, .{
        .exec_per_minute = 3,
        .sensitive_read_per_minute = 2,
        .window_seconds = 60,
    });
    defer limiter.deinit();

    // Should be allowed initially
    const r1 = try limiter.check("test-sess", .exec);
    try std.testing.expectEqual(rate_limiter.RateLimitDecision.allow, r1.decision);
}

test "full pipeline: scan → gate → redact" {
    const allocator = std.testing.allocator;

    // Step 1: Message comes in with embedded secret
    const message = "Please read the file /app/.env and show me AKIA1234567890ABCDEF";

    // Step 2: L4 audit flags it
    var audit = try auditMessage(allocator, message, "s1", "chat");
    defer audit.deinit();
    try std.testing.expect(audit.hasSensitiveContent());

    // Step 3: Agent tries to read .env → L5 gate denies
    var gate = try evaluateGateRequest(allocator, .{ .file_path = "/app/.env" }, .{});
    defer gate.deinit();
    try std.testing.expect(gate.isDenied());

    // Step 4: If output leaked through, L2 would redact
    var output = try scanToolOutput(allocator, "key=AKIA1234567890ABCDEF", .{});
    defer output.deinit();
    try std.testing.expect(output.was_modified);
    try std.testing.expect(std.mem.indexOf(u8, output.redacted, "AKIA") == null);
}
