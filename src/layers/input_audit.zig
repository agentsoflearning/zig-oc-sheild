// OpenClaw Shield — L4: Input Audit
//
// Scans inbound messages for embedded secrets/PII and logs findings.
// Observe-only — never blocks. Maps to the message_received hook.
//
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const scanner = @import("../core/scanner.zig");
const pattern = @import("../core/pattern.zig");
const Match = pattern.Match;
const Category = pattern.Category;
const Severity = pattern.Severity;
const secrets = @import("../patterns/secrets.zig");
const pii_patterns = @import("../patterns/pii.zig");

const all_input_patterns = secrets.patterns ++ pii_patterns.patterns;

// ── Types ──────────────────────────────────────────────────────────────

pub const AuditEntry = struct {
    timestamp_ms: i64,
    session_key: []const u8,
    channel: []const u8,
    findings: []Match,
    secret_count: usize,
    pii_count: usize,
    severity: Severity,
    allocator: Allocator,

    pub fn deinit(self: *AuditEntry) void {
        self.allocator.free(self.findings);
    }

    pub fn hasSensitiveContent(self: AuditEntry) bool {
        return self.findings.len > 0;
    }
};

// ── Main Entry Point ───────────────────────────────────────────────────

/// Audit an inbound message. Returns an audit entry with findings.
/// This is observe-only — it never blocks or modifies the message.
pub fn auditMessage(
    allocator: Allocator,
    message: []const u8,
    session_key: []const u8,
    channel: []const u8,
) !AuditEntry {
    const findings = try scanner.scan(allocator, message, &all_input_patterns);

    var secret_count: usize = 0;
    var pii_count: usize = 0;
    var max_severity: Severity = .info;

    for (findings) |f| {
        switch (f.category) {
            .secret => secret_count += 1,
            .pii => pii_count += 1,
            else => {},
        }
        if (@intFromEnum(f.severity) < @intFromEnum(max_severity)) {
            max_severity = f.severity;
        }
    }

    return AuditEntry{
        .timestamp_ms = std.time.milliTimestamp(),
        .session_key = session_key,
        .channel = channel,
        .findings = findings,
        .secret_count = secret_count,
        .pii_count = pii_count,
        .severity = if (findings.len > 0) max_severity else .info,
        .allocator = allocator,
    };
}

/// Format an audit entry as a human-readable log line.
pub fn formatAuditLog(allocator: Allocator, entry: AuditEntry) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();

    try w.print("[oc-shield] L4:input-audit session={s} channel={s}", .{
        entry.session_key,
        entry.channel,
    });

    if (entry.findings.len == 0) {
        try w.writeAll(" status=clean");
    } else {
        try w.print(" status=flagged secrets={d} pii={d} severity={s} patterns=", .{
            entry.secret_count,
            entry.pii_count,
            @tagName(entry.severity),
        });
        for (entry.findings, 0..) |f, i| {
            if (i > 0) try w.writeAll(",");
            try w.writeAll(f.pattern_name);
        }
    }

    return out.toOwnedSlice();
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "auditMessage — clean message" {
    var entry = try auditMessage(testing.allocator, "Hello, how are you?", "session-1", "telegram");
    defer entry.deinit();

    try testing.expect(!entry.hasSensitiveContent());
    try testing.expectEqual(@as(usize, 0), entry.secret_count);
    try testing.expectEqual(@as(usize, 0), entry.pii_count);
}

test "auditMessage — message with secret" {
    var entry = try auditMessage(
        testing.allocator,
        "My API key is AKIA1234567890ABCDEF",
        "session-2",
        "slack",
    );
    defer entry.deinit();

    try testing.expect(entry.hasSensitiveContent());
    try testing.expectEqual(@as(usize, 1), entry.secret_count);
    try testing.expectEqual(@as(usize, 0), entry.pii_count);
    try testing.expectEqualStrings("aws_access_key", entry.findings[0].pattern_name);
}

test "auditMessage — message with PII" {
    var entry = try auditMessage(
        testing.allocator,
        "My SSN is 123-45-6789 and email is test@example.com",
        "session-3",
        "discord",
    );
    defer entry.deinit();

    try testing.expect(entry.hasSensitiveContent());
    try testing.expectEqual(@as(usize, 0), entry.secret_count);
    try testing.expectEqual(@as(usize, 2), entry.pii_count);
}

test "auditMessage — mixed secrets and PII" {
    var entry = try auditMessage(
        testing.allocator,
        "key=AKIA1234567890ABCDEF email=user@test.com ssn=123-45-6789",
        "session-4",
        "web",
    );
    defer entry.deinit();

    try testing.expect(entry.hasSensitiveContent());
    try testing.expectEqual(@as(usize, 1), entry.secret_count);
    try testing.expectEqual(@as(usize, 2), entry.pii_count);
}

test "formatAuditLog — clean" {
    var entry = try auditMessage(testing.allocator, "clean message", "s1", "web");
    defer entry.deinit();

    const log = try formatAuditLog(testing.allocator, entry);
    defer testing.allocator.free(log);

    try testing.expect(std.mem.indexOf(u8, log, "status=clean") != null);
}

test "formatAuditLog — flagged" {
    var entry = try auditMessage(testing.allocator, "key: AKIA1234567890ABCDEF", "s2", "slack");
    defer entry.deinit();

    const log = try formatAuditLog(testing.allocator, entry);
    defer testing.allocator.free(log);

    try testing.expect(std.mem.indexOf(u8, log, "status=flagged") != null);
    try testing.expect(std.mem.indexOf(u8, log, "secrets=1") != null);
    try testing.expect(std.mem.indexOf(u8, log, "aws_access_key") != null);
}
