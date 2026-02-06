// OpenClaw Shield — Destructive Command Patterns
//
// Ported from openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0
// Original regex: /\b(rm|rmdir|unlink|del|format|mkfs|dd\s+if=)\b/

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const Pattern = pattern.Pattern;

// ── Pattern Table ──────────────────────────────────────────────────────

pub const patterns = [_]Pattern{
    .{ .name = "cmd_rm", .category = .destructive, .severity = .critical, .matchAt = matchRm },
    .{ .name = "cmd_rmdir", .category = .destructive, .severity = .critical, .matchAt = matchRmdir },
    .{ .name = "cmd_unlink", .category = .destructive, .severity = .critical, .matchAt = matchUnlink },
    .{ .name = "cmd_del", .category = .destructive, .severity = .critical, .matchAt = matchDel },
    .{ .name = "cmd_format", .category = .destructive, .severity = .critical, .matchAt = matchFormat },
    .{ .name = "cmd_mkfs", .category = .destructive, .severity = .critical, .matchAt = matchMkfs },
    .{ .name = "cmd_dd", .category = .destructive, .severity = .critical, .matchAt = matchDd },
};

// ── Match Functions ────────────────────────────────────────────────────

/// Match a keyword with word boundaries on both sides.
fn matchKeyword(input: []const u8, pos: usize, keyword: []const u8) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    if (!pattern.startsWith(input, pos, keyword)) return null;
    if (!pattern.isWordBoundaryAfter(input, pos + keyword.len)) return null;
    return keyword.len;
}

fn matchRm(input: []const u8, pos: usize) ?usize {
    // Match "rm" but not "rmdir"
    if (!pattern.isWordBoundary(input, pos)) return null;
    if (!pattern.startsWith(input, pos, "rm")) return null;
    // Ensure it's not "rmdir"
    if (pattern.startsWith(input, pos, "rmdir")) return null;
    if (!pattern.isWordBoundaryAfter(input, pos + 2)) return null;
    return 2;
}

fn matchRmdir(input: []const u8, pos: usize) ?usize {
    return matchKeyword(input, pos, "rmdir");
}

fn matchUnlink(input: []const u8, pos: usize) ?usize {
    return matchKeyword(input, pos, "unlink");
}

fn matchDel(input: []const u8, pos: usize) ?usize {
    return matchKeyword(input, pos, "del");
}

fn matchFormat(input: []const u8, pos: usize) ?usize {
    return matchKeyword(input, pos, "format");
}

fn matchMkfs(input: []const u8, pos: usize) ?usize {
    return matchKeyword(input, pos, "mkfs");
}

/// Match "dd" followed by whitespace and "if=" (the dangerous form)
fn matchDd(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    if (!pattern.startsWith(input, pos, "dd")) return null;
    var p = pos + 2;
    // Must have at least one whitespace
    if (p >= input.len or (input[p] != ' ' and input[p] != '\t')) return null;
    p = pattern.skipWhitespace(input, p);
    // Must have "if="
    if (!pattern.startsWith(input, p, "if=")) return null;
    p += 3;
    // Consume the value (non-whitespace)
    while (p < input.len and input[p] != ' ' and input[p] != '\t' and input[p] != '\n') {
        p += 1;
    }
    return p - pos;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "rm" {
    try testing.expect(matchRm("rm -rf /", 0) != null);
    try testing.expect(matchRm("sudo rm file", 5) != null);
    try testing.expectEqual(@as(?usize, null), matchRm("rmdir foo", 0)); // should not match rmdir
    try testing.expectEqual(@as(?usize, null), matchRm("alarm", 2)); // no word boundary
}

test "rmdir" {
    try testing.expect(matchRmdir("rmdir foo", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchRmdir("rm foo", 0));
}

test "unlink" {
    try testing.expect(matchUnlink("unlink file.txt", 0) != null);
}

test "del" {
    try testing.expect(matchDel("del /q file", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchDel("delete", 0)); // no word boundary
    try testing.expectEqual(@as(?usize, null), matchDel("model", 2)); // no word boundary
}

test "format" {
    try testing.expect(matchFormat("format C:", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchFormat("formatted", 0)); // no word boundary
}

test "mkfs" {
    try testing.expect(matchMkfs("mkfs /dev/sda", 0) != null);
}

test "dd with if=" {
    try testing.expect(matchDd("dd if=/dev/zero of=/dev/sda", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchDd("dd of=/dev/null", 0)); // no if=
    try testing.expectEqual(@as(?usize, null), matchDd("added", 2)); // no word boundary
}
