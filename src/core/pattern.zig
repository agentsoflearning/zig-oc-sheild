// OpenClaw Shield — Pattern types and matching helpers
//
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");

// ── Types ──────────────────────────────────────────────────────────────

pub const Category = enum {
    secret,
    pii,
    destructive,
    sensitive_file,
    skill_threat,
};

pub const Severity = enum {
    critical,
    warning,
    info,
};

pub const MatchFn = *const fn (input: []const u8, pos: usize) ?usize;

pub const Pattern = struct {
    name: []const u8,
    category: Category,
    severity: Severity,
    matchAt: MatchFn,
};

pub const Match = struct {
    pattern_name: []const u8,
    category: Category,
    severity: Severity,
    start: usize,
    end: usize,

    pub fn preview(self: Match, input: []const u8) []const u8 {
        const raw = input[self.start..self.end];
        if (raw.len > 12) return raw[0..12];
        return raw;
    }

    pub fn slice(self: Match, input: []const u8) []const u8 {
        return input[self.start..self.end];
    }
};

pub const RedactStrategy = enum {
    mask, // [REDACTED:pattern_name]
    partial, // sk-...abc123
    hash, // [SHA256:a1b2c3d4]
    drop, // (empty)
};

pub const RedactOptions = struct {
    strategy: RedactStrategy = .mask,
    tag: []const u8 = "REDACTED",
    partial_chars: usize = 4,
};

// ── Character class helpers ────────────────────────────────────────────

pub fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

pub fn isWordBoundary(input: []const u8, pos: usize) bool {
    const prev_is_word = if (pos > 0) isWordChar(input[pos - 1]) else false;
    const curr_is_word = if (pos < input.len) isWordChar(input[pos]) else false;
    return prev_is_word != curr_is_word;
}

pub fn isWordBoundaryAfter(input: []const u8, pos: usize) bool {
    // pos is one past the last matched character
    const prev_is_word = if (pos > 0) isWordChar(input[pos - 1]) else false;
    const curr_is_word = if (pos < input.len) isWordChar(input[pos]) else false;
    return prev_is_word != curr_is_word;
}

pub fn isAlnumOrDash(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-';
}

pub fn isAlnumOrUnderscore(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

pub fn isAlnumOrUnderscoreOrDash(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

pub fn isBase64Char(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=';
}

pub fn isBase64UrlChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

pub fn isTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '-' or c == '/' or c == '+' or c == '=';
}

pub fn isEmailLocalChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '%' or c == '+' or c == '-';
}

pub fn isEmailDomainChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '-';
}

pub fn isUpperAlphaDigit(c: u8) bool {
    return std.ascii.isUpper(c) or std.ascii.isDigit(c);
}

pub fn isSeparatorChar(c: u8) bool {
    return c == ' ' or c == '-' or c == '.';
}

/// Skip optional whitespace, return new position.
pub fn skipWhitespace(input: []const u8, start: usize) usize {
    var pos = start;
    while (pos < input.len and (input[pos] == ' ' or input[pos] == '\t')) {
        pos += 1;
    }
    return pos;
}

/// Match a set of literal alternatives at a given position.
/// Returns the length of the matched alternative, or null.
pub fn matchAlternatives(input: []const u8, pos: usize, alternatives: []const []const u8) ?usize {
    for (alternatives) |alt| {
        if (pos + alt.len <= input.len and std.mem.eql(u8, input[pos..][0..alt.len], alt)) {
            return alt.len;
        }
    }
    return null;
}

/// Count consecutive characters matching a predicate starting at pos.
pub fn countWhile(input: []const u8, start: usize, predicate: *const fn (u8) bool) usize {
    var pos = start;
    while (pos < input.len and predicate(input[pos])) {
        pos += 1;
    }
    return pos - start;
}

/// Check if a slice starts with a given prefix at the specified position.
pub fn startsWith(input: []const u8, pos: usize, prefix: []const u8) bool {
    if (pos + prefix.len > input.len) return false;
    return std.mem.eql(u8, input[pos..][0..prefix.len], prefix);
}

// ── Tests ──────────────────────────────────────────────────────────────

test "isWordBoundary" {
    const input = "hello world";
    try std.testing.expect(isWordBoundary(input, 0)); // start of word
    try std.testing.expect(!isWordBoundary(input, 1)); // middle of word
    try std.testing.expect(isWordBoundary(input, 5)); // end of word -> space
    try std.testing.expect(isWordBoundary(input, 6)); // space -> start of word
}

test "isWordBoundaryAfter" {
    const input = "rm -rf";
    try std.testing.expect(isWordBoundaryAfter(input, 2)); // after "rm"
    try std.testing.expect(!isWordBoundaryAfter(input, 1)); // middle of "rm"
}

test "skipWhitespace" {
    const input = "key  =  value";
    try std.testing.expectEqual(@as(usize, 5), skipWhitespace(input, 3));
}

test "countWhile alphanumeric" {
    const input = "abcDEF123!@#";
    try std.testing.expectEqual(@as(usize, 9), countWhile(input, 0, std.ascii.isAlphanumeric));
}

test "startsWith" {
    const input = "AKIA1234567890ABCDEF";
    try std.testing.expect(startsWith(input, 0, "AKIA"));
    try std.testing.expect(!startsWith(input, 0, "AKIB"));
    try std.testing.expect(!startsWith(input, 18, "AKIA"));
}

test "matchAlternatives" {
    const input = "aws_secret_access_key = value";
    const alts = [_][]const u8{ "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY" };
    const result = matchAlternatives(input, 0, &alts);
    try std.testing.expectEqual(@as(?usize, 21), result);
}
