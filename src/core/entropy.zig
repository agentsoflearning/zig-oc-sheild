// OpenClaw Shield — Shannon Entropy Analyzer
//
// Detects high-entropy strings that may be undiscovered secrets.
// This is a new capability not present in the original openclaw-shield.

const std = @import("std");
const math = std.math;
const Allocator = std.mem.Allocator;

// ── Types ──────────────────────────────────────────────────────────────

pub const Encoding = enum {
    base64,
    hex,
    raw,
};

pub const EntropyFlag = struct {
    start: usize,
    end: usize,
    entropy: f64,
    encoding: Encoding,
};

pub const EntropyConfig = struct {
    base64_threshold: f64 = 4.5,
    hex_threshold: f64 = 3.5,
    raw_threshold: f64 = 4.8,
    min_length: usize = 16,
    max_length: usize = 256,
};

// ── Shannon Entropy ────────────────────────────────────────────────────

/// Calculate Shannon entropy of a byte slice in bits per character.
pub fn shannonEntropy(data: []const u8) f64 {
    if (data.len == 0) return 0.0;

    var freq: [256]u32 = [_]u32{0} ** 256;
    for (data) |byte| {
        freq[byte] += 1;
    }

    const n: f64 = @floatFromInt(data.len);
    var entropy: f64 = 0.0;

    for (freq) |count| {
        if (count == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(count)) / n;
        entropy -= p * @log(p) / @log(2.0);
    }

    return entropy;
}

// ── High-Entropy String Detection ──────────────────────────────────────

/// Scan for high-entropy substrings that might be undiscovered secrets.
/// Returns owned slice of EntropyFlag.
pub fn detectHighEntropy(
    allocator: Allocator,
    input: []const u8,
    config: EntropyConfig,
) ![]EntropyFlag {
    var flags = std.ArrayList(EntropyFlag).init(allocator);
    errdefer flags.deinit();

    var pos: usize = 0;
    while (pos < input.len) {
        // Skip whitespace and non-printable
        if (input[pos] <= ' ' or input[pos] > '~') {
            pos += 1;
            continue;
        }

        // Try to identify a contiguous token
        const token_start = pos;
        const encoding = identifyEncoding(input, pos);
        const char_check: *const fn (u8) bool = switch (encoding) {
            .base64 => isBase64Char,
            .hex => isHexChar,
            .raw => isTokenChar,
        };

        while (pos < input.len and char_check(input[pos])) {
            pos += 1;
        }

        const token_len = pos - token_start;
        if (token_len < config.min_length or token_len > config.max_length) continue;

        const token = input[token_start..pos];
        const entropy = shannonEntropy(token);

        const threshold: f64 = switch (encoding) {
            .base64 => config.base64_threshold,
            .hex => config.hex_threshold,
            .raw => config.raw_threshold,
        };

        if (entropy >= threshold) {
            try flags.append(.{
                .start = token_start,
                .end = pos,
                .entropy = entropy,
                .encoding = encoding,
            });
        }
    }

    return flags.toOwnedSlice();
}

// ── Helpers ────────────────────────────────────────────────────────────

fn identifyEncoding(input: []const u8, pos: usize) Encoding {
    // Check if it looks like hex (all hex chars, even length common)
    var hex_count: usize = 0;
    var total: usize = 0;
    var p = pos;
    while (p < input.len and isTokenChar(input[p])) : (p += 1) {
        total += 1;
        if (isHexChar(input[p])) hex_count += 1;
    }

    if (total >= 16) {
        // If all chars are hex, it's likely hex
        if (hex_count == total) return .hex;

        // Check for base64 characteristics (A-Z, a-z, 0-9, +, /, =)
        var b64_count: usize = 0;
        var q = pos;
        while (q < input.len and isTokenChar(input[q])) : (q += 1) {
            if (isBase64Char(input[q])) b64_count += 1;
        }
        if (b64_count == total) return .base64;
    }

    return .raw;
}

fn isBase64Char(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=' or c == '_' or c == '-';
}

fn isHexChar(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn isTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '+' or c == '/' or c == '=' or c == '.';
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "shannonEntropy of uniform data" {
    // All same character → 0 entropy
    const data = "aaaaaaaaaa";
    const e = shannonEntropy(data);
    try testing.expect(e < 0.01);
}

test "shannonEntropy of binary string" {
    // Alternating a,b → 1 bit
    const data = "abababababababab";
    const e = shannonEntropy(data);
    try testing.expect(e > 0.99 and e < 1.01);
}

test "shannonEntropy of high entropy string" {
    // Random-looking string should have high entropy
    const data = "aB3$kL9mNpQrStUvWxYz1234567890!@";
    const e = shannonEntropy(data);
    try testing.expect(e > 3.5);
}

test "detectHighEntropy finds base64 secret" {
    const input = "token=dGhpcyBpcyBhIHZlcnkgbG9uZyBzZWNyZXQga2V5IHRoYXQgc2hvdWxkIGJlIGRldGVjdGVk rest";
    const flags = try detectHighEntropy(testing.allocator, input, .{});
    defer testing.allocator.free(flags);

    // Should flag the base64 string
    try testing.expect(flags.len >= 1);
}

test "detectHighEntropy ignores low entropy" {
    const input = "this is a normal sentence with common words only";
    const flags = try detectHighEntropy(testing.allocator, input, .{});
    defer testing.allocator.free(flags);

    try testing.expectEqual(@as(usize, 0), flags.len);
}

test "detectHighEntropy ignores short tokens" {
    const input = "ab12 cd34 ef56";
    const flags = try detectHighEntropy(testing.allocator, input, .{ .min_length = 16 });
    defer testing.allocator.free(flags);

    try testing.expectEqual(@as(usize, 0), flags.len);
}
