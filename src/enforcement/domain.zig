// OpenClaw Shield — L7: Domain Allowlist Matching
//
// Matches hostnames against an allowlist with wildcard support.
// Used by net.zig to enforce network boundary policies.
//
// Matching rules:
//   - Exact match: "api.openai.com" matches "api.openai.com"
//   - Wildcard: "*.slack.com" matches "hooks.slack.com" and "api.slack.com"
//   - Wildcard "*" matches everything (used in permissive profiles)
//   - Normalization: lowercase, trim trailing dot

const std = @import("std");

/// Check if a host matches any entry in the allowlist.
/// Returns true if the host is allowed.
pub fn isAllowed(host: []const u8, allowlist: []const []const u8) bool {
    if (allowlist.len == 0) return false;

    for (allowlist) |entry| {
        if (matchEntry(host, entry)) return true;
    }
    return false;
}

/// Match a single host against a single allowlist entry.
/// Supports exact match and wildcard patterns.
fn matchEntry(host: []const u8, entry: []const u8) bool {
    // Universal wildcard
    if (entry.len == 1 and entry[0] == '*') return true;

    // Wildcard prefix: "*.example.com"
    if (entry.len > 2 and entry[0] == '*' and entry[1] == '.') {
        const suffix = entry[2..]; // "example.com"
        return hasSuffixLower(host, suffix);
    }

    // Exact match (case-insensitive, trimming trailing dots)
    return eqlNormalized(host, entry);
}

/// Check if host ends with ".suffix" or equals suffix exactly (case-insensitive).
fn hasSuffixLower(host: []const u8, suffix: []const u8) bool {
    const h = trimTrailingDot(host);
    const s = trimTrailingDot(suffix);

    // Exact match of suffix itself (e.g., host="slack.com", suffix="slack.com")
    if (eqlLower(h, s)) return true;

    // Subdomain match: host must end with ".suffix"
    if (h.len <= s.len) return false;
    const host_tail = h[h.len - s.len ..];
    if (!eqlLower(host_tail, s)) return false;
    // Ensure the character before the suffix is a dot
    return h[h.len - s.len - 1] == '.';
}

/// Compare two strings case-insensitively after trimming trailing dots.
fn eqlNormalized(a: []const u8, b: []const u8) bool {
    return eqlLower(trimTrailingDot(a), trimTrailingDot(b));
}

fn trimTrailingDot(s: []const u8) []const u8 {
    if (s.len > 0 and s[s.len - 1] == '.') return s[0 .. s.len - 1];
    return s;
}

fn eqlLower(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != std.ascii.toLower(bc)) return false;
    }
    return true;
}

/// Normalize a hostname: lowercase, trim trailing dot.
/// Allocates a new string. Caller must free.
pub fn normalize(allocator: std.mem.Allocator, host: []const u8) ![]u8 {
    const trimmed = trimTrailingDot(host);
    const result = try allocator.alloc(u8, trimmed.len);
    for (trimmed, 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return result;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "isAllowed — exact match" {
    const list = [_][]const u8{ "api.openai.com", "api.anthropic.com" };
    try testing.expect(isAllowed("api.openai.com", &list));
    try testing.expect(isAllowed("api.anthropic.com", &list));
    try testing.expect(!isAllowed("evil.com", &list));
}

test "isAllowed — case insensitive" {
    const list = [_][]const u8{"API.OpenAI.COM"};
    try testing.expect(isAllowed("api.openai.com", &list));
    try testing.expect(isAllowed("Api.Openai.Com", &list));
}

test "isAllowed — wildcard" {
    const list = [_][]const u8{"*.slack.com"};
    try testing.expect(isAllowed("hooks.slack.com", &list));
    try testing.expect(isAllowed("api.slack.com", &list));
    try testing.expect(isAllowed("slack.com", &list)); // suffix also matches
    try testing.expect(!isAllowed("notslack.com", &list));
    try testing.expect(!isAllowed("evil.com", &list));
}

test "isAllowed — universal wildcard" {
    const list = [_][]const u8{"*"};
    try testing.expect(isAllowed("anything.example.com", &list));
    try testing.expect(isAllowed("localhost", &list));
}

test "isAllowed — empty allowlist blocks all" {
    const list = [_][]const u8{};
    try testing.expect(!isAllowed("api.openai.com", &list));
}

test "isAllowed — trailing dot normalization" {
    const list = [_][]const u8{"api.openai.com."};
    try testing.expect(isAllowed("api.openai.com", &list));
    try testing.expect(isAllowed("api.openai.com.", &list));
}

test "isAllowed — wildcard trailing dot" {
    const list = [_][]const u8{"*.slack.com."};
    try testing.expect(isAllowed("hooks.slack.com", &list));
    try testing.expect(isAllowed("hooks.slack.com.", &list));
}

test "isAllowed — mixed allowlist" {
    const list = [_][]const u8{ "api.openai.com", "*.anthropic.com", "exact.example.org" };
    try testing.expect(isAllowed("api.openai.com", &list));
    try testing.expect(isAllowed("docs.anthropic.com", &list));
    try testing.expect(isAllowed("exact.example.org", &list));
    try testing.expect(!isAllowed("evil.com", &list));
}

test "isAllowed — wildcard does not match partial" {
    const list = [_][]const u8{"*.slack.com"};
    // "evilslack.com" should NOT match — needs a dot separator
    try testing.expect(!isAllowed("evilslack.com", &list));
}

test "normalize — lowercases and trims" {
    const result = try normalize(testing.allocator, "API.OpenAI.COM.");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("api.openai.com", result);
}
