// OpenClaw Shield — Core Scanner Engine
//
// Scan, redact, and deep-walk JSON for secrets and PII.
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;
const pattern = @import("pattern.zig");
const Pattern = pattern.Pattern;
const Match = pattern.Match;
const RedactOptions = pattern.RedactOptions;
const RedactStrategy = pattern.RedactStrategy;

// ── Scan ───────────────────────────────────────────────────────────────

/// Scan input for all pattern matches. Returns an owned slice of matches.
pub fn scan(allocator: Allocator, input: []const u8, patterns: []const Pattern) ![]Match {
    var matches = std.ArrayList(Match).init(allocator);
    errdefer matches.deinit();

    var pos: usize = 0;
    while (pos < input.len) {
        var best_match: ?Match = null;
        var best_len: usize = 0;

        // Try every pattern at this position, keep the longest match
        for (patterns) |pat| {
            if (pat.matchAt(input, pos)) |match_len| {
                if (best_match == null or match_len > best_len) {
                    best_match = Match{
                        .pattern_name = pat.name,
                        .category = pat.category,
                        .severity = pat.severity,
                        .start = pos,
                        .end = pos + match_len,
                    };
                    best_len = match_len;
                }
            }
        }

        if (best_match) |m| {
            try matches.append(m);
            pos = m.end; // Skip past the match
        } else {
            pos += 1;
        }
    }

    return matches.toOwnedSlice();
}

// ── Redact ─────────────────────────────────────────────────────────────

/// Build a redacted copy of input, replacing matched regions.
/// Matches must be sorted by start position and non-overlapping.
pub fn redact(allocator: Allocator, input: []const u8, matches: []const Match, options: RedactOptions) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var last_end: usize = 0;

    for (matches) |m| {
        // Copy everything between last match and this one
        if (m.start > last_end) {
            try out.appendSlice(input[last_end..m.start]);
        }

        // Write replacement
        switch (options.strategy) {
            .mask => {
                try out.appendSlice("[");
                try out.appendSlice(options.tag);
                try out.appendSlice(":");
                try out.appendSlice(m.pattern_name);
                try out.appendSlice("]");
            },
            .partial => {
                const raw = input[m.start..m.end];
                const show = @min(options.partial_chars, raw.len);
                try out.appendSlice(raw[0..show]);
                try out.appendSlice("...");
                if (raw.len > show) {
                    const tail_start = if (raw.len > show) raw.len - show else 0;
                    try out.appendSlice(raw[tail_start..]);
                }
            },
            .hash => {
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                hasher.update(input[m.start..m.end]);
                var digest: [32]u8 = undefined;
                hasher.final(&digest);
                try out.appendSlice("[SHA256:");
                // Write first 8 hex chars
                for (digest[0..4]) |byte| {
                    const hex = "0123456789abcdef";
                    try out.append(hex[byte >> 4]);
                    try out.append(hex[byte & 0xf]);
                }
                try out.appendSlice("]");
            },
            .drop => {
                // Nothing — the matched content is dropped
            },
        }

        last_end = m.end;
    }

    // Copy trailing content
    if (last_end < input.len) {
        try out.appendSlice(input[last_end..]);
    }

    return out.toOwnedSlice();
}

// ── Scan and Redact ────────────────────────────────────────────────────

pub const ScanRedactResult = struct {
    redacted: []u8,
    matches: []Match,
    allocator: Allocator,

    pub fn deinit(self: *ScanRedactResult) void {
        self.allocator.free(self.redacted);
        self.allocator.free(self.matches);
    }
};

/// Scan and redact in one step.
pub fn scanAndRedact(allocator: Allocator, input: []const u8, patterns: []const Pattern, options: RedactOptions) !ScanRedactResult {
    const matches = try scan(allocator, input, patterns);
    errdefer allocator.free(matches);
    const redacted = try redact(allocator, input, matches, options);
    return ScanRedactResult{
        .redacted = redacted,
        .matches = matches,
        .allocator = allocator,
    };
}

// ── JSON Deep-Walk ─────────────────────────────────────────────────────

pub const WalkResult = struct {
    output: []u8,
    match_count: usize,
    allocator: Allocator,

    pub fn deinit(self: *WalkResult) void {
        self.allocator.free(self.output);
    }
};

/// Parse JSON, scan and redact all string values, re-serialize.
pub fn walkJsonAndRedact(
    allocator: Allocator,
    json_input: []const u8,
    patterns: []const Pattern,
    options: RedactOptions,
) !WalkResult {
    // Parse the JSON
    const parsed = try json.parseFromSlice(json.Value, allocator, json_input, .{});
    defer parsed.deinit();

    // Walk and redact all strings
    var match_count: usize = 0;
    const redacted_value = try walkValue(allocator, parsed.value, patterns, options, &match_count);

    // Re-serialize
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try json.stringify(redacted_value, .{}, out.writer());

    // Clean up the walked value's allocations (strings we allocated)
    freeWalkedValue(allocator, redacted_value, parsed.value);

    return WalkResult{
        .output = try out.toOwnedSlice(),
        .match_count = match_count,
        .allocator = allocator,
    };
}

fn walkValue(
    allocator: Allocator,
    value: json.Value,
    patterns: []const Pattern,
    options: RedactOptions,
    match_count: *usize,
) !json.Value {
    switch (value) {
        .string => |s| {
            const matches = try scan(allocator, s, patterns);
            defer allocator.free(matches);
            if (matches.len == 0) return value;
            match_count.* += matches.len;
            const redacted = try redact(allocator, s, matches, options);
            return json.Value{ .string = redacted };
        },
        .array => |arr| {
            var new_arr = try std.ArrayList(json.Value).initCapacity(allocator, arr.items.len);
            errdefer new_arr.deinit();
            for (arr.items) |item| {
                try new_arr.append(try walkValue(allocator, item, patterns, options, match_count));
            }
            return json.Value{ .array = new_arr };
        },
        .object => |obj| {
            var new_obj = json.ObjectMap.init(allocator);
            errdefer new_obj.deinit();
            var it = obj.iterator();
            while (it.next()) |entry| {
                try new_obj.put(entry.key_ptr.*, try walkValue(allocator, entry.value_ptr.*, patterns, options, match_count));
            }
            return json.Value{ .object = new_obj };
        },
        else => return value,
    }
}

fn freeWalkedValue(allocator: Allocator, walked: json.Value, original: json.Value) void {
    switch (walked) {
        .string => |s| {
            // Only free if it's a different string (i.e., we allocated it)
            switch (original) {
                .string => |orig_s| {
                    if (s.ptr != orig_s.ptr) {
                        allocator.free(s);
                    }
                },
                else => allocator.free(s),
            }
        },
        .array => |arr| {
            switch (original) {
                .array => |orig_arr| {
                    for (arr.items, 0..) |item, i| {
                        if (i < orig_arr.items.len) {
                            freeWalkedValue(allocator, item, orig_arr.items[i]);
                        }
                    }
                },
                else => {},
            }
            var mut_arr = arr;
            mut_arr.deinit();
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                switch (original) {
                    .object => |orig_obj| {
                        if (orig_obj.get(entry.key_ptr.*)) |orig_val| {
                            freeWalkedValue(allocator, entry.value_ptr.*, orig_val);
                        }
                    },
                    else => {},
                }
            }
            var mut_obj = obj;
            mut_obj.deinit();
        },
        else => {},
    }
}

// ── Collect Strings (utility) ──────────────────────────────────────────

/// Collect all string values from parsed JSON into a flat list.
pub fn collectJsonStrings(allocator: Allocator, json_input: []const u8) ![][]const u8 {
    const parsed = try json.parseFromSlice(json.Value, allocator, json_input, .{});
    defer parsed.deinit();

    var strings = std.ArrayList([]const u8).init(allocator);
    errdefer strings.deinit();

    try collectStringsFromValue(&strings, parsed.value);
    return strings.toOwnedSlice();
}

fn collectStringsFromValue(list: *std.ArrayList([]const u8), value: json.Value) !void {
    switch (value) {
        .string => |s| try list.append(s),
        .array => |arr| {
            for (arr.items) |item| {
                try collectStringsFromValue(list, item);
            }
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                try collectStringsFromValue(list, entry.value_ptr.*);
            }
        },
        else => {},
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const secrets = @import("../patterns/secrets.zig");

test "scan finds AWS key" {
    const input = "my key is AKIA1234567890ABCDEF and more text";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    try testing.expectEqual(@as(usize, 1), matches.len);
    try testing.expectEqualStrings("aws_access_key", matches[0].pattern_name);
    try testing.expectEqual(@as(usize, 10), matches[0].start);
    try testing.expectEqual(@as(usize, 30), matches[0].end);
}

test "scan finds multiple patterns" {
    const input = "key1=AKIA1234567890ABCDEF key2=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    try testing.expectEqual(@as(usize, 2), matches.len);
    try testing.expectEqualStrings("aws_access_key", matches[0].pattern_name);
    try testing.expectEqualStrings("npm_token", matches[1].pattern_name);
}

test "scan returns empty for clean input" {
    const input = "this is totally clean text with no secrets";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    try testing.expectEqual(@as(usize, 0), matches.len);
}

test "redact with mask strategy" {
    const input = "key=AKIA1234567890ABCDEF rest";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    const redacted = try redact(testing.allocator, input, matches, .{});
    defer testing.allocator.free(redacted);

    try testing.expectEqualStrings("key=[REDACTED:aws_access_key] rest", redacted);
}

test "redact with partial strategy" {
    const input = "key=AKIA1234567890ABCDEF rest";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    const redacted = try redact(testing.allocator, input, matches, .{ .strategy = .partial, .partial_chars = 4 });
    defer testing.allocator.free(redacted);

    try testing.expectEqualStrings("key=AKIA...CDEF rest", redacted);
}

test "redact with hash strategy" {
    const input = "key=AKIA1234567890ABCDEF rest";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    const redacted = try redact(testing.allocator, input, matches, .{ .strategy = .hash });
    defer testing.allocator.free(redacted);

    // Should be "key=[SHA256:XXXXXXXX] rest"
    try testing.expect(std.mem.startsWith(u8, redacted, "key=[SHA256:"));
    try testing.expect(std.mem.endsWith(u8, redacted, "] rest"));
}

test "redact with drop strategy" {
    const input = "key=AKIA1234567890ABCDEF rest";
    const matches = try scan(testing.allocator, input, &secrets.patterns);
    defer testing.allocator.free(matches);

    const redacted = try redact(testing.allocator, input, matches, .{ .strategy = .drop });
    defer testing.allocator.free(redacted);

    try testing.expectEqualStrings("key= rest", redacted);
}

test "scanAndRedact combined" {
    const input = "secret: AKIA1234567890ABCDEF";
    var result = try scanAndRedact(testing.allocator, input, &secrets.patterns, .{});
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.matches.len);
    try testing.expectEqualStrings("secret: [REDACTED:aws_access_key]", result.redacted);
}

test "walkJsonAndRedact" {
    const json_input =
        \\{"key":"AKIA1234567890ABCDEF","nested":{"value":"clean"},"arr":["npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]}
    ;
    var result = try walkJsonAndRedact(testing.allocator, json_input, &secrets.patterns, .{});
    defer result.deinit();

    try testing.expectEqual(@as(usize, 2), result.match_count);
    // The output should contain redaction tags
    try testing.expect(std.mem.indexOf(u8, result.output, "[REDACTED:aws_access_key]") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "[REDACTED:npm_token]") != null);
    // Clean values should be preserved
    try testing.expect(std.mem.indexOf(u8, result.output, "clean") != null);
}
