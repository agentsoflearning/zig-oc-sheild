// OpenClaw Shield — L6: Rate Limiter
//
// Sliding window rate limiter for sensitive operations.
// Prevents rapid-fire exec/read calls that may indicate automated attacks.
// New capability not present in the original openclaw-shield.

const std = @import("std");
const Allocator = std.mem.Allocator;
const config_mod = @import("config.zig");
const RateLimitSettings = config_mod.RateLimitSettings;

// ── Types ──────────────────────────────────────────────────────────────

pub const OperationType = enum {
    exec,
    sensitive_read,
};

pub const RateLimitDecision = enum {
    allow,
    throttle, // Warn but allow
    block, // Hard block
};

pub const RateLimitResult = struct {
    decision: RateLimitDecision,
    reason: []const u8,
    count: u32,
    limit: u32,
    window_seconds: u32,
};

/// Sliding window rate limiter with per-session tracking.
pub const RateLimiter = struct {
    settings: RateLimitSettings,
    /// Keyed by session ID, storing ring buffers of timestamps per operation type.
    sessions: std.StringHashMap(SessionState),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, settings: RateLimitSettings) Self {
        return Self{
            .settings = settings,
            .sessions = std.StringHashMap(SessionState).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.sessions.deinit();
    }

    /// Check if an operation is within rate limits.
    pub fn check(self: *Self, session_key: []const u8, op: OperationType) !RateLimitResult {
        const now = currentTimestamp();
        const limit = self.getLimit(op);
        const window = self.settings.window_seconds;

        // Get or create session state
        const state = try self.getOrCreateSession(session_key);
        const timestamps = switch (op) {
            .exec => &state.exec_timestamps,
            .sensitive_read => &state.read_timestamps,
        };

        // Prune expired entries
        pruneExpired(timestamps, now, window);

        // Count events in window
        const count: u32 = @intCast(timestamps.items.len);

        // Record this event
        try timestamps.append(now);

        // Evaluate
        if (count >= limit) {
            return RateLimitResult{
                .decision = .block,
                .reason = "Rate limit exceeded — too many operations in time window",
                .count = count + 1,
                .limit = limit,
                .window_seconds = window,
            };
        } else if (count >= limit * 80 / 100) {
            // 80% threshold — warn
            return RateLimitResult{
                .decision = .throttle,
                .reason = "Approaching rate limit — slow down",
                .count = count + 1,
                .limit = limit,
                .window_seconds = window,
            };
        } else {
            return RateLimitResult{
                .decision = .allow,
                .reason = "Within rate limits",
                .count = count + 1,
                .limit = limit,
                .window_seconds = window,
            };
        }
    }

    /// Clear all state for a session (call on session end).
    pub fn clearSession(self: *Self, session_key: []const u8) void {
        if (self.sessions.fetchRemove(session_key)) |entry| {
            var state = entry.value;
            state.deinit(self.allocator);
        }
    }

    /// Reset all sessions.
    pub fn reset(self: *Self) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.sessions.clearRetainingCapacity();
    }

    fn getLimit(self: Self, op: OperationType) u32 {
        return switch (op) {
            .exec => self.settings.exec_per_minute,
            .sensitive_read => self.settings.sensitive_read_per_minute,
        };
    }

    fn getOrCreateSession(self: *Self, session_key: []const u8) !*SessionState {
        const result = try self.sessions.getOrPut(session_key);
        if (!result.found_existing) {
            result.value_ptr.* = SessionState.init(self.allocator);
        }
        return result.value_ptr;
    }
};

const SessionState = struct {
    exec_timestamps: std.ArrayList(i64),
    read_timestamps: std.ArrayList(i64),

    fn init(allocator: Allocator) SessionState {
        return .{
            .exec_timestamps = std.ArrayList(i64).init(allocator),
            .read_timestamps = std.ArrayList(i64).init(allocator),
        };
    }

    fn deinit(self: *SessionState, _: Allocator) void {
        self.exec_timestamps.deinit();
        self.read_timestamps.deinit();
    }
};

fn pruneExpired(timestamps: *std.ArrayList(i64), now: i64, window_seconds: u32) void {
    const cutoff = now - @as(i64, window_seconds);
    // Remove all timestamps before cutoff
    var i: usize = 0;
    while (i < timestamps.items.len) {
        if (timestamps.items[i] < cutoff) {
            _ = timestamps.orderedRemove(i);
        } else {
            i += 1;
        }
    }
}

fn currentTimestamp() i64 {
    return std.time.timestamp();
}

// ── Standalone check for simple usage ──────────────────────────────────

/// Quick check without persistent state. Uses a provided count.
pub fn quickCheck(count: u32, limit: u32, window_seconds: u32) RateLimitResult {
    if (count >= limit) {
        return RateLimitResult{
            .decision = .block,
            .reason = "Rate limit exceeded",
            .count = count,
            .limit = limit,
            .window_seconds = window_seconds,
        };
    } else if (count >= limit * 80 / 100) {
        return RateLimitResult{
            .decision = .throttle,
            .reason = "Approaching rate limit",
            .count = count,
            .limit = limit,
            .window_seconds = window_seconds,
        };
    } else {
        return RateLimitResult{
            .decision = .allow,
            .reason = "Within rate limits",
            .count = count,
            .limit = limit,
            .window_seconds = window_seconds,
        };
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "quickCheck — under limit" {
    const result = quickCheck(3, 10, 60);
    try testing.expectEqual(RateLimitDecision.allow, result.decision);
}

test "quickCheck — at 80% threshold" {
    const result = quickCheck(8, 10, 60);
    try testing.expectEqual(RateLimitDecision.throttle, result.decision);
}

test "quickCheck — over limit" {
    const result = quickCheck(10, 10, 60);
    try testing.expectEqual(RateLimitDecision.block, result.decision);
}

test "RateLimiter — basic flow" {
    var limiter = RateLimiter.init(testing.allocator, .{
        .exec_per_minute = 3,
        .sensitive_read_per_minute = 2,
        .window_seconds = 60,
    });
    defer limiter.deinit();

    // First few calls should be allowed
    const r1 = try limiter.check("session-1", .exec);
    try testing.expectEqual(RateLimitDecision.allow, r1.decision);

    const r2 = try limiter.check("session-1", .exec);
    try testing.expectEqual(RateLimitDecision.allow, r2.decision);

    // Third call should trigger throttle (80% of 3 ≈ 2.4 → 2)
    // count=2 at check time, 80% of 3 = 2, so count >= 2 → throttle
    const r3 = try limiter.check("session-1", .exec);
    try testing.expect(r3.decision == .throttle or r3.decision == .block);
}

test "RateLimiter — different sessions are independent" {
    var limiter = RateLimiter.init(testing.allocator, .{
        .exec_per_minute = 2,
        .sensitive_read_per_minute = 2,
        .window_seconds = 60,
    });
    defer limiter.deinit();

    _ = try limiter.check("session-a", .exec);
    _ = try limiter.check("session-a", .exec);

    // Session B should be independent
    const rb = try limiter.check("session-b", .exec);
    try testing.expectEqual(RateLimitDecision.allow, rb.decision);
}

test "RateLimiter — different operation types are independent" {
    var limiter = RateLimiter.init(testing.allocator, .{
        .exec_per_minute = 2,
        .sensitive_read_per_minute = 2,
        .window_seconds = 60,
    });
    defer limiter.deinit();

    _ = try limiter.check("s1", .exec);
    _ = try limiter.check("s1", .exec);

    // Read should be independent from exec
    const r = try limiter.check("s1", .sensitive_read);
    try testing.expectEqual(RateLimitDecision.allow, r.decision);
}

test "RateLimiter — clearSession" {
    var limiter = RateLimiter.init(testing.allocator, .{
        .exec_per_minute = 2,
        .sensitive_read_per_minute = 2,
        .window_seconds = 60,
    });
    defer limiter.deinit();

    _ = try limiter.check("s1", .exec);
    _ = try limiter.check("s1", .exec);
    _ = try limiter.check("s1", .exec);

    // Clear session
    limiter.clearSession("s1");

    // Should be fresh
    const r = try limiter.check("s1", .exec);
    try testing.expectEqual(RateLimitDecision.allow, r.decision);
}
