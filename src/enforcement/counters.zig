// OpenClaw Shield — L7: Rate Counters
//
// Lightweight sliding window counters for egress bytes and exec operations.
// Used by net.zig and proc.zig to enforce rate limits per session.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A timestamped event for the sliding window.
const Event = struct {
    timestamp: i64,
    value: u64, // bytes for egress, 1 for exec count
};

/// Sliding window counter for a single metric.
pub const WindowCounter = struct {
    events: std.ArrayList(Event),
    window_seconds: u32,

    pub fn init(allocator: Allocator, window_seconds: u32) WindowCounter {
        return .{
            .events = std.ArrayList(Event).init(allocator),
            .window_seconds = window_seconds,
        };
    }

    pub fn deinit(self: *WindowCounter) void {
        self.events.deinit();
    }

    /// Add a value and check if total in window exceeds the limit.
    /// Returns the current total after adding (including this event).
    pub fn addAndCheck(self: *WindowCounter, value: u64, now: i64) !u64 {
        self.prune(now);
        try self.events.append(.{ .timestamp = now, .value = value });
        return self.total();
    }

    /// Get the current total in the window without adding.
    pub fn currentTotal(self: *WindowCounter, now: i64) u64 {
        self.prune(now);
        return self.total();
    }

    /// Reset all events.
    pub fn reset(self: *WindowCounter) void {
        self.events.clearRetainingCapacity();
    }

    fn prune(self: *WindowCounter, now: i64) void {
        const cutoff = now - @as(i64, self.window_seconds);
        var i: usize = 0;
        while (i < self.events.items.len) {
            if (self.events.items[i].timestamp < cutoff) {
                _ = self.events.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn total(self: *const WindowCounter) u64 {
        var sum: u64 = 0;
        for (self.events.items) |e| {
            sum += e.value;
        }
        return sum;
    }
};

/// Per-session counters for L7 enforcement.
pub const SessionCounters = struct {
    egress_bytes: WindowCounter,
    exec_count: WindowCounter,

    pub fn init(allocator: Allocator, window_seconds: u32) SessionCounters {
        return .{
            .egress_bytes = WindowCounter.init(allocator, window_seconds),
            .exec_count = WindowCounter.init(allocator, window_seconds),
        };
    }

    pub fn deinit(self: *SessionCounters) void {
        self.egress_bytes.deinit();
        self.exec_count.deinit();
    }

    pub fn reset(self: *SessionCounters) void {
        self.egress_bytes.reset();
        self.exec_count.reset();
    }
};

/// Counter manager that tracks multiple sessions.
pub const CounterManager = struct {
    sessions: std.StringHashMap(SessionCounters),
    allocator: Allocator,
    window_seconds: u32,

    pub fn init(allocator: Allocator, window_seconds: u32) CounterManager {
        return .{
            .sessions = std.StringHashMap(SessionCounters).init(allocator),
            .allocator = allocator,
            .window_seconds = window_seconds,
        };
    }

    pub fn deinit(self: *CounterManager) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.sessions.deinit();
    }

    /// Add egress bytes for a session. Returns total bytes in window.
    pub fn checkAndAddBytes(self: *CounterManager, session_id: []const u8, bytes: u64, now: i64) !u64 {
        const counters = try self.getOrCreate(session_id);
        return counters.egress_bytes.addAndCheck(bytes, now);
    }

    /// Increment exec count for a session. Returns total exec count in window.
    pub fn checkAndIncExec(self: *CounterManager, session_id: []const u8, now: i64) !u64 {
        const counters = try self.getOrCreate(session_id);
        return counters.exec_count.addAndCheck(1, now);
    }

    /// Get current byte total without adding.
    pub fn currentBytes(self: *CounterManager, session_id: []const u8, now: i64) u64 {
        if (self.sessions.getPtr(session_id)) |counters| {
            return counters.egress_bytes.currentTotal(now);
        }
        return 0;
    }

    /// Get current exec count without adding.
    pub fn currentExecCount(self: *CounterManager, session_id: []const u8, now: i64) u64 {
        if (self.sessions.getPtr(session_id)) |counters| {
            return counters.exec_count.currentTotal(now);
        }
        return 0;
    }

    /// Clear counters for a specific session.
    pub fn clearSession(self: *CounterManager, session_id: []const u8) void {
        if (self.sessions.fetchRemove(session_id)) |entry| {
            var counters = entry.value;
            counters.deinit();
        }
    }

    fn getOrCreate(self: *CounterManager, session_id: []const u8) !*SessionCounters {
        const result = try self.sessions.getOrPut(session_id);
        if (!result.found_existing) {
            result.value_ptr.* = SessionCounters.init(self.allocator, self.window_seconds);
        }
        return result.value_ptr;
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "WindowCounter — basic add and check" {
    var counter = WindowCounter.init(testing.allocator, 60);
    defer counter.deinit();

    const total = try counter.addAndCheck(100, 1000);
    try testing.expectEqual(@as(u64, 100), total);

    const total2 = try counter.addAndCheck(200, 1001);
    try testing.expectEqual(@as(u64, 300), total2);
}

test "WindowCounter — prunes expired events" {
    var counter = WindowCounter.init(testing.allocator, 60);
    defer counter.deinit();

    _ = try counter.addAndCheck(100, 1000);
    _ = try counter.addAndCheck(200, 1030);

    // After window expires, first event is pruned
    const total = try counter.addAndCheck(50, 1070);
    // Event at 1000 is expired (1070 - 60 = 1010 > 1000)
    // Event at 1030 still valid, plus new 50
    try testing.expectEqual(@as(u64, 250), total);
}

test "WindowCounter — reset clears all" {
    var counter = WindowCounter.init(testing.allocator, 60);
    defer counter.deinit();

    _ = try counter.addAndCheck(100, 1000);
    _ = try counter.addAndCheck(200, 1001);
    counter.reset();

    const total = counter.currentTotal(1002);
    try testing.expectEqual(@as(u64, 0), total);
}

test "CounterManager — egress bytes tracking" {
    var mgr = CounterManager.init(testing.allocator, 60);
    defer mgr.deinit();

    const t1 = try mgr.checkAndAddBytes("sess-1", 1000, 100);
    try testing.expectEqual(@as(u64, 1000), t1);

    const t2 = try mgr.checkAndAddBytes("sess-1", 2000, 101);
    try testing.expectEqual(@as(u64, 3000), t2);
}

test "CounterManager — exec count tracking" {
    var mgr = CounterManager.init(testing.allocator, 60);
    defer mgr.deinit();

    const c1 = try mgr.checkAndIncExec("sess-1", 100);
    try testing.expectEqual(@as(u64, 1), c1);

    const c2 = try mgr.checkAndIncExec("sess-1", 101);
    try testing.expectEqual(@as(u64, 2), c2);

    const c3 = try mgr.checkAndIncExec("sess-1", 102);
    try testing.expectEqual(@as(u64, 3), c3);
}

test "CounterManager — sessions are independent" {
    var mgr = CounterManager.init(testing.allocator, 60);
    defer mgr.deinit();

    _ = try mgr.checkAndAddBytes("sess-1", 5000, 100);
    _ = try mgr.checkAndAddBytes("sess-1", 5000, 101);

    const b2 = try mgr.checkAndAddBytes("sess-2", 100, 102);
    try testing.expectEqual(@as(u64, 100), b2);
}

test "CounterManager — clearSession" {
    var mgr = CounterManager.init(testing.allocator, 60);
    defer mgr.deinit();

    _ = try mgr.checkAndAddBytes("sess-1", 5000, 100);
    mgr.clearSession("sess-1");

    const current = mgr.currentBytes("sess-1", 101);
    try testing.expectEqual(@as(u64, 0), current);
}

test "CounterManager — window expiry" {
    var mgr = CounterManager.init(testing.allocator, 60);
    defer mgr.deinit();

    _ = try mgr.checkAndIncExec("s1", 100);
    _ = try mgr.checkAndIncExec("s1", 120);
    _ = try mgr.checkAndIncExec("s1", 140);

    // At t=170, event at t=100 is expired (170-60=110 > 100)
    const c = try mgr.checkAndIncExec("s1", 170);
    // Events at 120, 140, plus new at 170 = 3
    try testing.expectEqual(@as(u64, 3), c);
}
