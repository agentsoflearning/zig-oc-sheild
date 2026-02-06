// OpenClaw Shield — L7: Taint Policy Engine
//
// Manages session taint state machine: CLEAN → TAINTED → QUARANTINED.
// Provides escalation and de-escalation logic based on configurable thresholds.
//
// Taint triggers:
//   - Secret findings
//   - High-confidence entropy flags
//   - Repeated blocks (any L7 deny)
//   - Untrusted content marker (from TS layer)
//
// Escalation: TAINTED → QUARANTINED when block_count >= quarantine_threshold
//             or critical severity finding
//
// De-escalation: TAINTED → CLEAN after cool_down_seconds with no triggers

const std = @import("std");
const Allocator = std.mem.Allocator;
const reason_codes = @import("reason_codes.zig");
const TaintState = reason_codes.TaintState;

/// Taint policy configuration.
pub const TaintConfig = struct {
    auto_escalate: bool = true,
    quarantine_threshold: u32 = 5,
    cool_down_seconds: u64 = 300,
};

/// Reason a taint escalation occurred.
pub const TaintTrigger = enum {
    secret_detected,
    entropy_flag,
    block_event,
    untrusted_content,
    critical_finding,
    operator_quarantine,
    operator_unquarantine,
};

/// Per-session taint tracking.
pub const SessionTaint = struct {
    state: TaintState,
    block_count: u32,
    last_trigger_time: i64,
    last_trigger: ?TaintTrigger,

    pub fn init() SessionTaint {
        return .{
            .state = .clean,
            .block_count = 0,
            .last_trigger_time = 0,
            .last_trigger = null,
        };
    }
};

/// Result of a taint evaluation.
pub const TaintResult = struct {
    new_state: TaintState,
    old_state: TaintState,
    changed: bool,
    reason: []const u8,
};

/// Taint policy manager — tracks taint state for multiple sessions.
pub const TaintManager = struct {
    sessions: std.StringHashMap(SessionTaint),
    config: TaintConfig,
    allocator: Allocator,

    pub fn init(allocator: Allocator, config: TaintConfig) TaintManager {
        return .{
            .sessions = std.StringHashMap(SessionTaint).init(allocator),
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TaintManager) void {
        self.sessions.deinit();
    }

    /// Record a trigger event and evaluate taint state transition.
    pub fn recordTrigger(
        self: *TaintManager,
        session_id: []const u8,
        trigger: TaintTrigger,
        now: i64,
    ) !TaintResult {
        const session = try self.getOrCreate(session_id);
        const old_state = session.state;

        // Operator overrides take immediate effect
        if (trigger == .operator_quarantine) {
            session.state = .quarantined;
            session.last_trigger = trigger;
            session.last_trigger_time = now;
            return TaintResult{
                .new_state = .quarantined,
                .old_state = old_state,
                .changed = old_state != .quarantined,
                .reason = "Operator forced quarantine",
            };
        }

        if (trigger == .operator_unquarantine) {
            session.state = .clean;
            session.block_count = 0;
            session.last_trigger = trigger;
            session.last_trigger_time = now;
            return TaintResult{
                .new_state = .clean,
                .old_state = old_state,
                .changed = old_state != .clean,
                .reason = "Operator unquarantined session",
            };
        }

        // If already quarantined, stay quarantined (only operator can unquarantine)
        if (session.state == .quarantined) {
            return TaintResult{
                .new_state = .quarantined,
                .old_state = .quarantined,
                .changed = false,
                .reason = "Session is quarantined",
            };
        }

        if (!self.config.auto_escalate) {
            return TaintResult{
                .new_state = session.state,
                .old_state = old_state,
                .changed = false,
                .reason = "Auto-escalation disabled",
            };
        }

        // Record the trigger
        session.last_trigger = trigger;
        session.last_trigger_time = now;

        // Track block events
        if (trigger == .block_event or trigger == .secret_detected or
            trigger == .entropy_flag or trigger == .untrusted_content)
        {
            session.block_count += 1;
        }

        // Critical findings → immediate quarantine
        if (trigger == .critical_finding) {
            session.state = .quarantined;
            return TaintResult{
                .new_state = .quarantined,
                .old_state = old_state,
                .changed = old_state != .quarantined,
                .reason = "Critical finding triggered quarantine",
            };
        }

        // CLEAN → TAINTED on any trigger
        if (session.state == .clean) {
            session.state = .tainted;
            // Check if we should immediately quarantine
            if (session.block_count >= self.config.quarantine_threshold) {
                session.state = .quarantined;
                return TaintResult{
                    .new_state = .quarantined,
                    .old_state = old_state,
                    .changed = true,
                    .reason = "Block threshold exceeded — quarantined",
                };
            }
            return TaintResult{
                .new_state = .tainted,
                .old_state = old_state,
                .changed = true,
                .reason = "Taint trigger detected",
            };
        }

        // TAINTED → QUARANTINED on threshold
        if (session.state == .tainted and session.block_count >= self.config.quarantine_threshold) {
            session.state = .quarantined;
            return TaintResult{
                .new_state = .quarantined,
                .old_state = old_state,
                .changed = true,
                .reason = "Block threshold exceeded — quarantined",
            };
        }

        // Still TAINTED
        return TaintResult{
            .new_state = .tainted,
            .old_state = old_state,
            .changed = false,
            .reason = "Taint trigger recorded",
        };
    }

    /// Check for de-escalation based on elapsed time since last trigger.
    /// Call periodically (e.g., on each request) with the current timestamp.
    pub fn checkDeescalation(
        self: *TaintManager,
        session_id: []const u8,
        now: i64,
    ) TaintResult {
        const session_ptr = self.sessions.getPtr(session_id) orelse {
            return TaintResult{
                .new_state = .clean,
                .old_state = .clean,
                .changed = false,
                .reason = "No session state",
            };
        };

        const old_state = session_ptr.state;

        // Only de-escalate from TAINTED (not QUARANTINED)
        if (session_ptr.state != .tainted) {
            return TaintResult{
                .new_state = session_ptr.state,
                .old_state = old_state,
                .changed = false,
                .reason = if (session_ptr.state == .quarantined)
                    "Quarantined — operator must unquarantine"
                else
                    "Already clean",
            };
        }

        // Check cool-down window
        const elapsed: u64 = @intCast(@max(0, now - session_ptr.last_trigger_time));
        if (elapsed >= self.config.cool_down_seconds) {
            session_ptr.state = .clean;
            session_ptr.block_count = 0;
            return TaintResult{
                .new_state = .clean,
                .old_state = old_state,
                .changed = true,
                .reason = "Cool-down period elapsed — de-escalated to clean",
            };
        }

        return TaintResult{
            .new_state = .tainted,
            .old_state = .tainted,
            .changed = false,
            .reason = "Cool-down period not yet elapsed",
        };
    }

    /// Get the current taint state for a session.
    pub fn getState(self: *TaintManager, session_id: []const u8) TaintState {
        if (self.sessions.get(session_id)) |session| {
            return session.state;
        }
        return .clean;
    }

    /// Get the full session taint info.
    pub fn getSessionInfo(self: *TaintManager, session_id: []const u8) ?SessionTaint {
        return self.sessions.get(session_id);
    }

    /// Force a session to a specific state (for operator commands).
    pub fn setSessionState(
        self: *TaintManager,
        session_id: []const u8,
        state: TaintState,
        now: i64,
    ) !void {
        const session = try self.getOrCreate(session_id);
        session.state = state;
        session.last_trigger_time = now;
        if (state == .clean) {
            session.block_count = 0;
        }
    }

    /// Clear a session entirely.
    pub fn clearSession(self: *TaintManager, session_id: []const u8) void {
        _ = self.sessions.fetchRemove(session_id);
    }

    fn getOrCreate(self: *TaintManager, session_id: []const u8) !*SessionTaint {
        const result = try self.sessions.getOrPut(session_id);
        if (!result.found_existing) {
            result.value_ptr.* = SessionTaint.init();
        }
        return result.value_ptr;
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "TaintManager — initial state is clean" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    try testing.expectEqual(TaintState.clean, mgr.getState("sess-1"));
}

test "TaintManager — CLEAN → TAINTED on block event" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    const result = try mgr.recordTrigger("sess-1", .block_event, 1000);
    try testing.expect(result.changed);
    try testing.expectEqual(TaintState.clean, result.old_state);
    try testing.expectEqual(TaintState.tainted, result.new_state);
    try testing.expectEqual(TaintState.tainted, mgr.getState("sess-1"));
}

test "TaintManager — CLEAN → TAINTED on secret detected" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    const result = try mgr.recordTrigger("sess-1", .secret_detected, 1000);
    try testing.expect(result.changed);
    try testing.expectEqual(TaintState.tainted, result.new_state);
}

test "TaintManager — TAINTED → QUARANTINED at threshold" {
    var mgr = TaintManager.init(testing.allocator, .{ .quarantine_threshold = 3 });
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 100); // count=1, CLEAN→TAINTED
    _ = try mgr.recordTrigger("s1", .block_event, 101); // count=2, stay TAINTED
    const r3 = try mgr.recordTrigger("s1", .block_event, 102); // count=3 >= threshold
    try testing.expect(r3.changed);
    try testing.expectEqual(TaintState.quarantined, r3.new_state);
}

test "TaintManager — critical finding → immediate quarantine" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    const result = try mgr.recordTrigger("s1", .critical_finding, 100);
    try testing.expect(result.changed);
    try testing.expectEqual(TaintState.quarantined, result.new_state);
}

test "TaintManager — quarantined stays quarantined on more triggers" {
    var mgr = TaintManager.init(testing.allocator, .{ .quarantine_threshold = 1 });
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 100); // → QUARANTINED
    const r2 = try mgr.recordTrigger("s1", .block_event, 101);
    try testing.expect(!r2.changed);
    try testing.expectEqual(TaintState.quarantined, r2.new_state);
}

test "TaintManager — de-escalation after cool-down" {
    var mgr = TaintManager.init(testing.allocator, .{ .cool_down_seconds = 60 });
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 1000); // → TAINTED

    // Not enough time elapsed
    const r1 = mgr.checkDeescalation("s1", 1050);
    try testing.expect(!r1.changed);
    try testing.expectEqual(TaintState.tainted, r1.new_state);

    // After cool-down
    const r2 = mgr.checkDeescalation("s1", 1060);
    try testing.expect(r2.changed);
    try testing.expectEqual(TaintState.clean, r2.new_state);
}

test "TaintManager — quarantined does not de-escalate" {
    var mgr = TaintManager.init(testing.allocator, .{ .quarantine_threshold = 1, .cool_down_seconds = 10 });
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 100); // → QUARANTINED
    const r = mgr.checkDeescalation("s1", 200);
    try testing.expect(!r.changed);
    try testing.expectEqual(TaintState.quarantined, r.new_state);
}

test "TaintManager — operator quarantine" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    const result = try mgr.recordTrigger("s1", .operator_quarantine, 100);
    try testing.expect(result.changed);
    try testing.expectEqual(TaintState.quarantined, result.new_state);
}

test "TaintManager — operator unquarantine" {
    var mgr = TaintManager.init(testing.allocator, .{ .quarantine_threshold = 1 });
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 100); // → QUARANTINED
    const r = try mgr.recordTrigger("s1", .operator_unquarantine, 200);
    try testing.expect(r.changed);
    try testing.expectEqual(TaintState.clean, r.new_state);
    try testing.expectEqual(@as(u32, 0), mgr.getSessionInfo("s1").?.block_count);
}

test "TaintManager — auto_escalate disabled" {
    var mgr = TaintManager.init(testing.allocator, .{ .auto_escalate = false });
    defer mgr.deinit();

    const result = try mgr.recordTrigger("s1", .block_event, 100);
    try testing.expect(!result.changed);
    try testing.expectEqual(TaintState.clean, result.new_state);
}

test "TaintManager — sessions are independent" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 100);
    try testing.expectEqual(TaintState.tainted, mgr.getState("s1"));
    try testing.expectEqual(TaintState.clean, mgr.getState("s2"));
}

test "TaintManager — clearSession" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    _ = try mgr.recordTrigger("s1", .block_event, 100);
    mgr.clearSession("s1");
    try testing.expectEqual(TaintState.clean, mgr.getState("s1"));
}

test "TaintManager — setSessionState" {
    var mgr = TaintManager.init(testing.allocator, .{});
    defer mgr.deinit();

    try mgr.setSessionState("s1", .quarantined, 100);
    try testing.expectEqual(TaintState.quarantined, mgr.getState("s1"));

    try mgr.setSessionState("s1", .clean, 200);
    try testing.expectEqual(TaintState.clean, mgr.getState("s1"));
    try testing.expectEqual(@as(u32, 0), mgr.getSessionInfo("s1").?.block_count);
}
