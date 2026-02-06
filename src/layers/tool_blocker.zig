// OpenClaw Shield — L3: Tool Blocker
//
// Evaluates tool calls before execution and blocks dangerous ones.
// Maps to the before_tool_call hook in OpenClaw.
//
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const scanner = @import("../core/scanner.zig");
const pattern = @import("../core/pattern.zig");
const sensitive_files = @import("../patterns/sensitive_files.zig");
const destructive = @import("../patterns/destructive.zig");
const secrets = @import("../patterns/secrets.zig");
const pii_patterns = @import("../patterns/pii.zig");
const config_mod = @import("config.zig");
const ShieldConfig = config_mod.ShieldConfig;
const Match = pattern.Match;

// ── Types ──────────────────────────────────────────────────────────────

pub const Decision = enum {
    allow,
    block,
    audit_only, // Would block, but in audit mode
};

pub const ToolEvaluation = struct {
    decision: Decision,
    reason: []const u8,
    findings: []Match,
    allocator: Allocator,

    pub fn deinit(self: *ToolEvaluation) void {
        self.allocator.free(self.findings);
    }

    pub fn isBlocked(self: ToolEvaluation) bool {
        return self.decision == .block;
    }
};

// ── Tool names recognized as dangerous ─────────────────────────────────

const exec_tools = [_][]const u8{
    "exec",
    "bash",
    "shell",
    "run_command",
    "execute",
    "terminal",
    "system",
};

const read_tools = [_][]const u8{
    "read",
    "read_file",
    "cat",
    "view",
    "open",
};

// ── Main Entry Point ───────────────────────────────────────────────────

/// Evaluate a tool call before execution. Returns whether it should be blocked.
pub fn evaluateToolCall(
    allocator: Allocator,
    tool_name: []const u8,
    params_json: []const u8,
    config: ShieldConfig,
) !ToolEvaluation {
    // Check if tool is an exec-type tool
    if (isExecTool(tool_name)) {
        return evaluateExecCall(allocator, params_json, config);
    }

    // Check if tool is a read-type tool
    if (isReadTool(tool_name)) {
        return evaluateReadCall(allocator, params_json, config);
    }

    // All other tools: allow
    const empty = try allocator.alloc(Match, 0);
    return ToolEvaluation{
        .decision = .allow,
        .reason = "Tool is not restricted",
        .findings = empty,
        .allocator = allocator,
    };
}

// ── Exec Evaluation ────────────────────────────────────────────────────

fn evaluateExecCall(allocator: Allocator, params_json: []const u8, config: ShieldConfig) !ToolEvaluation {
    // Scan params for destructive commands
    const findings = try scanner.scan(allocator, params_json, &destructive.patterns);

    if (findings.len > 0) {
        const decision: Decision = if (config.mode == .audit) .audit_only else .block;
        return ToolEvaluation{
            .decision = decision,
            .reason = "Destructive command detected in tool parameters",
            .findings = findings,
            .allocator = allocator,
        };
    }

    return ToolEvaluation{
        .decision = .allow,
        .reason = "No destructive commands detected",
        .findings = findings,
        .allocator = allocator,
    };
}

// ── Read Evaluation ────────────────────────────────────────────────────

fn evaluateReadCall(allocator: Allocator, params_json: []const u8, config: ShieldConfig) !ToolEvaluation {
    // Extract file path from params — look for path-like strings
    // The params could be JSON like {"path": "/etc/shadow"} or just a path string
    const empty = try allocator.alloc(Match, 0);

    // Simple approach: check if any sensitive file path appears in params
    if (findSensitivePath(params_json)) |matched_pattern| {
        const decision: Decision = if (config.mode == .audit) .audit_only else .block;
        return ToolEvaluation{
            .decision = decision,
            .reason = matched_pattern,
            .findings = empty,
            .allocator = allocator,
        };
    }

    // Also scan for any embedded secrets in the params themselves
    const secret_findings = try scanner.scan(allocator, params_json, &secrets.patterns);
    allocator.free(empty);

    if (secret_findings.len > 0) {
        const decision: Decision = if (config.mode == .audit) .audit_only else .block;
        return ToolEvaluation{
            .decision = decision,
            .reason = "Secrets detected in tool parameters",
            .findings = secret_findings,
            .allocator = allocator,
        };
    }

    return ToolEvaluation{
        .decision = .allow,
        .reason = "File path is not restricted",
        .findings = secret_findings,
        .allocator = allocator,
    };
}

// ── Helpers ────────────────────────────────────────────────────────────

fn isExecTool(name: []const u8) bool {
    for (exec_tools) |tool| {
        if (eqlIgnoreCase(name, tool)) return true;
    }
    return false;
}

fn isReadTool(name: []const u8) bool {
    for (read_tools) |tool| {
        if (eqlIgnoreCase(name, tool)) return true;
    }
    return false;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != std.ascii.toLower(bc)) return false;
    }
    return true;
}

fn findSensitivePath(params: []const u8) ?[]const u8 {
    // First: check the entire params as a bare path (common for simple tool calls)
    if (sensitive_files.matchSensitivePath(std.mem.trim(u8, params, " \t\n\r"))) |name| {
        return name;
    }

    // Walk through params looking for path-like strings
    var i: usize = 0;
    while (i < params.len) {
        // Look for quote-delimited strings
        if (params[i] == '"') {
            i += 1;
            const start = i;
            while (i < params.len and params[i] != '"') i += 1;
            if (i > start) {
                const candidate = params[start..i];
                if (sensitive_files.matchSensitivePath(candidate)) |name| {
                    return name;
                }
            }
            if (i < params.len) i += 1;
        } else if (params[i] == '/' or params[i] == '.' or params[i] == '~') {
            // Could be start of a bare path
            const start = i;
            while (i < params.len and !isPathDelimiter(params[i])) {
                i += 1;
            }
            if (i > start) {
                const candidate = params[start..i];
                if (sensitive_files.matchSensitivePath(candidate)) |name| {
                    return name;
                }
            }
        } else {
            i += 1;
        }
    }
    return null;
}

fn isPathDelimiter(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r' or
        c == ',' or c == '}' or c == ']' or c == '"' or c == '\'';
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "evaluateToolCall — exec with rm is blocked" {
    var eval = try evaluateToolCall(testing.allocator, "exec", "rm -rf /tmp", .{});
    defer eval.deinit();

    try testing.expect(eval.isBlocked());
    try testing.expect(eval.findings.len > 0);
}

test "evaluateToolCall — exec with safe command is allowed" {
    var eval = try evaluateToolCall(testing.allocator, "exec", "ls -la /home", .{});
    defer eval.deinit();

    try testing.expect(!eval.isBlocked());
    try testing.expectEqual(Decision.allow, eval.decision);
}

test "evaluateToolCall — bash with dd is blocked" {
    var eval = try evaluateToolCall(testing.allocator, "bash", "dd if=/dev/zero of=/dev/sda", .{});
    defer eval.deinit();

    try testing.expect(eval.isBlocked());
}

test "evaluateToolCall — read sensitive file is blocked" {
    var eval = try evaluateToolCall(testing.allocator, "read", "{\"path\": \"/etc/shadow\"}", .{});
    defer eval.deinit();

    try testing.expect(eval.isBlocked());
}

test "evaluateToolCall — read normal file is allowed" {
    var eval = try evaluateToolCall(testing.allocator, "read", "{\"path\": \"src/main.zig\"}", .{});
    defer eval.deinit();

    try testing.expect(!eval.isBlocked());
}

test "evaluateToolCall — exec rm in audit mode" {
    var eval = try evaluateToolCall(testing.allocator, "exec", "rm -rf /tmp", .{ .mode = .audit });
    defer eval.deinit();

    try testing.expectEqual(Decision.audit_only, eval.decision);
    try testing.expect(!eval.isBlocked());
}

test "evaluateToolCall — unknown tool is allowed" {
    var eval = try evaluateToolCall(testing.allocator, "weather", "{\"city\": \"NYC\"}", .{});
    defer eval.deinit();

    try testing.expect(!eval.isBlocked());
}

test "evaluateToolCall — read .env file" {
    var eval = try evaluateToolCall(testing.allocator, "read_file", "/app/.env", .{});
    defer eval.deinit();

    try testing.expect(eval.isBlocked());
}

test "evaluateToolCall — read ssh key" {
    var eval = try evaluateToolCall(testing.allocator, "read", "/home/user/.ssh/id_rsa", .{});
    defer eval.deinit();

    try testing.expect(eval.isBlocked());
}
