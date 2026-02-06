// OpenClaw Shield — L5: Security Gate
//
// Gate tool that the agent must call before exec/read operations.
// Registered via registerTool in OpenClaw — works on all versions.
//
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const scanner = @import("../core/scanner.zig");
const pattern = @import("../core/pattern.zig");
const sensitive_files = @import("../patterns/sensitive_files.zig");
const destructive = @import("../patterns/destructive.zig");
const secrets = @import("../patterns/secrets.zig");
const config_mod = @import("config.zig");
const ShieldConfig = config_mod.ShieldConfig;
const Match = pattern.Match;

// ── Types ──────────────────────────────────────────────────────────────

pub const GateRequest = struct {
    command: ?[]const u8 = null,
    file_path: ?[]const u8 = null,
};

pub const GateStatus = enum {
    allowed,
    denied,
};

pub const GateResponse = struct {
    status: GateStatus,
    reason: []const u8,
    findings: []Match,
    sensitive_pattern: ?[]const u8,
    allocator: Allocator,

    pub fn deinit(self: *GateResponse) void {
        self.allocator.free(self.findings);
    }

    pub fn isDenied(self: GateResponse) bool {
        return self.status == .denied;
    }
};

// ── Main Entry Point ───────────────────────────────────────────────────

/// Evaluate a gate request. Called by the agent before exec/read.
pub fn evaluateGateRequest(
    allocator: Allocator,
    request: GateRequest,
    config: ShieldConfig,
) !GateResponse {
    // Check command if provided
    if (request.command) |command| {
        return evaluateCommand(allocator, command, config);
    }

    // Check file path if provided
    if (request.file_path) |file_path| {
        return evaluateFilePath(allocator, file_path, config);
    }

    // No command or file_path — invalid request
    const empty = try allocator.alloc(Match, 0);
    return GateResponse{
        .status = .denied,
        .reason = "Gate request must include either `command` or `file_path`",
        .findings = empty,
        .sensitive_pattern = null,
        .allocator = allocator,
    };
}

// ── Command Evaluation ─────────────────────────────────────────────────

fn evaluateCommand(allocator: Allocator, command: []const u8, config: ShieldConfig) !GateResponse {
    // Scan for destructive commands
    const cmd_findings = try scanner.scan(allocator, command, &destructive.patterns);
    errdefer allocator.free(cmd_findings);

    if (cmd_findings.len > 0) {
        const status: GateStatus = if (config.mode == .audit) .allowed else .denied;
        return GateResponse{
            .status = status,
            .reason = "Destructive command detected",
            .findings = cmd_findings,
            .sensitive_pattern = null,
            .allocator = allocator,
        };
    }

    // Also check for secrets embedded in command args (e.g., passing API keys as args)
    const secret_findings = try scanner.scan(allocator, command, &secrets.patterns);
    allocator.free(cmd_findings);

    if (secret_findings.len > 0) {
        const status: GateStatus = if (config.mode == .audit) .allowed else .denied;
        return GateResponse{
            .status = status,
            .reason = "Secret detected in command arguments",
            .findings = secret_findings,
            .sensitive_pattern = null,
            .allocator = allocator,
        };
    }

    return GateResponse{
        .status = .allowed,
        .reason = "Command approved",
        .findings = secret_findings,
        .sensitive_pattern = null,
        .allocator = allocator,
    };
}

// ── File Path Evaluation ───────────────────────────────────────────────

fn evaluateFilePath(allocator: Allocator, file_path: []const u8, config: ShieldConfig) !GateResponse {
    const empty = try allocator.alloc(Match, 0);

    if (sensitive_files.matchSensitivePath(file_path)) |matched_pattern| {
        const status: GateStatus = if (config.mode == .audit) .allowed else .denied;
        return GateResponse{
            .status = status,
            .reason = "Sensitive file path detected",
            .findings = empty,
            .sensitive_pattern = matched_pattern,
            .allocator = allocator,
        };
    }

    return GateResponse{
        .status = .allowed,
        .reason = "File path approved",
        .findings = empty,
        .sensitive_pattern = null,
        .allocator = allocator,
    };
}

/// Format a gate response as a structured string for the agent.
pub fn formatGateResponse(allocator: Allocator, response: GateResponse) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();

    try w.print("STATUS: {s}\n", .{if (response.status == .allowed) "ALLOWED" else "DENIED"});
    try w.print("REASON: {s}\n", .{response.reason});

    if (response.sensitive_pattern) |sp| {
        try w.print("PATTERN: {s}\n", .{sp});
    }

    if (response.findings.len > 0) {
        try w.writeAll("FINDINGS:\n");
        for (response.findings) |f| {
            try w.print("  - [{s}] {s}\n", .{ @tagName(f.severity), f.pattern_name });
        }
    }

    return out.toOwnedSlice();
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "evaluateGateRequest — safe command" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .command = "ls -la /home" }, .{});
    defer resp.deinit();

    try testing.expect(!resp.isDenied());
    try testing.expectEqual(GateStatus.allowed, resp.status);
}

test "evaluateGateRequest — destructive command" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .command = "rm -rf /" }, .{});
    defer resp.deinit();

    try testing.expect(resp.isDenied());
    try testing.expect(std.mem.indexOf(u8, resp.reason, "Destructive") != null);
}

test "evaluateGateRequest — command with embedded secret" {
    var resp = try evaluateGateRequest(
        testing.allocator,
        .{ .command = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmno'" },
        .{},
    );
    defer resp.deinit();

    try testing.expect(resp.isDenied());
    try testing.expect(std.mem.indexOf(u8, resp.reason, "Secret") != null);
}

test "evaluateGateRequest — safe file path" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .file_path = "src/main.zig" }, .{});
    defer resp.deinit();

    try testing.expect(!resp.isDenied());
}

test "evaluateGateRequest — sensitive file path" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .file_path = "/etc/shadow" }, .{});
    defer resp.deinit();

    try testing.expect(resp.isDenied());
    try testing.expectEqualStrings("etc_shadow", resp.sensitive_pattern.?);
}

test "evaluateGateRequest — .env file" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .file_path = "/app/.env.production" }, .{});
    defer resp.deinit();

    try testing.expect(resp.isDenied());
    try testing.expectEqualStrings("dot_env", resp.sensitive_pattern.?);
}

test "evaluateGateRequest — ssh key" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .file_path = "/home/user/.ssh/id_rsa" }, .{});
    defer resp.deinit();

    try testing.expect(resp.isDenied());
}

test "evaluateGateRequest — audit mode allows but flags" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .command = "rm -rf /tmp" }, .{ .mode = .audit });
    defer resp.deinit();

    try testing.expect(!resp.isDenied());
    try testing.expectEqual(GateStatus.allowed, resp.status);
    try testing.expect(resp.findings.len > 0);
}

test "evaluateGateRequest — empty request" {
    var resp = try evaluateGateRequest(testing.allocator, .{}, .{});
    defer resp.deinit();

    try testing.expect(resp.isDenied());
    try testing.expect(std.mem.indexOf(u8, resp.reason, "must include") != null);
}

test "formatGateResponse — denied" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .command = "rm file" }, .{});
    defer resp.deinit();

    const formatted = try formatGateResponse(testing.allocator, resp);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "STATUS: DENIED") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "FINDINGS:") != null);
}

test "formatGateResponse — allowed" {
    var resp = try evaluateGateRequest(testing.allocator, .{ .command = "echo hello" }, .{});
    defer resp.deinit();

    const formatted = try formatGateResponse(testing.allocator, resp);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "STATUS: ALLOWED") != null);
}
