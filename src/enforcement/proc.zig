// OpenClaw Shield — L7: Process Enforcement
//
// Top-level decision function for subprocess spawning.
// Evaluates binary name against allowlist, denies shells by default.
// Called from the TypeScript bridge before child_process.spawn/execFile.
//
// Pure function — no I/O, no system calls, deterministic.

const std = @import("std");
const reason_codes = @import("reason_codes.zig");
const Decision = reason_codes.Decision;
const ReasonCode = reason_codes.ReasonCode;
const Risk = reason_codes.Risk;
const TaintState = reason_codes.TaintState;

/// Process policy settings (subset of PolicyCapsule).
pub const ProcessPolicy = struct {
    allow_spawn: bool = false,
    allowed_binaries: []const []const u8 = &.{},
    deny_shells: bool = true,
    max_exec_per_min: u32 = 10,
};

/// Known shell binary names.
const shell_names = [_][]const u8{
    "bash",
    "sh",
    "zsh",
    "fish",
    "csh",
    "tcsh",
    "ksh",
    "dash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
};

/// Evaluate a subprocess spawn attempt.
///
/// Checks in order (first deny wins):
/// 1. Quarantine state → block all
/// 2. Spawn globally disabled → block
/// 3. Shell binary + deny_shells → block
/// 4. Binary not in allowlist → block (unless allowlist has "*")
/// 5. Exec rate limit (caller checks externally like egress bytes)
///
/// The `binary` parameter should be the basename of the executable
/// (e.g., "git", not "/usr/bin/git").
pub fn decideSpawn(
    policy: ProcessPolicy,
    binary: []const u8,
    taint_state: TaintState,
) Decision {
    // Quarantined sessions: block everything
    if (taint_state == .quarantined) {
        return Decision.quarantine();
    }

    // Global spawn toggle
    if (!policy.allow_spawn) {
        return Decision.blocked(.proc_spawn_denied, .high);
    }

    // Shell denial
    if (policy.deny_shells and isShell(binary)) {
        return Decision.blocked(.proc_shell_denied, .high);
    }

    // Allowlist check
    if (!isBinaryAllowed(binary, policy.allowed_binaries)) {
        return Decision.blocked(.proc_binary_not_allowed, .medium);
    }

    return Decision.allowed();
}

/// Check exec count against rate limit.
/// Separate from decideSpawn because counter state is managed externally.
pub fn checkExecLimit(current_count: u64, max_per_min: u32) Decision {
    if (current_count >= max_per_min) {
        return Decision.blocked(.rate_limit_exceeded, .medium);
    }
    return Decision.allowed();
}

/// Extract the basename from a path (e.g., "/usr/bin/git" → "git").
pub fn basename(path: []const u8) []const u8 {
    // Find last '/' or '\'
    var last_sep: usize = 0;
    var found_sep = false;
    for (path, 0..) |c, i| {
        if (c == '/' or c == '\\') {
            last_sep = i;
            found_sep = true;
        }
    }
    if (found_sep) return path[last_sep + 1 ..];
    return path;
}

/// Parse a JSON argv array and extract the binary name (first element).
/// Expected format: ["git", "clone", "..."] or just "git clone ..."
/// Returns the binary basename or null if parsing fails.
pub fn extractBinaryFromArgv(argv_json: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, argv_json, " \t\n\r");
    if (trimmed.len == 0) return null;

    // JSON array format: ["binary", "arg1", ...]
    if (trimmed[0] == '[') {
        // Find first quoted string
        if (std.mem.indexOf(u8, trimmed, "\"")) |start| {
            const after = trimmed[start + 1 ..];
            if (std.mem.indexOf(u8, after, "\"")) |end| {
                return basename(after[0..end]);
            }
        }
        return null;
    }

    // Plain string: take first whitespace-delimited token
    var end: usize = 0;
    while (end < trimmed.len and trimmed[end] != ' ' and trimmed[end] != '\t') {
        end += 1;
    }
    if (end > 0) {
        return basename(trimmed[0..end]);
    }
    return null;
}

fn isShell(binary_name: []const u8) bool {
    const name = basename(binary_name);
    for (shell_names) |shell| {
        if (eqlIgnoreCase(name, shell)) return true;
    }
    return false;
}

fn isBinaryAllowed(binary_name: []const u8, allowed: []const []const u8) bool {
    if (allowed.len == 0) return false;

    const name = basename(binary_name);
    for (allowed) |entry| {
        // Universal wildcard
        if (entry.len == 1 and entry[0] == '*') return true;
        if (eqlIgnoreCase(name, entry)) return true;
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

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "decideSpawn — spawn disabled blocks all" {
    const policy = ProcessPolicy{ .allow_spawn = false };
    const d = decideSpawn(policy, "git", .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.proc_spawn_denied, d.reason_code);
}

test "decideSpawn — allowed binary" {
    const bins = [_][]const u8{ "git", "node", "npx" };
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins };

    const d = decideSpawn(policy, "git", .clean);
    try testing.expect(d.allow);
}

test "decideSpawn — blocked binary not in allowlist" {
    const bins = [_][]const u8{ "git", "node" };
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins };

    const d = decideSpawn(policy, "curl", .clean);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.proc_binary_not_allowed, d.reason_code);
}

test "decideSpawn — shell denied" {
    const bins = [_][]const u8{"*"};
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins, .deny_shells = true };

    const d1 = decideSpawn(policy, "bash", .clean);
    try testing.expect(!d1.allow);
    try testing.expectEqual(ReasonCode.proc_shell_denied, d1.reason_code);

    const d2 = decideSpawn(policy, "sh", .clean);
    try testing.expect(!d2.allow);

    const d3 = decideSpawn(policy, "powershell", .clean);
    try testing.expect(!d3.allow);

    const d4 = decideSpawn(policy, "cmd.exe", .clean);
    try testing.expect(!d4.allow);
}

test "decideSpawn — shell allowed when deny_shells is false" {
    const bins = [_][]const u8{"*"};
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins, .deny_shells = false };

    const d = decideSpawn(policy, "bash", .clean);
    try testing.expect(d.allow);
}

test "decideSpawn — wildcard allowlist" {
    const bins = [_][]const u8{"*"};
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins };

    const d = decideSpawn(policy, "anything", .clean);
    try testing.expect(d.allow);
}

test "decideSpawn — quarantined blocks all" {
    const bins = [_][]const u8{"*"};
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins, .deny_shells = false };

    const d = decideSpawn(policy, "git", .quarantined);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.quarantined, d.reason_code);
}

test "decideSpawn — case insensitive binary match" {
    const bins = [_][]const u8{"Git"};
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins };

    const d = decideSpawn(policy, "git", .clean);
    try testing.expect(d.allow);
}

test "basename — extracts from path" {
    try testing.expectEqualStrings("git", basename("/usr/bin/git"));
    try testing.expectEqualStrings("node", basename("/usr/local/bin/node"));
    try testing.expectEqualStrings("cmd.exe", basename("C:\\Windows\\System32\\cmd.exe"));
    try testing.expectEqualStrings("git", basename("git"));
}

test "extractBinaryFromArgv — JSON array" {
    try testing.expectEqualStrings("git", extractBinaryFromArgv("[\"git\", \"clone\", \"url\"]").?);
    try testing.expectEqualStrings("node", extractBinaryFromArgv("[\"node\", \"app.js\"]").?);
    try testing.expectEqualStrings("bash", extractBinaryFromArgv("[\"/bin/bash\", \"-c\", \"echo hi\"]").?);
}

test "extractBinaryFromArgv — plain string" {
    try testing.expectEqualStrings("git", extractBinaryFromArgv("git clone url").?);
    try testing.expectEqualStrings("ls", extractBinaryFromArgv("ls -la").?);
}

test "extractBinaryFromArgv — empty" {
    try testing.expect(extractBinaryFromArgv("") == null);
    try testing.expect(extractBinaryFromArgv("  ") == null);
}

test "checkExecLimit — under limit" {
    const d = checkExecLimit(3, 10);
    try testing.expect(d.allow);
}

test "checkExecLimit — at limit" {
    const d = checkExecLimit(10, 10);
    try testing.expect(!d.allow);
    try testing.expectEqual(ReasonCode.rate_limit_exceeded, d.reason_code);
}

test "decideSpawn — full path binary resolved to basename" {
    const bins = [_][]const u8{"git"};
    const policy = ProcessPolicy{ .allow_spawn = true, .allowed_binaries = &bins };

    const d = decideSpawn(policy, "/usr/bin/git", .clean);
    try testing.expect(d.allow);
}

test "isShell — all known shells detected" {
    const shells = [_][]const u8{
        "bash", "sh", "zsh", "fish", "csh", "tcsh", "ksh", "dash",
        "cmd",  "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    };
    for (shells) |s| {
        try testing.expect(isShell(s));
    }
    try testing.expect(!isShell("git"));
    try testing.expect(!isShell("node"));
}
