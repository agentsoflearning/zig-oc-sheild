// OpenClaw Shield — Skill Threat Detection Patterns
//
// Phase 3: Static analysis patterns for detecting malicious or dangerous
// constructs in skill/plugin code. Mirrors OpenClaw's built-in
// skill-scanner.ts but runs in Zig for performance.
//
// Categories:
//   - Code execution: child_process, eval, new Function
//   - Crypto-mining: stratum, coinhive, xmrig
//   - Environment harvesting: process.env bulk access
//   - Obfuscated code: hex-encoded strings, large base64 blobs
//   - Privilege escalation: sudo, chmod, chown patterns

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const Pattern = pattern.Pattern;

// ── Pattern Table ──────────────────────────────────────────────────────

pub const patterns = [_]Pattern{
    .{ .name = "child_process_usage", .category = .skill_threat, .severity = .critical, .matchAt = matchChildProcess },
    .{ .name = "eval_usage", .category = .skill_threat, .severity = .critical, .matchAt = matchEval },
    .{ .name = "new_function", .category = .skill_threat, .severity = .critical, .matchAt = matchNewFunction },
    .{ .name = "crypto_mining", .category = .skill_threat, .severity = .critical, .matchAt = matchCryptoMining },
    .{ .name = "env_harvesting", .category = .skill_threat, .severity = .warning, .matchAt = matchEnvHarvesting },
    .{ .name = "hex_encoded_string", .category = .skill_threat, .severity = .warning, .matchAt = matchHexEncoded },
    .{ .name = "privilege_escalation", .category = .skill_threat, .severity = .critical, .matchAt = matchPrivEsc },
};

// ── Match Functions ────────────────────────────────────────────────────

/// Detect child_process usage:
///   require("child_process"), require('child_process'),
///   from "child_process", from 'child_process',
///   child_process.exec, child_process.spawn, etc.
fn matchChildProcess(input: []const u8, pos: usize) ?usize {
    // require("child_process") or require('child_process')
    if (matchRequire(input, pos, "child_process")) |len| return len;

    // from "child_process" (ES import)
    if (matchFrom(input, pos, "child_process")) |len| return len;

    // child_process.exec/spawn/execFile/fork
    if (pattern.startsWith(input, pos, "child_process.")) {
        const after = pos + 14; // len("child_process.")
        const methods = [_][]const u8{ "exec", "execFile", "execSync", "spawn", "spawnSync", "fork" };
        for (methods) |method| {
            if (pattern.startsWith(input, after, method)) {
                return 14 + method.len;
            }
        }
    }

    return null;
}

/// Detect eval() usage: eval( — must be preceded by non-alphanumeric
/// to avoid matching "medieval" etc.
fn matchEval(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    if (!pattern.startsWith(input, pos, "eval(")) return null;
    return 5; // "eval("
}

/// Detect new Function() — dynamic code construction
fn matchNewFunction(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "new")) return null;
    var p = pos + 3;
    // Require whitespace
    if (p >= input.len or (input[p] != ' ' and input[p] != '\t')) return null;
    p = pattern.skipWhitespace(input, p);
    if (!pattern.startsWith(input, p, "Function(") and !pattern.startsWith(input, p, "Function (")) return null;
    // Match up to the opening paren
    while (p < input.len and input[p] != '(') {
        p += 1;
    }
    if (p < input.len) p += 1; // include the (
    return p - pos;
}

/// Detect crypto-mining patterns:
///   stratum+tcp://, stratum+ssl://, stratum://
///   coinhive, xmrig, minergate, cryptonight
fn matchCryptoMining(input: []const u8, pos: usize) ?usize {
    // Stratum protocol URLs
    const stratum_prefixes = [_][]const u8{
        "stratum+tcp://",
        "stratum+ssl://",
        "stratum://",
    };
    for (stratum_prefixes) |prefix| {
        if (startsWithIgnoreCase(input, pos, prefix)) {
            // Consume until whitespace or end
            var p = pos + prefix.len;
            while (p < input.len and input[p] != ' ' and input[p] != '\t' and
                input[p] != '\n' and input[p] != '"' and input[p] != '\'')
            {
                p += 1;
            }
            return p - pos;
        }
    }

    // Known miner names (word-boundary required)
    if (!pattern.isWordBoundary(input, pos)) return null;
    const miners = [_][]const u8{
        "coinhive",
        "CoinHive",
        "xmrig",
        "xmr-stak",
        "minergate",
        "cryptonight",
        "hashrate",
    };
    for (miners) |miner| {
        if (pattern.startsWith(input, pos, miner)) {
            const end = pos + miner.len;
            if (pattern.isWordBoundaryAfter(input, end)) {
                return miner.len;
            }
        }
    }

    return null;
}

/// Detect environment variable harvesting:
///   process.env (bulk access to all env vars)
///   JSON.stringify(process.env)
///   Object.keys(process.env)
///   Object.entries(process.env)
fn matchEnvHarvesting(input: []const u8, pos: usize) ?usize {
    // JSON.stringify(process.env)
    if (pattern.startsWith(input, pos, "JSON.stringify(process.env")) {
        return 25;
    }
    // Object.keys(process.env) or Object.entries(process.env) or Object.values(process.env)
    if (pattern.startsWith(input, pos, "Object.")) {
        const after = pos + 7;
        const methods = [_][]const u8{ "keys(process.env", "entries(process.env", "values(process.env" };
        for (methods) |method| {
            if (pattern.startsWith(input, after, method)) {
                return 7 + method.len;
            }
        }
    }
    // Bare process.env (without .SPECIFIC_VAR — which is normal usage)
    if (pattern.startsWith(input, pos, "process.env")) {
        const after = pos + 11;
        // If followed by [ or ) or , or ; or whitespace or end → bulk access
        // If followed by . → specific var, not harvesting
        if (after >= input.len) return 11;
        const next = input[after];
        if (next == '.' or next == '_') return null; // process.env.VAR or process.env_something
        if (next == '[' or next == ')' or next == ',' or next == ';' or
            next == ' ' or next == '\n' or next == '\t' or next == '}')
        {
            return 11;
        }
    }
    return null;
}

/// Detect hex-encoded strings: \x followed by 10+ hex pairs
/// e.g., \x68\x65\x6c\x6c\x6f (often used to obfuscate payloads)
fn matchHexEncoded(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "\\x")) return null;

    var p = pos;
    var pairs: usize = 0;
    while (p + 3 < input.len and input[p] == '\\' and input[p + 1] == 'x') {
        if (!isHexDigit(input[p + 2]) or !isHexDigit(input[p + 3])) break;
        p += 4;
        pairs += 1;
    }

    // Require at least 5 hex pairs (10 bytes — short enough to catch payloads)
    if (pairs < 5) return null;
    return p - pos;
}

/// Detect privilege escalation commands:
///   sudo, chmod 777, chmod +s, chown root, setuid
fn matchPrivEsc(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;

    // sudo
    if (pattern.startsWith(input, pos, "sudo ")) {
        // Consume the command after sudo
        var p = pos + 5;
        while (p < input.len and input[p] != '\n' and input[p] != ';' and input[p] != '"' and input[p] != '\'') {
            p += 1;
        }
        if (p > pos + 5) return p - pos;
    }

    // chmod with dangerous modes
    if (pattern.startsWith(input, pos, "chmod ") or pattern.startsWith(input, pos, "chmod\t")) {
        var p = pos + 6;
        p = pattern.skipWhitespace(input, p);
        // Check for dangerous patterns: 777, 666, +s, u+s, g+s, 4755, 2755
        if (pattern.startsWith(input, p, "777") or
            pattern.startsWith(input, p, "666") or
            pattern.startsWith(input, p, "+s") or
            pattern.startsWith(input, p, "u+s") or
            pattern.startsWith(input, p, "g+s") or
            pattern.startsWith(input, p, "4755") or
            pattern.startsWith(input, p, "2755"))
        {
            while (p < input.len and input[p] != '\n' and input[p] != ';') {
                p += 1;
            }
            return p - pos;
        }
    }

    // chown root
    if (pattern.startsWith(input, pos, "chown ") or pattern.startsWith(input, pos, "chown\t")) {
        var p = pos + 6;
        p = pattern.skipWhitespace(input, p);
        if (pattern.startsWith(input, p, "root")) {
            while (p < input.len and input[p] != '\n' and input[p] != ';') {
                p += 1;
            }
            return p - pos;
        }
    }

    return null;
}

// ── Helpers ────────────────────────────────────────────────────────────

fn matchRequire(input: []const u8, pos: usize, module: []const u8) ?usize {
    if (!pattern.startsWith(input, pos, "require(")) return null;
    var p = pos + 8; // len("require(")
    // Quote
    if (p >= input.len or (input[p] != '"' and input[p] != '\'')) return null;
    const quote = input[p];
    p += 1;
    // Module name
    if (!pattern.startsWith(input, p, module)) return null;
    p += module.len;
    // Closing quote
    if (p >= input.len or input[p] != quote) return null;
    p += 1;
    // Closing paren
    if (p >= input.len or input[p] != ')') return null;
    p += 1;
    return p - pos;
}

fn matchFrom(input: []const u8, pos: usize, module: []const u8) ?usize {
    if (!pattern.startsWith(input, pos, "from ") and !pattern.startsWith(input, pos, "from\t")) return null;
    var p = pos + 5;
    p = pattern.skipWhitespace(input, p);
    // Quote
    if (p >= input.len or (input[p] != '"' and input[p] != '\'')) return null;
    const quote = input[p];
    p += 1;
    // Module name
    if (!pattern.startsWith(input, p, module)) return null;
    p += module.len;
    // Closing quote
    if (p >= input.len or input[p] != quote) return null;
    p += 1;
    return p - pos;
}

fn startsWithIgnoreCase(input: []const u8, pos: usize, prefix: []const u8) bool {
    if (pos + prefix.len > input.len) return false;
    for (input[pos..][0..prefix.len], prefix) |a, b| {
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return true;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "child_process — require double quotes" {
    try testing.expect(matchChildProcess("require(\"child_process\")", 0) != null);
}

test "child_process — require single quotes" {
    try testing.expect(matchChildProcess("require('child_process')", 0) != null);
}

test "child_process — ES import from" {
    try testing.expect(matchChildProcess("from \"child_process\"", 0) != null);
    try testing.expect(matchChildProcess("from 'child_process'", 0) != null);
}

test "child_process — method calls" {
    try testing.expect(matchChildProcess("child_process.exec(", 0) != null);
    try testing.expect(matchChildProcess("child_process.spawn(", 0) != null);
    try testing.expect(matchChildProcess("child_process.execFile(", 0) != null);
    try testing.expect(matchChildProcess("child_process.fork(", 0) != null);
}

test "child_process — no false positive" {
    try testing.expect(matchChildProcess("child_process_module", 0) == null);
    try testing.expect(matchChildProcess("process.exit()", 0) == null);
}

test "eval_usage — basic" {
    try testing.expect(matchEval("eval(code)", 0) != null);
    try testing.expect(matchEval(" eval(x)", 1) != null);
}

test "eval_usage — no false positive" {
    try testing.expect(matchEval("medieval", 0) == null); // part of a word
    try testing.expect(matchEval("xeval(", 1) == null); // preceded by alnum
}

test "new_function — basic" {
    try testing.expect(matchNewFunction("new Function(code)", 0) != null);
    try testing.expect(matchNewFunction("new Function (code)", 0) != null);
}

test "new_function — not a match without Function" {
    try testing.expect(matchNewFunction("new Date()", 0) == null);
    try testing.expect(matchNewFunction("newFunction()", 0) == null);
}

test "crypto_mining — stratum protocols" {
    try testing.expect(matchCryptoMining("stratum+tcp://pool.example.com:3333", 0) != null);
    try testing.expect(matchCryptoMining("stratum+ssl://pool.example.com:3333", 0) != null);
    try testing.expect(matchCryptoMining("stratum://pool.example.com:3333", 0) != null);
}

test "crypto_mining — known miners" {
    try testing.expect(matchCryptoMining("coinhive", 0) != null);
    try testing.expect(matchCryptoMining("xmrig", 0) != null);
    try testing.expect(matchCryptoMining("minergate", 0) != null);
    try testing.expect(matchCryptoMining("cryptonight", 0) != null);
}

test "crypto_mining — no false positive" {
    try testing.expect(matchCryptoMining("coin", 0) == null);
    try testing.expect(matchCryptoMining("mining", 0) == null);
}

test "env_harvesting — JSON.stringify" {
    try testing.expect(matchEnvHarvesting("JSON.stringify(process.env", 0) != null);
}

test "env_harvesting — Object methods" {
    try testing.expect(matchEnvHarvesting("Object.keys(process.env", 0) != null);
    try testing.expect(matchEnvHarvesting("Object.entries(process.env", 0) != null);
}

test "env_harvesting — bulk access" {
    try testing.expect(matchEnvHarvesting("process.env)", 0) != null);
    try testing.expect(matchEnvHarvesting("process.env,", 0) != null);
}

test "env_harvesting — specific var is NOT flagged" {
    try testing.expect(matchEnvHarvesting("process.env.HOME", 0) == null);
    try testing.expect(matchEnvHarvesting("process.env.NODE_ENV", 0) == null);
}

test "hex_encoded_string — 5+ pairs" {
    try testing.expect(matchHexEncoded("\\x68\\x65\\x6c\\x6c\\x6f", 0) != null); // hello
    try testing.expect(matchHexEncoded("\\x41\\x42\\x43\\x44\\x45\\x46", 0) != null);
}

test "hex_encoded_string — too few pairs" {
    try testing.expect(matchHexEncoded("\\x41\\x42\\x43", 0) == null); // only 3
}

test "privilege_escalation — sudo" {
    try testing.expect(matchPrivEsc("sudo rm -rf /", 0) != null);
    try testing.expect(matchPrivEsc("sudo apt install", 0) != null);
}

test "privilege_escalation — chmod dangerous" {
    try testing.expect(matchPrivEsc("chmod 777 /var/www", 0) != null);
    try testing.expect(matchPrivEsc("chmod +s /usr/bin/prog", 0) != null);
    try testing.expect(matchPrivEsc("chmod 666 file.txt", 0) != null);
}

test "privilege_escalation — chmod safe not matched" {
    try testing.expect(matchPrivEsc("chmod 644 file.txt", 0) == null);
    try testing.expect(matchPrivEsc("chmod 755 /usr/bin/prog", 0) == null);
}

test "privilege_escalation — chown root" {
    try testing.expect(matchPrivEsc("chown root /etc/passwd", 0) != null);
    try testing.expect(matchPrivEsc("chown root:root /etc/shadow", 0) != null);
}

test "privilege_escalation — chown non-root not matched" {
    try testing.expect(matchPrivEsc("chown user file.txt", 0) == null);
}
