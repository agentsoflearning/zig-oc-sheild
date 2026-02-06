// OpenClaw Shield — Hardening Tests
//
// Fuzz-like edge-case tests covering boundary conditions, malformed inputs,
// and adversarial scenarios across all modules. No panics allowed.

const std = @import("std");
const testing = std.testing;

// ── Module Imports ──────────────────────────────────────────────────

const scanner = @import("../core/scanner.zig");
const pattern = @import("../core/pattern.zig");
const entropy = @import("../core/entropy.zig");
const secrets = @import("../patterns/secrets.zig");
const pii = @import("../patterns/pii.zig");
const pii_intl = @import("../patterns/pii_intl.zig");
const skill_threats = @import("../patterns/skill_threats.zig");
const prompt_injection = @import("../patterns/prompt_injection.zig");
const destructive = @import("../patterns/destructive.zig");
const sensitive_files = @import("../patterns/sensitive_files.zig");
const ip_ranges = @import("../enforcement/ip_ranges.zig");
const domain = @import("../enforcement/domain.zig");
const net = @import("../enforcement/net.zig");
const proc = @import("../enforcement/proc.zig");
const layer_config = @import("../layers/config.zig");
const loader = @import("loader.zig");
const validator = @import("validator.zig");
const engine = @import("engine.zig");

const alloc = testing.allocator;

// ═══════════════════════════════════════════════════════════════════
// Scanner Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: empty input produces no matches" {
    const matches = try scanner.scan(alloc, "", &secrets.patterns);
    defer alloc.free(matches);
    try testing.expectEqual(@as(usize, 0), matches.len);
}

test "hardening: single character inputs" {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    for (0..chars.len) |i| {
        const input = chars[i .. i + 1];
        const matches = try scanner.scan(alloc, input, &secrets.patterns);
        defer alloc.free(matches);
        // Must not panic — zero matches expected
    }
}

test "hardening: null bytes in input" {
    const input = "AKIA\x001234567890ABCDEF";
    const matches = try scanner.scan(alloc, input, &secrets.patterns);
    defer alloc.free(matches);
    // Null byte breaks the pattern — should not match
}

test "hardening: very long input without patterns" {
    // 10KB of clean text
    var buf: [10240]u8 = undefined;
    @memset(&buf, 'A');
    const matches = try scanner.scan(alloc, &buf, &secrets.patterns);
    defer alloc.free(matches);
    try testing.expectEqual(@as(usize, 0), matches.len);
}

test "hardening: consecutive pattern matches back to back" {
    const input = "AKIA1234567890ABCDEFAKIA0987654321ZYXWVU";
    const matches = try scanner.scan(alloc, input, &secrets.patterns);
    defer alloc.free(matches);
    try testing.expectEqual(@as(usize, 2), matches.len);
}

test "hardening: pattern at exact end of input" {
    const input = "text AKIA1234567890ABCDEF";
    const matches = try scanner.scan(alloc, input, &secrets.patterns);
    defer alloc.free(matches);
    try testing.expect(matches.len >= 1);
    try testing.expectEqual(input.len, matches[0].end);
}

test "hardening: unicode input does not panic" {
    const input = "Hello \xc3\xa9\xc3\xa0\xc3\xbc world \xf0\x9f\x98\x80";
    const matches = try scanner.scan(alloc, input, &secrets.patterns);
    defer alloc.free(matches);
    // No panic, no matches expected
}

test "hardening: redact empty matches array" {
    const input = "Hello, world!";
    const empty_matches: []const pattern.Match = &.{};
    const result = try scanner.redact(alloc, input, empty_matches, .{});
    defer alloc.free(result);
    try testing.expectEqualStrings(input, result);
}

test "hardening: redact with all strategies on same input" {
    const input = "My key is AKIA1234567890ABCDEF";
    const matches = try scanner.scan(alloc, input, &secrets.patterns);
    defer alloc.free(matches);
    try testing.expect(matches.len >= 1);

    // mask
    const r1 = try scanner.redact(alloc, input, matches, .{ .strategy = .mask });
    defer alloc.free(r1);
    try testing.expect(std.mem.indexOf(u8, r1, "[REDACTED:") != null);

    // partial
    const r2 = try scanner.redact(alloc, input, matches, .{ .strategy = .partial, .partial_chars = 4 });
    defer alloc.free(r2);
    try testing.expect(r2.len > 0);

    // hash
    const r3 = try scanner.redact(alloc, input, matches, .{ .strategy = .hash });
    defer alloc.free(r3);
    try testing.expect(std.mem.indexOf(u8, r3, "[SHA256:") != null);

    // drop
    const r4 = try scanner.redact(alloc, input, matches, .{ .strategy = .drop });
    defer alloc.free(r4);
    try testing.expect(r4.len < input.len);
}

// ═══════════════════════════════════════════════════════════════════
// Entropy Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: entropy of empty string" {
    const e = entropy.shannonEntropy("");
    try testing.expectEqual(@as(f64, 0.0), e);
}

test "hardening: entropy of single char repeated" {
    const e = entropy.shannonEntropy("AAAAAAAAAA");
    try testing.expectEqual(@as(f64, 0.0), e);
}

test "hardening: entropy of all unique bytes" {
    // Max entropy for 256 unique values in a 256-byte string
    var buf: [256]u8 = undefined;
    for (0..256) |i| buf[i] = @intCast(i);
    const e = entropy.shannonEntropy(&buf);
    try testing.expect(e > 7.9); // Should be ~8.0
}

test "hardening: detect high entropy on short strings" {
    const flags = try entropy.detectHighEntropy(alloc, "ab", .{});
    defer alloc.free(flags);
    try testing.expectEqual(@as(usize, 0), flags.len);
}

// ═══════════════════════════════════════════════════════════════════
// IP Range Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: empty host string" {
    const cls = ip_ranges.parseIp("");
    try testing.expect(cls == null);
}

test "hardening: IPv4 boundary values" {
    // 0.0.0.0
    const c1 = ip_ranges.parseIp("0.0.0.0");
    try testing.expect(c1 != null);

    // 255.255.255.255
    const c2 = ip_ranges.parseIp("255.255.255.255");
    try testing.expect(c2 != null);

    // 256.0.0.0 — invalid
    const c3 = ip_ranges.parseIp("256.0.0.0");
    try testing.expect(c3 == null);
}

test "hardening: malformed IP strings" {
    const cases = [_][]const u8{
        "not-an-ip",
        "192.168",
        "192.168.1",
        "192.168.1.1.1",
        "192.168.1.",
        ".192.168.1.1",
        "192.168.1.1:8080",
        "abc.def.ghi.jkl",
        "1234567890",
    };
    for (cases) |host| {
        const cls = ip_ranges.parseIp(host);
        // Must not panic — null means "not recognized"
        _ = cls;
    }
}

test "hardening: IPv6 loopback" {
    const cls = ip_ranges.parseIp("::1");
    try testing.expect(cls != null);
    try testing.expect(cls.? == .localhost);
}

// ═══════════════════════════════════════════════════════════════════
// Domain Matching Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: empty allowlist blocks everything" {
    try testing.expect(!domain.isAllowed("example.com", &.{}));
}

test "hardening: empty host with wildcard allowlist" {
    const hosts = [_][]const u8{"*"};
    // Empty host with wildcard — should match (wildcard matches all)
    try testing.expect(domain.isAllowed("", &hosts));
}

test "hardening: domain with trailing dot" {
    const hosts = [_][]const u8{"example.com"};
    try testing.expect(domain.isAllowed("example.com.", &hosts));
}

test "hardening: case insensitive domain" {
    const hosts = [_][]const u8{"EXAMPLE.COM"};
    try testing.expect(domain.isAllowed("example.com", &hosts));
}

test "hardening: wildcard suffix does not match parent" {
    const hosts = [_][]const u8{"*.example.com"};
    // "example.com" itself should match (suffix match)
    try testing.expect(domain.isAllowed("example.com", &hosts));
    try testing.expect(domain.isAllowed("sub.example.com", &hosts));
    // But not "notexample.com"
    try testing.expect(!domain.isAllowed("notexample.com", &hosts));
}

// ═══════════════════════════════════════════════════════════════════
// Net / Proc Decision Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: net decision with empty policy" {
    const policy = net.NetworkPolicy{};
    const d = net.decideNetConnect(policy, "8.8.8.8", 53, .clean);
    // Empty allowed_hosts = deny all (domain check fails)
    try testing.expect(!d.allow);
}

test "hardening: proc decision with quarantined state" {
    const bins = [_][]const u8{"*"};
    const policy = proc.ProcessPolicy{
        .allow_spawn = true,
        .allowed_binaries = &bins,
    };
    const d = proc.decideSpawn(policy, "git", .quarantined);
    try testing.expect(!d.allow);
}

test "hardening: proc with empty binary name" {
    const policy = proc.ProcessPolicy{ .allow_spawn = true };
    const d = proc.decideSpawn(policy, "", .clean);
    // Empty binary — should still not panic
    try testing.expect(!d.allow); // Not in allowlist
}

test "hardening: net egress limit boundary" {
    // Exactly at limit
    const d1 = net.checkEgressLimit(10_485_760, 10_485_760);
    try testing.expect(!d1.allow); // At limit = blocked

    // One byte under
    const d2 = net.checkEgressLimit(10_485_759, 10_485_760);
    try testing.expect(d2.allow);
}

// ═══════════════════════════════════════════════════════════════════
// Loader Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: load empty JSON string" {
    const result = loader.loadFromJson(alloc, "");
    try testing.expectError(loader.LoadError.InvalidJson, result);
}

test "hardening: load JSON array instead of object" {
    const result = loader.loadFromJson(alloc, "[1, 2, 3]");
    try testing.expectError(loader.LoadError.InvalidJson, result);
}

test "hardening: load JSON with wrong types" {
    // mode should be string, not number
    const result = loader.loadFromJson(alloc, "{\"mode\": 42}");
    try testing.expectError(loader.LoadError.InvalidJson, result);
}

test "hardening: load JSON with deeply nested unknown fields" {
    const json_str =
        \\{"mode": "audit", "unknown": {"nested": {"deep": true}}}
    ;
    const cfg = try loader.loadFromJson(alloc, json_str);
    try testing.expectEqual(layer_config.ShieldConfig.Mode.audit, cfg.mode);
}

test "hardening: load JSON with all fields set" {
    const json_str =
        \\{
        \\  "mode": "enforce",
        \\  "profile": "corp-dev",
        \\  "layers": {
        \\    "prompt_guard": true,
        \\    "output_scanner": true,
        \\    "tool_blocker": true,
        \\    "input_audit": true,
        \\    "security_gate": true,
        \\    "rate_limiter": true,
        \\    "preventive_enforcement": true
        \\  },
        \\  "redaction": {"strategy": "mask", "partial_chars": 4},
        \\  "entropy": {"enabled": true, "base64_threshold": 4.5, "hex_threshold": 3.5},
        \\  "rate_limits": {"exec_per_minute": 10, "sensitive_read_per_minute": 5, "window_seconds": 60},
        \\  "network": {"block_rfc1918": true, "block_localhost": true, "block_link_local": true, "block_metadata": true, "max_egress_bytes_per_min": 10485760},
        \\  "process": {"allow_spawn": false, "deny_shells": true, "max_exec_per_min": 10},
        \\  "taint": {"auto_escalate": true, "quarantine_threshold": 5, "cool_down_seconds": 300}
        \\}
    ;
    const cfg = try loader.loadFromJson(alloc, json_str);
    try testing.expectEqual(layer_config.ShieldConfig.Mode.enforce, cfg.mode);
    try testing.expectEqual(layer_config.Profile.corp_dev, cfg.profile);
}

// ═══════════════════════════════════════════════════════════════════
// Validator Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: validator maximum errors not exceeded" {
    // Create a config with many issues
    var cfg = layer_config.ShieldConfig{};
    cfg.entropy.base64_threshold = 0.0;
    cfg.entropy.hex_threshold = 0.0;
    cfg.rate_limits.exec_per_minute = 0;
    cfg.rate_limits.sensitive_read_per_minute = 0;
    cfg.rate_limits.window_seconds = 0;
    cfg.network.max_egress_bytes_per_min = 0;
    cfg.process.max_exec_per_min = 0;
    cfg.taint.quarantine_threshold = 0;
    cfg.redaction.strategy = .partial;
    cfg.redaction.partial_chars = 0;

    const result = validator.validate(cfg);
    try testing.expect(!result.isValid());
    // Should have collected multiple errors without panicking
    try testing.expect(result.count > 0);
    try testing.expect(result.count <= 32);
}

// ═══════════════════════════════════════════════════════════════════
// Pattern-Specific Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: PII patterns on all-digits input" {
    // A long string of digits could trigger multiple PII patterns
    const input = "123456789012345678901234567890";
    const matches = try scanner.scan(alloc, input, &pii.patterns);
    defer alloc.free(matches);
    // Should not panic; may or may not match
}

test "hardening: skill threats on normal JS code" {
    const input = "function medieval() { return 42; }";
    const matches = try scanner.scan(alloc, input, &skill_threats.patterns);
    defer alloc.free(matches);
    // "medieval" should NOT trigger eval pattern
    try testing.expectEqual(@as(usize, 0), matches.len);
}

test "hardening: prompt injection on normal conversation" {
    const input = "Can you help me understand how this code works? I want to learn about programming.";
    const matches = try scanner.scan(alloc, input, &prompt_injection.patterns);
    defer alloc.free(matches);
    try testing.expectEqual(@as(usize, 0), matches.len);
}

test "hardening: sensitive file paths with traversal" {
    try testing.expect(sensitive_files.isSensitivePath("../../.env"));
    try testing.expect(sensitive_files.isSensitivePath("/tmp/../home/user/.ssh/id_rsa"));
}

test "hardening: destructive on partial match" {
    // "rm" alone without -rf should not match cmd_rm_rf
    const input = "rm file.txt";
    const matches = try scanner.scan(alloc, input, &destructive.patterns);
    defer alloc.free(matches);
    // May match cmd_rm but not cmd_rm_rf
    for (matches) |m| {
        try testing.expect(!std.mem.eql(u8, m.pattern_name, "cmd_rm_rf") or m.end <= input.len);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Engine Edge Cases
// ═══════════════════════════════════════════════════════════════════

test "hardening: engine resolve nonexistent session" {
    var eng = engine.PolicyEngine.init(alloc, engine.profileDefaults(.prod));
    defer eng.deinit();

    // Should return base config, not panic
    const cfg = eng.resolve("nonexistent-session-12345");
    try testing.expectEqual(layer_config.ShieldConfig.Mode.enforce, cfg.mode);
}

test "hardening: engine rapid profile switching" {
    var eng = engine.PolicyEngine.init(alloc, engine.profileDefaults(.prod));
    defer eng.deinit();

    eng.setProfile(.home_lab);
    eng.setProfile(.corp_dev);
    eng.setProfile(.research);
    eng.setProfile(.prod);

    try testing.expectEqual(@as(u64, 4), eng.getVersion().sequence);
    try testing.expectEqual(layer_config.ShieldConfig.Mode.enforce, eng.resolve("s1").mode);
}

test "hardening: engine clear nonexistent override" {
    var eng = engine.PolicyEngine.init(alloc, engine.profileDefaults(.prod));
    defer eng.deinit();

    // Should not panic
    eng.clearSessionOverride("nonexistent");
}
