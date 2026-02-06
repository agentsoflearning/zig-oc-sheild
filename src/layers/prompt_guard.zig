// OpenClaw Shield — L1: Prompt Guard
//
// Generates the security policy prompt injected into the agent's system context
// via the before_agent_start hook.
//
// Based on openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const config_mod = @import("config.zig");
const ShieldConfig = config_mod.ShieldConfig;

/// Generate the security policy prompt to prepend to the agent's context.
pub fn generateSecurityPrompt(allocator: Allocator, config: ShieldConfig) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();

    try w.writeAll("<oc-shield-security-policy>\n");
    try w.writeAll("CRITICAL SYSTEM REQUIREMENT — OpenClaw Shield is active.\n\n");

    if (config.layers.security_gate) {
        try w.writeAll(
            \\You have a tool called `oc_shield_gate`. You MUST call it in these situations:
            \\
            \\RULE 1 — SHELL COMMANDS:
            \\Before calling exec/bash, call oc_shield_gate with the `command` parameter.
            \\
            \\RULE 2 — FILE READS:
            \\Before calling the read tool on ANY file, call oc_shield_gate with the `file_path` parameter.
            \\
            \\WORKFLOW:
            \\1. BEFORE calling exec or read, call oc_shield_gate with the appropriate parameter.
            \\2. Read the oc_shield_gate response.
            \\3. If status is DENIED — do NOT proceed. Report the denial to the user.
            \\4. If status is ALLOWED — proceed with the tool call normally.
            \\
            \\NEVER skip the oc_shield_gate step. NEVER call exec or read without calling oc_shield_gate first.
            \\
            \\
        );
    }

    try w.writeAll("ADDITIONAL RULES:\n");
    try w.writeAll("- Never output raw API keys, tokens, passwords, or credentials.\n");
    try w.writeAll("- Never output unmasked PII (SSNs, credit cards, emails, phone numbers).\n");

    if (config.layers.security_gate) {
        try w.writeAll("- If oc_shield_gate flags a file as containing sensitive data, summarize what\n");
        try w.writeAll("  the file contains WITHOUT showing the raw sensitive values.\n");
    }

    if (config.layers.output_scanner) {
        try w.writeAll("- Tool output is automatically scanned and redacted by the shield.\n");
    }

    if (config.layers.tool_blocker) {
        try w.writeAll("- Destructive commands (rm, format, dd, etc.) are automatically blocked.\n");
    }

    if (config.layers.rate_limiter) {
        try w.writeAll("- Rapid-fire sensitive operations may be rate-limited.\n");
    }

    // Mode note
    switch (config.mode) {
        .enforce => try w.writeAll("\nMode: ENFORCE — violations are blocked and redacted.\n"),
        .audit => try w.writeAll("\nMode: AUDIT — violations are logged but not blocked.\n"),
    }

    try w.writeAll("\nSecurity shield by OpenClaw Shield (Zig) — ");
    try w.writeAll("based on openclaw-shield by Knostic (https://knostic.ai/)\n");
    try w.writeAll("</oc-shield-security-policy>");

    return out.toOwnedSlice();
}

/// Return the active layer summary as a human-readable string.
pub fn activeLayerSummary(allocator: Allocator, config: ShieldConfig) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();

    const layers = [_]struct { flag: bool, label: []const u8 }{
        .{ .flag = config.layers.prompt_guard, .label = "L1:prompt-guard" },
        .{ .flag = config.layers.output_scanner, .label = "L2:output-scanner" },
        .{ .flag = config.layers.tool_blocker, .label = "L3:tool-blocker" },
        .{ .flag = config.layers.input_audit, .label = "L4:input-audit" },
        .{ .flag = config.layers.security_gate, .label = "L5:security-gate" },
        .{ .flag = config.layers.rate_limiter, .label = "L6:rate-limiter" },
    };

    var first = true;
    for (layers) |layer| {
        if (layer.flag) {
            if (!first) try w.writeAll(", ");
            try w.writeAll(layer.label);
            first = false;
        }
    }

    return out.toOwnedSlice();
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "generateSecurityPrompt — default config" {
    const prompt = try generateSecurityPrompt(testing.allocator, .{});
    defer testing.allocator.free(prompt);

    try testing.expect(std.mem.indexOf(u8, prompt, "<oc-shield-security-policy>") != null);
    try testing.expect(std.mem.indexOf(u8, prompt, "oc_shield_gate") != null);
    try testing.expect(std.mem.indexOf(u8, prompt, "ENFORCE") != null);
    try testing.expect(std.mem.indexOf(u8, prompt, "Knostic") != null);
}

test "generateSecurityPrompt — audit mode" {
    const prompt = try generateSecurityPrompt(testing.allocator, .{ .mode = .audit });
    defer testing.allocator.free(prompt);

    try testing.expect(std.mem.indexOf(u8, prompt, "AUDIT") != null);
}

test "generateSecurityPrompt — gate disabled" {
    var config = ShieldConfig{};
    config.layers.security_gate = false;
    const prompt = try generateSecurityPrompt(testing.allocator, config);
    defer testing.allocator.free(prompt);

    // Should not mention oc_shield_gate tool
    try testing.expect(std.mem.indexOf(u8, prompt, "oc_shield_gate") == null);
}

test "activeLayerSummary — all active" {
    const summary = try activeLayerSummary(testing.allocator, .{});
    defer testing.allocator.free(summary);

    try testing.expect(std.mem.indexOf(u8, summary, "L1:prompt-guard") != null);
    try testing.expect(std.mem.indexOf(u8, summary, "L6:rate-limiter") != null);
}

test "activeLayerSummary — some disabled" {
    var config = ShieldConfig{};
    config.layers.rate_limiter = false;
    config.layers.tool_blocker = false;
    const summary = try activeLayerSummary(testing.allocator, config);
    defer testing.allocator.free(summary);

    try testing.expect(std.mem.indexOf(u8, summary, "L3:tool-blocker") == null);
    try testing.expect(std.mem.indexOf(u8, summary, "L6:rate-limiter") == null);
    try testing.expect(std.mem.indexOf(u8, summary, "L1:prompt-guard") != null);
}
