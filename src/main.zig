// OpenClaw Shield — CLI Entry Point
//
// Standalone command-line tool for scanning and redacting secrets/PII.
// Usage:
//   ocshield scan <file>         Scan a file for secrets and PII
//   ocshield redact <file>       Scan and redact, output to stdout
//   ocshield check-path <path>   Check if a file path is sensitive
//   ocshield entropy <file>      Analyze entropy of a file

const std = @import("std");
const lib = @import("lib.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "scan")) {
        try cmdScan(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "redact")) {
        try cmdRedact(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "check-path")) {
        try cmdCheckPath(args[2..]);
    } else if (std.mem.eql(u8, command, "entropy")) {
        try cmdEntropy(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version")) {
        const stdout = std.io.getStdOut().writer();
        try stdout.print("{s} v{s}\n", .{ lib.name, lib.version });
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("Unknown command: {s}\n\n", .{command});
        printUsage();
    }
}

fn printUsage() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\{s} v{s}
        \\
        \\Security scanner for secrets, PII, and destructive commands.
        \\Based on openclaw-shield by Knostic (https://knostic.ai/)
        \\
        \\USAGE:
        \\  ocshield <command> [args]
        \\
        \\COMMANDS:
        \\  scan <file>         Scan a file for secrets, PII, and destructive commands
        \\  redact <file>       Scan and redact sensitive content, output to stdout
        \\  check-path <path>   Check if a file path matches sensitive patterns
        \\  entropy <file>      Analyze entropy of strings in a file
        \\  version             Show version
        \\  help                Show this help
        \\
        \\EXAMPLES:
        \\  ocshield scan config.yml
        \\  ocshield redact .env > .env.safe
        \\  ocshield check-path /home/user/.ssh/id_rsa
        \\  ocshield entropy suspicious-file.txt
        \\
    , .{ lib.name, lib.version }) catch {};
}

fn cmdScan(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    const input = try readInput(allocator, args);
    defer allocator.free(input);

    const matches = try lib.scan(allocator, input, lib.allPatterns());
    defer allocator.free(matches);

    if (matches.len == 0) {
        try stdout.print("No sensitive content detected.\n", .{});
        return;
    }

    try stdout.print("Found {d} match(es):\n\n", .{matches.len});
    for (matches) |m| {
        const preview_text = m.preview(input);
        try stdout.print("  [{s}] {s}: \"{s}...\" (pos {d}-{d})\n", .{
            @tagName(m.severity),
            m.pattern_name,
            preview_text,
            m.start,
            m.end,
        });
    }

    // Summary by category
    var secret_count: usize = 0;
    var pii_count: usize = 0;
    var destructive_count: usize = 0;
    for (matches) |m| {
        switch (m.category) {
            .secret => secret_count += 1,
            .pii => pii_count += 1,
            .destructive => destructive_count += 1,
            else => {},
        }
    }
    try stdout.print("\nSummary: {d} secret(s), {d} PII, {d} destructive command(s)\n", .{
        secret_count,
        pii_count,
        destructive_count,
    });
}

fn cmdRedact(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();
    const input = try readInput(allocator, args);
    defer allocator.free(input);

    var result = try lib.scanAndRedact(allocator, input, lib.allPatterns(), .{});
    defer result.deinit();

    try stdout.writeAll(result.redacted);

    if (result.matches.len > 0) {
        try stderr.print("\n[ocshield] Redacted {d} match(es)\n", .{result.matches.len});
    }
}

fn cmdCheckPath(args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();

    if (args.len == 0) {
        try stdout.print("Usage: ocshield check-path <file-path>\n", .{});
        return;
    }

    const path = args[0];
    if (lib.matchSensitivePath(path)) |pattern_name| {
        try stdout.print("SENSITIVE: {s} (matched: {s})\n", .{ path, pattern_name });
    } else {
        try stdout.print("OK: {s} (no sensitive pattern matched)\n", .{path});
    }
}

fn cmdEntropy(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    const input = try readInput(allocator, args);
    defer allocator.free(input);

    // Overall entropy
    const overall = lib.shannonEntropy(input);
    try stdout.print("Overall entropy: {d:.2} bits/char ({d} bytes)\n\n", .{ overall, input.len });

    // High-entropy segments
    const flags = try lib.detectHighEntropy(allocator, input, .{});
    defer allocator.free(flags);

    if (flags.len == 0) {
        try stdout.print("No high-entropy segments detected.\n", .{});
        return;
    }

    try stdout.print("High-entropy segments ({d}):\n", .{flags.len});
    for (flags) |f| {
        const segment = input[f.start..f.end];
        const preview = if (segment.len > 40) segment[0..40] else segment;
        try stdout.print("  [{s}] {d:.2} bits/char at {d}-{d}: \"{s}...\"\n", .{
            @tagName(f.encoding),
            f.entropy,
            f.start,
            f.end,
            preview,
        });
    }
}

fn readInput(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    if (args.len > 0) {
        // Read from file
        const file = try std.fs.cwd().openFile(args[0], .{});
        defer file.close();
        return try file.readToEndAlloc(allocator, 10 * 1024 * 1024); // 10MB max
    } else {
        // Read from stdin
        const stdin = std.io.getStdIn();
        return try stdin.readToEndAlloc(allocator, 10 * 1024 * 1024);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

test {
    _ = lib;
}
