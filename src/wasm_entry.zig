// OpenClaw Shield — WASM Entry Point
//
// Thin wrappers that expose Zig decision functions with C ABI for
// WebAssembly consumption. Lives at src/ level so relative imports
// to enforcement/ work correctly.
//
// Build: zig build wasm

const std = @import("std");
const ip_ranges = @import("enforcement/ip_ranges.zig");
const net = @import("enforcement/net.zig");
const proc = @import("enforcement/proc.zig");
const reason_codes = @import("enforcement/reason_codes.zig");
const TaintState = reason_codes.TaintState;
const Decision = reason_codes.Decision;

// ── WASM Memory Allocator ─────────────────────────────────────────────

var wasm_allocator = std.heap.page_allocator;

/// Allocate bytes in WASM linear memory.
export fn wasm_alloc(len: u32) ?[*]u8 {
    const slice = wasm_allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

/// Free previously allocated WASM memory.
export fn wasm_free(ptr: [*]u8, len: u32) void {
    wasm_allocator.free(ptr[0..len]);
}

// ── Decision Result Encoding ──────────────────────────────────────────
//
// Packed u64:
//   bits  0:     allow (0=block, 1=allow)
//   bits  1-16:  reason_code (u16)
//   bits 17-18:  risk (0=low, 1=medium, 2=high)
//   bits 19-20:  taint_update (0=none, 1=clean, 2=tainted, 3=quarantined)

fn packDecision(d: Decision) u64 {
    var result: u64 = 0;
    if (d.allow) result |= 1;
    result |= @as(u64, @intFromEnum(d.reason_code)) << 1;
    result |= @as(u64, @intFromEnum(d.risk)) << 17;
    if (d.taint_update) |tu| {
        result |= @as(u64, @intFromEnum(tu) + 1) << 19;
    }
    return result;
}

// ── Network Decision ──────────────────────────────────────────────────

/// Decide whether a network connection should be allowed.
/// policy_flags: bit0=blockRFC1918, bit1=blockLocalhost, bit2=blockLinkLocal, bit3=blockMetadata
export fn decide_net_connect(
    host_ptr: [*]const u8,
    host_len: u32,
    port: u16,
    taint: u8,
    policy_flags: u8,
) u64 {
    const host = host_ptr[0..host_len];
    const taint_state: TaintState = switch (taint) {
        0 => .clean,
        1 => .tainted,
        2 => .quarantined,
        else => .quarantined,
    };

    if (taint_state == .quarantined) {
        return packDecision(Decision.quarantine());
    }

    // IP classification checks — domain/port checked TS-side
    const policy = net.NetworkPolicy{
        .allowed_hosts = &.{},
        .allowed_ports = &.{},
        .block_rfc1918 = (policy_flags & 1) != 0,
        .block_localhost = (policy_flags & 2) != 0,
        .block_link_local = (policy_flags & 4) != 0,
        .block_metadata = (policy_flags & 8) != 0,
    };

    if (ip_ranges.parseIp(host)) |ip_class| {
        switch (ip_class) {
            .metadata => if (policy.block_metadata) return packDecision(Decision.blocked(.net_metadata_blocked, .high)),
            .localhost => if (policy.block_localhost) return packDecision(Decision.blocked(.net_localhost_blocked, .medium)),
            .link_local => if (policy.block_link_local) return packDecision(Decision.blocked(.net_link_local_blocked, .medium)),
            .rfc1918 => if (policy.block_rfc1918) return packDecision(Decision.blocked(.net_rfc1918_blocked, .medium)),
            .public => {},
        }
    } else {
        if (ip_ranges.isLocalhost(host) and policy.block_localhost) {
            return packDecision(Decision.blocked(.net_localhost_blocked, .medium));
        }
    }

    _ = port;
    return packDecision(Decision.allowed());
}

// ── Process Decision ──────────────────────────────────────────────────

/// Decide whether a subprocess spawn should be allowed.
export fn decide_spawn(
    binary_ptr: [*]const u8,
    binary_len: u32,
    taint: u8,
    allow_spawn: u8,
    deny_shells: u8,
) u64 {
    const binary = binary_ptr[0..binary_len];
    const taint_state: TaintState = switch (taint) {
        0 => .clean,
        1 => .tainted,
        2 => .quarantined,
        else => .quarantined,
    };

    const policy = proc.ProcessPolicy{
        .allow_spawn = allow_spawn != 0,
        .allowed_binaries = &[_][]const u8{"*"},
        .deny_shells = deny_shells != 0,
        .max_exec_per_min = 999,
    };

    return packDecision(proc.decideSpawn(policy, binary, taint_state));
}

// ── IP Classification ─────────────────────────────────────────────────

/// Classify IP: 0=public, 1=rfc1918, 2=localhost, 3=link_local, 4=metadata, 255=not-IP
export fn classify_ip(host_ptr: [*]const u8, host_len: u32) u8 {
    const host = host_ptr[0..host_len];
    if (ip_ranges.parseIp(host)) |cls| {
        return @intFromEnum(cls);
    }
    return 255;
}

/// Return version as packed u32: major.minor.patch
export fn version() u32 {
    return (0 << 16) | (3 << 8) | 0; // 0.3.0
}
