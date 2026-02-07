// OpenClaw Shield — Policy Validator
//
// Validates a ShieldConfig against structural and semantic constraints.
// Returns a list of validation errors with field paths and messages.

const std = @import("std");
const config = @import("../layers/config.zig");
const ShieldConfig = config.ShieldConfig;

// ── Validation Error ────────────────────────────────────────────────

pub const ValidationError = struct {
    field: []const u8,
    message: []const u8,
    severity: ErrorSeverity = .@"error",

    pub const ErrorSeverity = enum { warning, @"error" };
};

/// Maximum number of validation errors collected in a single pass.
const MAX_ERRORS = 32;

pub const ValidationResult = struct {
    errors: [MAX_ERRORS]ValidationError = undefined,
    count: usize = 0,

    pub fn isValid(self: ValidationResult) bool {
        // Valid if no errors (warnings are OK)
        for (self.errors[0..self.count]) |e| {
            if (e.severity == .@"error") return false;
        }
        return true;
    }

    pub fn hasWarnings(self: ValidationResult) bool {
        for (self.errors[0..self.count]) |e| {
            if (e.severity == .warning) return true;
        }
        return false;
    }

    pub fn errorCount(self: ValidationResult) usize {
        var c: usize = 0;
        for (self.errors[0..self.count]) |e| {
            if (e.severity == .@"error") c += 1;
        }
        return c;
    }

    pub fn warningCount(self: ValidationResult) usize {
        var c: usize = 0;
        for (self.errors[0..self.count]) |e| {
            if (e.severity == .warning) c += 1;
        }
        return c;
    }

    fn addError(self: *ValidationResult, field: []const u8, message: []const u8) void {
        if (self.count < MAX_ERRORS) {
            self.errors[self.count] = .{ .field = field, .message = message };
            self.count += 1;
        }
    }

    fn addWarning(self: *ValidationResult, field: []const u8, message: []const u8) void {
        if (self.count < MAX_ERRORS) {
            self.errors[self.count] = .{ .field = field, .message = message, .severity = .warning };
            self.count += 1;
        }
    }
};

// ── Validator ───────────────────────────────────────────────────────

/// Validate a ShieldConfig. Returns a result with all errors and warnings.
pub fn validate(cfg: ShieldConfig) ValidationResult {
    var result = ValidationResult{};

    // ── Entropy thresholds ──────────────────────────────────────────
    if (cfg.entropy.enabled) {
        if (cfg.entropy.base64_threshold <= 0.0 or cfg.entropy.base64_threshold > 8.0) {
            result.addError("entropy.base64_threshold", "must be between 0 and 8 (Shannon entropy range)");
        }
        if (cfg.entropy.hex_threshold <= 0.0 or cfg.entropy.hex_threshold > 8.0) {
            result.addError("entropy.hex_threshold", "must be between 0 and 8 (Shannon entropy range)");
        }
        if (cfg.entropy.base64_threshold < 3.0) {
            result.addWarning("entropy.base64_threshold", "below 3.0 may cause excessive false positives");
        }
    }

    // ── Rate limits ─────────────────────────────────────────────────
    if (cfg.rate_limits.exec_per_minute == 0) {
        result.addError("rate_limits.exec_per_minute", "must be at least 1");
    }
    if (cfg.rate_limits.sensitive_read_per_minute == 0) {
        result.addError("rate_limits.sensitive_read_per_minute", "must be at least 1");
    }
    if (cfg.rate_limits.window_seconds == 0) {
        result.addError("rate_limits.window_seconds", "must be at least 1");
    }
    if (cfg.rate_limits.window_seconds > 3600) {
        result.addWarning("rate_limits.window_seconds", "window over 1 hour may use excessive memory");
    }

    // ── Network settings ────────────────────────────────────────────
    if (cfg.network.max_egress_bytes_per_min == 0) {
        result.addError("network.max_egress_bytes_per_min", "must be at least 1");
    }
    // Validate ports are in valid range (compile-time u16 already constrains 0-65535)
    for (cfg.network.allowed_ports) |port| {
        if (port == 0) {
            result.addWarning("network.allowed_ports", "port 0 is unusual; ensure this is intentional");
            break;
        }
    }

    // Warn on overly permissive configurations
    if (cfg.network.allowed_hosts.len > 0) {
        for (cfg.network.allowed_hosts) |host| {
            if (std.mem.eql(u8, host, "*") and cfg.mode == .enforce) {
                if (!cfg.network.block_rfc1918 or !cfg.network.block_metadata) {
                    result.addWarning("network.allowed_hosts", "wildcard host with RFC1918/metadata unblocked is risky in enforce mode");
                }
                break;
            }
        }
    }

    // ── Process settings ────────────────────────────────────────────
    if (cfg.process.allow_spawn and !cfg.process.deny_shells) {
        result.addWarning("process", "allow_spawn=true with deny_shells=false permits shell access");
    }
    if (cfg.process.max_exec_per_min == 0) {
        result.addError("process.max_exec_per_min", "must be at least 1");
    }

    // ── Taint settings ──────────────────────────────────────────────
    if (cfg.taint.quarantine_threshold == 0) {
        result.addError("taint.quarantine_threshold", "must be at least 1");
    }
    if (cfg.taint.cool_down_seconds == 0 and cfg.taint.auto_escalate) {
        result.addWarning("taint.cool_down_seconds", "0 cool-down with auto-escalate means no de-escalation path");
    }

    // ── Redaction ───────────────────────────────────────────────────
    if (cfg.redaction.strategy == .partial and cfg.redaction.partial_chars == 0) {
        result.addError("redaction.partial_chars", "must be at least 1 when using partial strategy");
    }

    // ── Cross-field consistency ─────────────────────────────────────
    // Audit mode with preventive enforcement is contradictory
    if (cfg.mode == .audit and cfg.layers.preventive_enforcement) {
        result.addWarning("layers.preventive_enforcement", "preventive enforcement has no effect in audit mode");
    }

    return result;
}

/// Quick check: is this config valid? (No errors, warnings are OK)
pub fn isValid(cfg: ShieldConfig) bool {
    return validate(cfg).isValid();
}

// ── Tests ───────────────────────────────────────────────────────────

test "default config is valid" {
    const cfg = ShieldConfig{};
    const result = validate(cfg);
    try std.testing.expect(result.isValid());
}

test "bad entropy threshold" {
    var cfg = ShieldConfig{};
    cfg.entropy.base64_threshold = 0.0;
    const result = validate(cfg);
    try std.testing.expect(!result.isValid());
    try std.testing.expect(result.errorCount() >= 1);
}

test "entropy below 3.0 warns" {
    var cfg = ShieldConfig{};
    cfg.entropy.base64_threshold = 2.5;
    const result = validate(cfg);
    // 2.5 > 0 and <= 8, so no error, but should warn
    try std.testing.expect(result.hasWarnings());
}

test "zero rate limits are errors" {
    var cfg = ShieldConfig{};
    cfg.rate_limits.exec_per_minute = 0;
    cfg.rate_limits.sensitive_read_per_minute = 0;
    const result = validate(cfg);
    try std.testing.expect(!result.isValid());
    try std.testing.expect(result.errorCount() >= 2);
}

test "zero max_egress is error" {
    var cfg = ShieldConfig{};
    cfg.network.max_egress_bytes_per_min = 0;
    const result = validate(cfg);
    try std.testing.expect(!result.isValid());
}

test "spawn + no deny_shells warns" {
    var cfg = ShieldConfig{};
    cfg.process.allow_spawn = true;
    cfg.process.deny_shells = false;
    const result = validate(cfg);
    try std.testing.expect(result.isValid()); // warning, not error
    try std.testing.expect(result.hasWarnings());
}

test "zero quarantine_threshold is error" {
    var cfg = ShieldConfig{};
    cfg.taint.quarantine_threshold = 0;
    const result = validate(cfg);
    try std.testing.expect(!result.isValid());
}

test "partial strategy with 0 partial_chars is error" {
    var cfg = ShieldConfig{};
    cfg.redaction.strategy = .partial;
    cfg.redaction.partial_chars = 0;
    const result = validate(cfg);
    try std.testing.expect(!result.isValid());
}

test "audit mode with preventive enforcement warns" {
    var cfg = ShieldConfig{};
    cfg.mode = .audit;
    cfg.layers.preventive_enforcement = true;
    const result = validate(cfg);
    try std.testing.expect(result.isValid()); // warning, not error
    try std.testing.expect(result.hasWarnings());
}

test "zero cool_down with auto_escalate warns" {
    var cfg = ShieldConfig{};
    cfg.taint.cool_down_seconds = 0;
    cfg.taint.auto_escalate = true;
    const result = validate(cfg);
    try std.testing.expect(result.hasWarnings());
}

test "large window_seconds warns" {
    var cfg = ShieldConfig{};
    cfg.rate_limits.window_seconds = 7200;
    const result = validate(cfg);
    try std.testing.expect(result.hasWarnings());
}

test "isValid convenience function" {
    try std.testing.expect(isValid(ShieldConfig{}));
    var bad = ShieldConfig{};
    bad.taint.quarantine_threshold = 0;
    try std.testing.expect(!isValid(bad));
}
