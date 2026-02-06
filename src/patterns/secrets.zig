// OpenClaw Shield — Secret Detection Patterns
//
// Ported from openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0
// Original: 15 secret patterns covering AWS, Stripe, GitHub, OpenAI,
// Anthropic, Slack, SendGrid, npm, private keys, JWTs, Bearer tokens.

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const Pattern = pattern.Pattern;

// ── Pattern Table ──────────────────────────────────────────────────────

pub const patterns = [_]Pattern{
    .{ .name = "aws_access_key", .category = .secret, .severity = .critical, .matchAt = matchAwsAccessKey },
    .{ .name = "aws_secret_key", .category = .secret, .severity = .critical, .matchAt = matchAwsSecretKey },
    .{ .name = "stripe_key", .category = .secret, .severity = .critical, .matchAt = matchStripeKey },
    .{ .name = "github_token", .category = .secret, .severity = .critical, .matchAt = matchGithubToken },
    .{ .name = "github_fine_grained_pat", .category = .secret, .severity = .critical, .matchAt = matchGithubFinePat },
    .{ .name = "anthropic_key", .category = .secret, .severity = .critical, .matchAt = matchAnthropicKey },
    .{ .name = "openai_key", .category = .secret, .severity = .critical, .matchAt = matchOpenaiKey },
    .{ .name = "slack_token", .category = .secret, .severity = .critical, .matchAt = matchSlackToken },
    .{ .name = "slack_webhook", .category = .secret, .severity = .critical, .matchAt = matchSlackWebhook },
    .{ .name = "sendgrid_key", .category = .secret, .severity = .critical, .matchAt = matchSendgridKey },
    .{ .name = "npm_token", .category = .secret, .severity = .critical, .matchAt = matchNpmToken },
    .{ .name = "private_key", .category = .secret, .severity = .critical, .matchAt = matchPrivateKey },
    .{ .name = "jwt", .category = .secret, .severity = .critical, .matchAt = matchJwt },
    .{ .name = "bearer_token", .category = .secret, .severity = .critical, .matchAt = matchBearerToken },
    .{ .name = "generic_api_key", .category = .secret, .severity = .warning, .matchAt = matchGenericApiKey },
};

// ── Match Functions ────────────────────────────────────────────────────

/// AKIA[0-9A-Z]{16}
fn matchAwsAccessKey(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "AKIA")) return null;
    if (pos + 20 > input.len) return null;
    for (input[pos + 4 ..][0..16]) |c| {
        if (!pattern.isUpperAlphaDigit(c)) return null;
    }
    return 20;
}

/// (?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?
fn matchAwsSecretKey(input: []const u8, pos: usize) ?usize {
    const keywords = [_][]const u8{ "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY" };
    const kw_len = pattern.matchAlternatives(input, pos, &keywords) orelse return null;
    var p = pos + kw_len;
    p = pattern.skipWhitespace(input, p);
    if (p >= input.len or (input[p] != ':' and input[p] != '=')) return null;
    p += 1;
    p = pattern.skipWhitespace(input, p);
    // Optional opening quote
    const has_quote = p < input.len and (input[p] == '"' or input[p] == '\'');
    if (has_quote) p += 1;
    // Value: [A-Za-z0-9/+=]{40}
    const val_start = p;
    const val_count = pattern.countWhile(input, p, pattern.isBase64Char);
    if (val_count < 40) return null;
    p = val_start + val_count;
    // Optional closing quote
    if (has_quote and p < input.len and (input[p] == '"' or input[p] == '\'')) p += 1;
    return p - pos;
}

/// [sr]k[-_](?:live|test)[-_][a-zA-Z0-9]{20,}
fn matchStripeKey(input: []const u8, pos: usize) ?usize {
    if (pos + 28 > input.len) return null; // minimum: sk_live_<20 chars>
    const c0 = input[pos];
    if (c0 != 's' and c0 != 'r') return null;
    if (input[pos + 1] != 'k') return null;
    if (input[pos + 2] != '-' and input[pos + 2] != '_') return null;
    var p = pos + 3;
    const modes = [_][]const u8{ "live", "test" };
    const mode_len = pattern.matchAlternatives(input, p, &modes) orelse return null;
    p += mode_len;
    if (p >= input.len or (input[p] != '-' and input[p] != '_')) return null;
    p += 1;
    const val_count = pattern.countWhile(input, p, std.ascii.isAlphanumeric);
    if (val_count < 20) return null;
    p += val_count;
    return p - pos;
}

/// gh[pousr]_[a-zA-Z0-9]{36}
fn matchGithubToken(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "gh")) return null;
    if (pos + 40 > input.len) return null; // "gh" + 1 + "_" + 36
    const kind = input[pos + 2];
    if (kind != 'p' and kind != 'o' and kind != 'u' and kind != 's' and kind != 'r') return null;
    if (input[pos + 3] != '_') return null;
    for (input[pos + 4 ..][0..36]) |c| {
        if (!std.ascii.isAlphanumeric(c)) return null;
    }
    return 40;
}

/// github_pat_[a-zA-Z0-9_]{22,}
fn matchGithubFinePat(input: []const u8, pos: usize) ?usize {
    const prefix = "github_pat_";
    if (!pattern.startsWith(input, pos, prefix)) return null;
    var p = pos + prefix.len;
    const val_count = pattern.countWhile(input, p, pattern.isAlnumOrUnderscore);
    if (val_count < 22) return null;
    p += val_count;
    return p - pos;
}

/// sk-ant-[a-zA-Z0-9_-]{20,}
/// NOTE: Must be checked BEFORE openai_key since "sk-" is a prefix of "sk-ant-"
fn matchAnthropicKey(input: []const u8, pos: usize) ?usize {
    const prefix = "sk-ant-";
    if (!pattern.startsWith(input, pos, prefix)) return null;
    var p = pos + prefix.len;
    const val_count = pattern.countWhile(input, p, pattern.isAlnumOrUnderscoreOrDash);
    if (val_count < 20) return null;
    p += val_count;
    return p - pos;
}

/// sk-[a-zA-Z0-9]{20,}  (but NOT sk-ant-)
fn matchOpenaiKey(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "sk-")) return null;
    // Exclude Anthropic keys
    if (pattern.startsWith(input, pos, "sk-ant-")) return null;
    var p = pos + 3;
    const val_count = pattern.countWhile(input, p, std.ascii.isAlphanumeric);
    if (val_count < 20) return null;
    p += val_count;
    return p - pos;
}

/// xox[bpras]-[a-zA-Z0-9-]{10,}
fn matchSlackToken(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "xox")) return null;
    if (pos + 4 >= input.len) return null;
    const kind = input[pos + 3];
    if (kind != 'b' and kind != 'p' and kind != 'r' and kind != 'a' and kind != 's') return null;
    if (pos + 5 > input.len or input[pos + 4] != '-') return null;
    var p = pos + 5;
    const val_count = pattern.countWhile(input, p, pattern.isAlnumOrDash);
    if (val_count < 10) return null;
    p += val_count;
    return p - pos;
}

/// hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+
fn matchSlackWebhook(input: []const u8, pos: usize) ?usize {
    const prefix = "hooks.slack.com/services/T";
    if (!pattern.startsWith(input, pos, prefix)) return null;
    var p = pos + prefix.len;
    // T segment
    const t_count = pattern.countWhile(input, p, pattern.isAlnumOrUnderscore);
    if (t_count == 0) return null;
    p += t_count;
    // /B
    if (p + 2 > input.len or input[p] != '/' or input[p + 1] != 'B') return null;
    p += 2;
    // B segment
    const b_count = pattern.countWhile(input, p, pattern.isAlnumOrUnderscore);
    if (b_count == 0) return null;
    p += b_count;
    // /
    if (p >= input.len or input[p] != '/') return null;
    p += 1;
    // Final segment
    const f_count = pattern.countWhile(input, p, pattern.isAlnumOrUnderscore);
    if (f_count == 0) return null;
    p += f_count;
    return p - pos;
}

/// SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
fn matchSendgridKey(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "SG.")) return null;
    var p = pos + 3;
    // First segment: exactly 22 chars
    if (p + 22 > input.len) return null;
    for (input[p..][0..22]) |c| {
        if (!pattern.isAlnumOrUnderscoreOrDash(c)) return null;
    }
    p += 22;
    // Dot
    if (p >= input.len or input[p] != '.') return null;
    p += 1;
    // Second segment: exactly 43 chars
    if (p + 43 > input.len) return null;
    for (input[p..][0..43]) |c| {
        if (!pattern.isAlnumOrUnderscoreOrDash(c)) return null;
    }
    p += 43;
    return p - pos;
}

/// npm_[a-zA-Z0-9]{36,}
fn matchNpmToken(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "npm_")) return null;
    var p = pos + 4;
    const val_count = pattern.countWhile(input, p, std.ascii.isAlphanumeric);
    if (val_count < 36) return null;
    p += val_count;
    return p - pos;
}

/// -----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----
fn matchPrivateKey(input: []const u8, pos: usize) ?usize {
    const begin = "-----BEGIN ";
    if (!pattern.startsWith(input, pos, begin)) return null;
    var p = pos + begin.len;
    // Optional key type
    const key_types = [_][]const u8{ "RSA ", "EC ", "DSA ", "OPENSSH " };
    if (pattern.matchAlternatives(input, p, &key_types)) |klen| {
        p += klen;
    }
    const suffix = "PRIVATE KEY-----";
    if (!pattern.startsWith(input, p, suffix)) return null;
    p += suffix.len;
    return p - pos;
}

/// eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}
fn matchJwt(input: []const u8, pos: usize) ?usize {
    if (!pattern.startsWith(input, pos, "eyJ")) return null;
    var p = pos + 3;
    // Header segment
    const h_count = pattern.countWhile(input, p, pattern.isBase64UrlChar);
    if (h_count < 10) return null;
    p += h_count;
    // Dot
    if (p >= input.len or input[p] != '.') return null;
    p += 1;
    // Payload: must start with eyJ
    if (!pattern.startsWith(input, p, "eyJ")) return null;
    p += 3;
    const pay_count = pattern.countWhile(input, p, pattern.isBase64UrlChar);
    if (pay_count < 10) return null;
    p += pay_count;
    // Dot
    if (p >= input.len or input[p] != '.') return null;
    p += 1;
    // Signature
    const sig_count = pattern.countWhile(input, p, pattern.isBase64UrlChar);
    if (sig_count < 10) return null;
    p += sig_count;
    return p - pos;
}

/// (?:Authorization|authorization)\s*[:=]\s*["']?Bearer\s+[a-zA-Z0-9_.\\-/+=]{20,}
fn matchBearerToken(input: []const u8, pos: usize) ?usize {
    const keywords = [_][]const u8{ "Authorization", "authorization" };
    const kw_len = pattern.matchAlternatives(input, pos, &keywords) orelse return null;
    var p = pos + kw_len;
    p = pattern.skipWhitespace(input, p);
    if (p >= input.len or (input[p] != ':' and input[p] != '=')) return null;
    p += 1;
    p = pattern.skipWhitespace(input, p);
    // Optional quote
    if (p < input.len and (input[p] == '"' or input[p] == '\'')) p += 1;
    // "Bearer "
    if (!pattern.startsWith(input, p, "Bearer ")) return null;
    p += 7;
    // Skip additional spaces
    while (p < input.len and input[p] == ' ') p += 1;
    // Token value
    const val_count = pattern.countWhile(input, p, pattern.isTokenChar);
    if (val_count < 20) return null;
    p += val_count;
    return p - pos;
}

/// (?:api[-_]?key|api[-_]?secret|secret[-_]?key)\s*[:=]\s*["']?[a-zA-Z0-9_.\\-/+=]{20,}["']?
fn matchGenericApiKey(input: []const u8, pos: usize) ?usize {
    // Try each keyword variant
    const kw_len = matchGenericKeyword(input, pos) orelse return null;
    var p = pos + kw_len;
    p = pattern.skipWhitespace(input, p);
    if (p >= input.len or (input[p] != ':' and input[p] != '=')) return null;
    p += 1;
    p = pattern.skipWhitespace(input, p);
    // Optional opening quote
    const has_quote = p < input.len and (input[p] == '"' or input[p] == '\'');
    if (has_quote) p += 1;
    // Value
    const val_count = pattern.countWhile(input, p, pattern.isTokenChar);
    if (val_count < 20) return null;
    p += val_count;
    // Optional closing quote
    if (has_quote and p < input.len and (input[p] == '"' or input[p] == '\'')) p += 1;
    return p - pos;
}

/// Match api_key, api-key, apikey, api_secret, api-secret, apisecret, secret_key, secret-key, secretkey
/// Case-insensitive
fn matchGenericKeyword(input: []const u8, pos: usize) ?usize {
    // Lowercase the relevant portion for comparison
    const keywords = [_]struct { parts: []const []const u8 }{
        .{ .parts = &[_][]const u8{ "api", "key" } },
        .{ .parts = &[_][]const u8{ "api", "secret" } },
        .{ .parts = &[_][]const u8{ "secret", "key" } },
    };

    for (keywords) |kw| {
        if (matchKeywordParts(input, pos, kw.parts)) |len| return len;
    }
    return null;
}

fn matchKeywordParts(input: []const u8, pos: usize, parts: []const []const u8) ?usize {
    var p = pos;
    for (parts, 0..) |part, i| {
        // Match part case-insensitively
        if (p + part.len > input.len) return null;
        for (input[p..][0..part.len], part) |ic, pc| {
            if (std.ascii.toLower(ic) != pc) return null;
        }
        p += part.len;
        // Between parts: optional separator [-_]
        if (i + 1 < parts.len) {
            if (p < input.len and (input[p] == '-' or input[p] == '_')) {
                p += 1;
            }
        }
    }
    return p - pos;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "aws_access_key" {
    try testing.expectEqual(@as(?usize, 20), matchAwsAccessKey("AKIA1234567890ABCDEF", 0));
    try testing.expectEqual(@as(?usize, 20), matchAwsAccessKey("key=AKIA1234567890ABCDEF rest", 4));
    try testing.expectEqual(@as(?usize, null), matchAwsAccessKey("AKIB1234567890ABCDEF", 0));
    try testing.expectEqual(@as(?usize, null), matchAwsAccessKey("AKIA12345678", 0)); // too short
    try testing.expectEqual(@as(?usize, null), matchAwsAccessKey("AKIA1234567890abcdef", 0)); // lowercase
}

test "aws_secret_key" {
    const sample = "aws_secret_access_key = ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abc";
    try testing.expect(matchAwsSecretKey(sample, 0) != null);
    const sample2 = "AWS_SECRET_ACCESS_KEY:ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abc";
    try testing.expect(matchAwsSecretKey(sample2, 0) != null);
    try testing.expectEqual(@as(?usize, null), matchAwsSecretKey("not_a_key", 0));
}

test "stripe_key" {
    try testing.expect(matchStripeKey("sk_live_abcdefghij1234567890", 0) != null);
    try testing.expect(matchStripeKey("rk-test-abcdefghij1234567890", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchStripeKey("sk_live_short", 0));
    try testing.expectEqual(@as(?usize, null), matchStripeKey("xk_live_abcdefghij1234567890", 0));
}

test "github_token" {
    try testing.expectEqual(@as(?usize, 40), matchGithubToken("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 0));
    try testing.expectEqual(@as(?usize, 40), matchGithubToken("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 0));
    try testing.expectEqual(@as(?usize, null), matchGithubToken("ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 0));
}

test "github_fine_grained_pat" {
    try testing.expect(matchGithubFinePat("github_pat_ABCDEFGHIJKLMNOPQRSTUV12", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchGithubFinePat("github_pat_short", 0));
}

test "anthropic_key" {
    try testing.expect(matchAnthropicKey("sk-ant-abcdefghij1234567890", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchAnthropicKey("sk-ant-short", 0));
}

test "openai_key does not match anthropic" {
    try testing.expectEqual(@as(?usize, null), matchOpenaiKey("sk-ant-abcdefghij1234567890", 0));
    try testing.expect(matchOpenaiKey("sk-abcdefghijklmnopqrstuvwx", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchOpenaiKey("sk-short", 0));
}

test "slack_token" {
    try testing.expect(matchSlackToken("xoxb-1234567890-abcde", 0) != null);
    try testing.expect(matchSlackToken("xoxp-abcdefghij", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchSlackToken("xoxz-1234567890-abcde", 0));
}

test "slack_webhook" {
    const wh = "hooks.slack.com/services/T1234ABC/B5678DEF/xyzABC123456";
    try testing.expect(matchSlackWebhook(wh, 0) != null);
}

test "sendgrid_key" {
    // SG. + 22 chars + . + 43 chars = 69 total
    const key = "SG.abcdefghij1234567890AB.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG";
    try testing.expect(matchSendgridKey(key, 0) != null);
    try testing.expectEqual(@as(?usize, null), matchSendgridKey("SG.short.short", 0));
}

test "npm_token" {
    try testing.expect(matchNpmToken("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchNpmToken("npm_short", 0));
}

test "private_key" {
    try testing.expect(matchPrivateKey("-----BEGIN PRIVATE KEY-----", 0) != null);
    try testing.expect(matchPrivateKey("-----BEGIN RSA PRIVATE KEY-----", 0) != null);
    try testing.expect(matchPrivateKey("-----BEGIN EC PRIVATE KEY-----", 0) != null);
    try testing.expect(matchPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchPrivateKey("-----BEGIN PUBLIC KEY-----", 0));
}

test "jwt" {
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmno";
    try testing.expect(matchJwt(token, 0) != null);
    try testing.expectEqual(@as(?usize, null), matchJwt("eyJshort.eyJshort.short", 0));
}

test "bearer_token" {
    const header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    try testing.expect(matchBearerToken(header, 0) != null);
    try testing.expectEqual(@as(?usize, null), matchBearerToken("Content-Type: application/json", 0));
}

test "generic_api_key" {
    try testing.expect(matchGenericApiKey("api_key = abcdefghij1234567890ab", 0) != null);
    try testing.expect(matchGenericApiKey("API-SECRET=abcdefghij1234567890ab", 0) != null);
    try testing.expect(matchGenericApiKey("secret_key: abcdefghij1234567890ab", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchGenericApiKey("not_a_match = value", 0));
}
