// OpenClaw Shield — PII Detection Patterns
//
// Ported from openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0
// Original: 6 PII patterns — email, US SSN, credit card, US phone,
// international phone, IBAN.

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const Pattern = pattern.Pattern;

// ── Pattern Table ──────────────────────────────────────────────────────

pub const patterns = [_]Pattern{
    .{ .name = "email", .category = .pii, .severity = .warning, .matchAt = matchEmail },
    .{ .name = "us_ssn", .category = .pii, .severity = .critical, .matchAt = matchUsSsn },
    .{ .name = "credit_card", .category = .pii, .severity = .critical, .matchAt = matchCreditCard },
    .{ .name = "us_phone", .category = .pii, .severity = .warning, .matchAt = matchUsPhone },
    .{ .name = "intl_phone", .category = .pii, .severity = .warning, .matchAt = matchIntlPhone },
    .{ .name = "iban", .category = .pii, .severity = .critical, .matchAt = matchIban },
};

// ── Match Functions ────────────────────────────────────────────────────

/// [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
fn matchEmail(input: []const u8, pos: usize) ?usize {
    // Local part
    var p = pos;
    const local_count = pattern.countWhile(input, p, pattern.isEmailLocalChar);
    if (local_count == 0) return null;
    p += local_count;
    // @
    if (p >= input.len or input[p] != '@') return null;
    p += 1;
    // Domain part
    const domain_start = p;
    while (p < input.len and pattern.isEmailDomainChar(input[p])) {
        p += 1;
    }
    if (p == domain_start) return null;
    // Must have at least one dot in domain, find the last one
    var last_dot: ?usize = null;
    var i = domain_start;
    while (i < p) : (i += 1) {
        if (input[i] == '.') last_dot = i;
    }
    if (last_dot == null) return null;
    // TLD must be at least 2 alpha chars
    const tld_start = last_dot.? + 1;
    if (tld_start >= p) return null;
    for (input[tld_start..p]) |c| {
        if (!std.ascii.isAlphabetic(c)) return null;
    }
    if (p - tld_start < 2) return null;
    // Domain part before last dot must not be empty
    if (last_dot.? == domain_start) return null;
    return p - pos;
}

/// \b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b
fn matchUsSsn(input: []const u8, pos: usize) ?usize {
    // Word boundary at start
    if (!pattern.isWordBoundary(input, pos)) return null;
    // Need exactly 11 chars: DDD-DD-DDDD
    if (pos + 11 > input.len) return null;
    const s = input[pos..][0..11];
    // Check format
    if (!std.ascii.isDigit(s[0]) or !std.ascii.isDigit(s[1]) or !std.ascii.isDigit(s[2])) return null;
    if (s[3] != '-') return null;
    if (!std.ascii.isDigit(s[4]) or !std.ascii.isDigit(s[5])) return null;
    if (s[6] != '-') return null;
    if (!std.ascii.isDigit(s[7]) or !std.ascii.isDigit(s[8]) or !std.ascii.isDigit(s[9]) or !std.ascii.isDigit(s[10])) return null;
    // Negative lookaheads
    if (s[0] == '0' and s[1] == '0' and s[2] == '0') return null; // 000
    if (s[0] == '6' and s[1] == '6' and s[2] == '6') return null; // 666
    if (s[0] == '9') return null; // 9XX
    if (s[4] == '0' and s[5] == '0') return null; // XX-00-XXXX
    if (s[7] == '0' and s[8] == '0' and s[9] == '0' and s[10] == '0') return null; // XXX-XX-0000
    // Word boundary at end
    if (!pattern.isWordBoundaryAfter(input, pos + 11)) return null;
    return 11;
}

/// \b[3-6]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b
fn matchCreditCard(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    if (pos >= input.len) return null;
    // First digit must be 3-6
    const first = input[pos];
    if (first < '3' or first > '6') return null;
    var p = pos + 1;
    // Next 3 digits
    var count: usize = 0;
    while (count < 3) : (count += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }
    // Optional separator
    if (p < input.len and (input[p] == ' ' or input[p] == '-')) p += 1;
    // 4 digits
    count = 0;
    while (count < 4) : (count += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }
    // Optional separator
    if (p < input.len and (input[p] == ' ' or input[p] == '-')) p += 1;
    // 4 digits
    count = 0;
    while (count < 4) : (count += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }
    // Optional separator
    if (p < input.len and (input[p] == ' ' or input[p] == '-')) p += 1;
    // 1-7 digits (last group varies: Visa=4, Amex=5 in different position, etc.)
    const last_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - last_start < 7) {
        p += 1;
    }
    if (p - last_start < 1) return null;
    // Word boundary at end
    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// \b(?:\+?1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)[2-9]\d{2}[-.\s]?\d{4}\b
fn matchUsPhone(input: []const u8, pos: usize) ?usize {
    // Phone numbers can start with non-word chars like ( or +,
    // so use "not preceded by alphanumeric" instead of word boundary.
    if (pos > 0 and std.ascii.isAlphanumeric(input[pos - 1])) return null;
    var p = pos;
    // Optional country code: +1 or 1
    if (p < input.len and input[p] == '+') {
        p += 1;
        if (p >= input.len or input[p] != '1') return null;
        p += 1;
        if (p < input.len and pattern.isSeparatorChar(input[p])) p += 1;
    } else if (p < input.len and input[p] == '1') {
        // Could be country code 1 or part of area code — check if followed by separator
        if (p + 1 < input.len and pattern.isSeparatorChar(input[p + 1])) {
            p += 1;
            p += 1; // skip separator
        }
    }
    // Area code: optional parens around [2-9]\d{2}
    const has_paren = p < input.len and input[p] == '(';
    if (has_paren) p += 1;
    if (p >= input.len or input[p] < '2' or input[p] > '9') return null;
    p += 1;
    var d: usize = 0;
    while (d < 2) : (d += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }
    if (has_paren) {
        if (p >= input.len or input[p] != ')') return null;
        p += 1;
    }
    if (p < input.len and pattern.isSeparatorChar(input[p])) p += 1;
    // Exchange: [2-9]\d{2}
    if (p >= input.len or input[p] < '2' or input[p] > '9') return null;
    p += 1;
    d = 0;
    while (d < 2) : (d += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }
    if (p < input.len and pattern.isSeparatorChar(input[p])) p += 1;
    // Subscriber: \d{4}
    d = 0;
    while (d < 4) : (d += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }
    // Word boundary at end
    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// \b\+[2-9]\d{0,2}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b
fn matchIntlPhone(input: []const u8, pos: usize) ?usize {
    // Phone numbers start with +, a non-word char, so use
    // "not preceded by alphanumeric" instead of word boundary.
    if (pos > 0 and std.ascii.isAlphanumeric(input[pos - 1])) return null;
    var p = pos;
    // Must start with +
    if (p >= input.len or input[p] != '+') return null;
    p += 1;
    // Country code: [2-9] followed by 0-2 digits
    if (p >= input.len or input[p] < '2' or input[p] > '9') return null;
    p += 1;
    var cc_extra: usize = 0;
    while (cc_extra < 2 and p < input.len and std.ascii.isDigit(input[p])) {
        p += 1;
        cc_extra += 1;
    }
    // Separator
    if (p < input.len and pattern.isSeparatorChar(input[p])) p += 1;
    // Group 1: 2-4 digits
    const g1_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - g1_start < 4) {
        p += 1;
    }
    if (p - g1_start < 2) return null;
    // Separator
    if (p < input.len and pattern.isSeparatorChar(input[p])) p += 1;
    // Group 2: 3-4 digits
    const g2_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - g2_start < 4) {
        p += 1;
    }
    if (p - g2_start < 3) return null;
    // Separator
    if (p < input.len and pattern.isSeparatorChar(input[p])) p += 1;
    // Group 3: 3-4 digits
    const g3_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - g3_start < 4) {
        p += 1;
    }
    if (p - g3_start < 3) return null;
    // Word boundary at end
    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// \b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,23}\b
fn matchIban(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    var p = pos;
    // Country code: 2 uppercase letters
    if (p + 2 > input.len) return null;
    if (!std.ascii.isUpper(input[p]) or !std.ascii.isUpper(input[p + 1])) return null;
    p += 2;
    // Check digits: 2 digits
    if (p + 2 > input.len) return null;
    if (!std.ascii.isDigit(input[p]) or !std.ascii.isDigit(input[p + 1])) return null;
    p += 2;
    // Bank code: 4 alphanumeric
    if (p + 4 > input.len) return null;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        if (!std.ascii.isAlphanumeric(input[p + i]) or std.ascii.isLower(input[p + i])) return null;
    }
    p += 4;
    // Account: 7 digits
    if (p + 7 > input.len) return null;
    i = 0;
    while (i < 7) : (i += 1) {
        if (!std.ascii.isDigit(input[p + i])) return null;
    }
    p += 7;
    // Remaining: 0-23 alphanumeric (uppercase or digit)
    var extra: usize = 0;
    while (extra < 23 and p < input.len and (std.ascii.isUpper(input[p]) or std.ascii.isDigit(input[p]))) {
        p += 1;
        extra += 1;
    }
    // Word boundary at end
    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "email" {
    try testing.expect(matchEmail("user@example.com", 0) != null);
    try testing.expect(matchEmail("user.name+tag@domain.co.uk", 0) != null);
    try testing.expect(matchEmail("a@b.cc", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchEmail("not-an-email", 0));
    try testing.expectEqual(@as(?usize, null), matchEmail("@domain.com", 0));
    try testing.expectEqual(@as(?usize, null), matchEmail("user@", 0));
    try testing.expectEqual(@as(?usize, null), matchEmail("user@domain", 0));
    try testing.expectEqual(@as(?usize, null), matchEmail("user@domain.x", 0)); // TLD too short
}

test "us_ssn" {
    try testing.expectEqual(@as(?usize, 11), matchUsSsn("123-45-6789", 0));
    try testing.expect(matchUsSsn(" 123-45-6789 ", 1) != null);
    // Excluded ranges
    try testing.expectEqual(@as(?usize, null), matchUsSsn("000-45-6789", 0));
    try testing.expectEqual(@as(?usize, null), matchUsSsn("666-45-6789", 0));
    try testing.expectEqual(@as(?usize, null), matchUsSsn("900-45-6789", 0));
    try testing.expectEqual(@as(?usize, null), matchUsSsn("123-00-6789", 0));
    try testing.expectEqual(@as(?usize, null), matchUsSsn("123-45-0000", 0));
    // No word boundary
    try testing.expectEqual(@as(?usize, null), matchUsSsn("X123-45-6789", 1));
}

test "credit_card" {
    try testing.expect(matchCreditCard("4111 1111 1111 1111", 0) != null); // Visa
    try testing.expect(matchCreditCard("5500-0000-0000-0004", 0) != null); // MC
    try testing.expect(matchCreditCard("378282246310005", 0) != null); // Amex (15 digits continuous)
    try testing.expectEqual(@as(?usize, null), matchCreditCard("1234567890123456", 0)); // starts with 1
    try testing.expectEqual(@as(?usize, null), matchCreditCard("7111111111111111", 0)); // starts with 7
}

test "us_phone" {
    try testing.expect(matchUsPhone("(555) 867-5309", 0) != null);
    try testing.expect(matchUsPhone("555-867-5309", 0) != null);
    try testing.expect(matchUsPhone("+1-555-867-5309", 0) != null);
    try testing.expect(matchUsPhone("555.867.5309", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchUsPhone("(155) 867-5309", 0)); // area code starts with 1
}

test "intl_phone" {
    try testing.expect(matchIntlPhone("+44 20 7946 0958", 0) != null);
    try testing.expect(matchIntlPhone("+33-12-3456-7890", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchIntlPhone("+1-555-867-5309", 0)); // +1 is not 2-9
}

test "iban" {
    try testing.expect(matchIban("GB29NWBK60161331926819", 0) != null);
    try testing.expect(matchIban("DE89370400440532013000", 0) != null);
    try testing.expectEqual(@as(?usize, null), matchIban("gb29NWBK60161331926819", 0)); // lowercase country
    try testing.expectEqual(@as(?usize, null), matchIban("XX", 0)); // too short
}
