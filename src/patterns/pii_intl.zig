// OpenClaw Shield — International PII Detection Patterns
//
// Phase 3: Expanded detection beyond US-centric patterns.
// UK NIN/NHS, Canadian SIN, Australian TFN, EU VAT, passport numbers,
// IPv4/IPv6 addresses, MAC addresses, date of birth patterns.

const std = @import("std");
const pattern = @import("../core/pattern.zig");
const Pattern = pattern.Pattern;

// ── Pattern Table ──────────────────────────────────────────────────────

pub const patterns = [_]Pattern{
    .{ .name = "uk_nino", .category = .pii, .severity = .critical, .matchAt = matchUkNino },
    .{ .name = "uk_nhs", .category = .pii, .severity = .critical, .matchAt = matchUkNhs },
    .{ .name = "ca_sin", .category = .pii, .severity = .critical, .matchAt = matchCaSin },
    .{ .name = "au_tfn", .category = .pii, .severity = .critical, .matchAt = matchAuTfn },
    .{ .name = "eu_vat", .category = .pii, .severity = .warning, .matchAt = matchEuVat },
    .{ .name = "passport_number", .category = .pii, .severity = .critical, .matchAt = matchPassport },
    .{ .name = "ipv4_address", .category = .pii, .severity = .info, .matchAt = matchIpv4 },
    .{ .name = "mac_address", .category = .pii, .severity = .info, .matchAt = matchMac },
    .{ .name = "date_of_birth", .category = .pii, .severity = .warning, .matchAt = matchDob },
};

// ── Match Functions ────────────────────────────────────────────────────

/// UK National Insurance Number: 2 letters + 6 digits + 1 letter
/// Format: AB 12 34 56 C (with optional spaces)
/// First two letters: not D, F, I, Q, U, V (prefix restrictions)
/// Second letter: not O
/// Suffix letter: A, B, C, D only
fn matchUkNino(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    var p = pos;

    // First letter (not D, F, I, Q, U, V)
    if (p >= input.len) return null;
    const c0 = std.ascii.toUpper(input[p]);
    if (!std.ascii.isAlphabetic(input[p])) return null;
    if (c0 == 'D' or c0 == 'F' or c0 == 'I' or c0 == 'Q' or c0 == 'U' or c0 == 'V') return null;
    p += 1;

    // Second letter (not D, F, I, O, Q, U, V)
    if (p >= input.len) return null;
    const c1 = std.ascii.toUpper(input[p]);
    if (!std.ascii.isAlphabetic(input[p])) return null;
    if (c1 == 'D' or c1 == 'F' or c1 == 'I' or c1 == 'O' or c1 == 'Q' or c1 == 'U' or c1 == 'V') return null;
    p += 1;

    // 6 digits with optional spaces between pairs
    var digit_count: usize = 0;
    while (digit_count < 6) {
        if (p < input.len and input[p] == ' ') p += 1;
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
        digit_count += 1;
    }

    // Optional space before suffix
    if (p < input.len and input[p] == ' ') p += 1;

    // Suffix: A, B, C, or D
    if (p >= input.len) return null;
    const suffix = std.ascii.toUpper(input[p]);
    if (suffix != 'A' and suffix != 'B' and suffix != 'C' and suffix != 'D') return null;
    p += 1;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// UK NHS Number: 10 digits (often displayed as 3-3-4 with spaces)
/// e.g., 123 456 7890
fn matchUkNhs(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    var p = pos;
    var digit_count: usize = 0;

    // Read exactly 10 digits, allowing spaces between groups of 3-3-4
    while (digit_count < 10) {
        if (p < input.len and input[p] == ' ' and digit_count > 0) p += 1;
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
        digit_count += 1;
    }

    // Must not be followed by more digits
    if (p < input.len and std.ascii.isDigit(input[p])) return null;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// Canadian Social Insurance Number: 9 digits (displayed as 3-3-3)
/// e.g., 123-456-789 or 123 456 789
fn matchCaSin(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    var p = pos;

    // Group 1: 3 digits
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }

    // Separator (space or dash)
    if (p >= input.len or (input[p] != '-' and input[p] != ' ')) return null;
    const sep = input[p];
    p += 1;

    // Group 2: 3 digits
    i = 0;
    while (i < 3) : (i += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }

    // Same separator
    if (p >= input.len or input[p] != sep) return null;
    p += 1;

    // Group 3: 3 digits
    i = 0;
    while (i < 3) : (i += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }

    // Must not start with 0 or 8
    if (input[pos] == '0' or input[pos] == '8') return null;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// Australian Tax File Number: 8 or 9 digits (often with spaces as 3-3-3 or 3-3-2)
/// e.g., 123 456 789
fn matchAuTfn(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    var p = pos;

    // Group 1: 3 digits
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }

    // Space separator
    if (p >= input.len or input[p] != ' ') return null;
    p += 1;

    // Group 2: 3 digits
    i = 0;
    while (i < 3) : (i += 1) {
        if (p >= input.len or !std.ascii.isDigit(input[p])) return null;
        p += 1;
    }

    // Space separator
    if (p >= input.len or input[p] != ' ') return null;
    p += 1;

    // Group 3: 2 or 3 digits
    i = 0;
    while (i < 3 and p < input.len and std.ascii.isDigit(input[p])) : (i += 1) {
        p += 1;
    }
    if (i < 2) return null;

    // Must not be followed by more digits
    if (p < input.len and std.ascii.isDigit(input[p])) return null;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// EU VAT Number: 2-letter country code + 2–13 alphanumeric characters
/// e.g., DE123456789, GB123456789, FR12345678901
fn matchEuVat(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    if (pos + 4 > input.len) return null; // Minimum: CC + 2 chars

    // Country code: 2 uppercase letters
    if (!std.ascii.isUpper(input[pos]) or !std.ascii.isUpper(input[pos + 1])) return null;

    // Validate known EU country codes
    const cc = input[pos..][0..2];
    if (!isEuVatCountry(cc)) return null;

    var p = pos + 2;

    // 2–13 alphanumeric (some countries use letters, e.g., FR has letter+digit check)
    const start = p;
    while (p < input.len and std.ascii.isAlphanumeric(input[p]) and p - start < 13) {
        p += 1;
    }
    if (p - start < 2) return null;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

fn isEuVatCountry(cc: *const [2]u8) bool {
    const countries = [_][]const u8{
        "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES",
        "FI", "FR", "GB", "HR", "HU", "IE", "IT", "LT", "LU", "LV",
        "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
    };
    for (countries) |c| {
        if (cc[0] == c[0] and cc[1] == c[1]) return true;
    }
    return false;
}

/// Passport number: keyword + alphanumeric sequence.
/// Matches: "passport" followed by separator and 6-12 alphanumeric characters.
/// e.g., "Passport: AB1234567" or "passport no AB1234567"
fn matchPassport(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;

    // Match "passport" keyword (case-insensitive)
    if (!startsWithIgnoreCase(input, pos, "passport")) return null;
    var p = pos + 8;

    // Optional "no" or "number" or "#"
    p = pattern.skipWhitespace(input, p);
    if (p < input.len) {
        if (startsWithIgnoreCase(input, p, "number")) {
            p += 6;
        } else if (startsWithIgnoreCase(input, p, "no")) {
            p += 2;
        } else if (input[p] == '#') {
            p += 1;
        }
    }

    // Separator: colon, equals, or whitespace
    if (p < input.len and (input[p] == ':' or input[p] == '=')) p += 1;
    p = pattern.skipWhitespace(input, p);

    // Passport number: 6-12 alphanumeric characters (must start with letter or digit)
    const num_start = p;
    while (p < input.len and std.ascii.isAlphanumeric(input[p]) and p - num_start < 12) {
        p += 1;
    }
    if (p - num_start < 6) return null;

    // Must contain at least one digit (pure letters unlikely to be passport number)
    var has_digit = false;
    for (input[num_start..p]) |c| {
        if (std.ascii.isDigit(c)) {
            has_digit = true;
            break;
        }
    }
    if (!has_digit) return null;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// IPv4 address: D.D.D.D where each octet is 0-255
/// Only matches when preceded by a word boundary to avoid matching
/// version numbers like "v1.2.3.4" or similar.
fn matchIpv4(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;
    var p = pos;

    var octets: usize = 0;
    while (octets < 4) : (octets += 1) {
        if (octets > 0) {
            if (p >= input.len or input[p] != '.') return null;
            p += 1;
        }
        // Parse octet: 1-3 digits, value 0-255
        const octet_start = p;
        while (p < input.len and std.ascii.isDigit(input[p]) and p - octet_start < 3) {
            p += 1;
        }
        if (p == octet_start) return null;
        // Validate range
        const octet_str = input[octet_start..p];
        var val: u16 = 0;
        for (octet_str) |c| {
            val = val * 10 + (c - '0');
        }
        if (val > 255) return null;
        // No leading zeros (except "0" itself)
        if (octet_str.len > 1 and octet_str[0] == '0') return null;
    }

    // Must not be followed by a dot (avoids partial version matches)
    if (p < input.len and input[p] == '.') return null;
    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// MAC address: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
/// where XX is 2 hex characters
fn matchMac(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;

    // Need at least 17 chars (6 groups * 2 + 5 separators)
    if (pos + 17 > input.len) return null;

    var p = pos;
    var groups: usize = 0;
    var sep: u8 = 0;

    while (groups < 6) : (groups += 1) {
        if (groups > 0) {
            if (p >= input.len) return null;
            if (groups == 1) {
                // Detect separator from first occurrence
                if (input[p] != ':' and input[p] != '-') return null;
                sep = input[p];
            } else {
                if (input[p] != sep) return null;
            }
            p += 1;
        }
        // 2 hex digits
        if (p + 2 > input.len) return null;
        if (!isHexDigit(input[p]) or !isHexDigit(input[p + 1])) return null;
        p += 2;
    }

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

/// Date of birth patterns: matches keyword + date
/// "DOB: 01/15/1990", "date of birth: 1990-01-15", "born: 15/01/1990"
fn matchDob(input: []const u8, pos: usize) ?usize {
    if (!pattern.isWordBoundary(input, pos)) return null;

    var p = pos;

    // Match keyword
    if (startsWithIgnoreCase(input, p, "date of birth")) {
        p += 13;
    } else if (startsWithIgnoreCase(input, p, "dob")) {
        p += 3;
    } else if (startsWithIgnoreCase(input, p, "born")) {
        p += 4;
    } else if (startsWithIgnoreCase(input, p, "birthday")) {
        p += 8;
    } else {
        return null;
    }

    // Separator: colon, equals, whitespace
    if (p < input.len and (input[p] == ':' or input[p] == '=')) p += 1;
    p = pattern.skipWhitespace(input, p);

    // Date: try MM/DD/YYYY or DD/MM/YYYY or YYYY-MM-DD
    const date_start = p;
    if (matchDatePattern(input, p)) |len| {
        p += len;
    } else {
        return null;
    }
    _ = date_start;

    if (!pattern.isWordBoundaryAfter(input, p)) return null;
    return p - pos;
}

fn matchDatePattern(input: []const u8, start: usize) ?usize {
    var p = start;

    // Read first number group (2 or 4 digits)
    const g1_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - g1_start < 4) {
        p += 1;
    }
    const g1_len = p - g1_start;
    if (g1_len < 2) return null;

    // Separator
    if (p >= input.len) return null;
    const sep = input[p];
    if (sep != '/' and sep != '-' and sep != '.') return null;
    p += 1;

    // Second group: 2 digits
    const g2_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - g2_start < 2) {
        p += 1;
    }
    if (p - g2_start != 2) return null;

    // Same separator
    if (p >= input.len or input[p] != sep) return null;
    p += 1;

    // Third group: 2 or 4 digits
    const g3_start = p;
    while (p < input.len and std.ascii.isDigit(input[p]) and p - g3_start < 4) {
        p += 1;
    }
    const g3_len = p - g3_start;
    if (g3_len != 2 and g3_len != 4) return null;

    // Validate: either DD/MM/YYYY or YYYY-MM-DD format
    if (g1_len == 4 and g3_len != 2) return null; // YYYY-MM-DD format
    if (g1_len == 2 and g3_len != 4) return null; // MM/DD/YYYY or DD/MM/YYYY format

    return p - start;
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

test "uk_nino — valid" {
    try testing.expect(matchUkNino("AB123456C", 0) != null);
    try testing.expect(matchUkNino("AB 12 34 56 C", 0) != null);
    try testing.expect(matchUkNino("ab123456c", 0) != null); // case insensitive
}

test "uk_nino — invalid prefix letters" {
    try testing.expect(matchUkNino("DA123456C", 0) == null); // D not allowed
    try testing.expect(matchUkNino("AF123456C", 0) == null); // F not allowed second
    try testing.expect(matchUkNino("AO123456C", 0) == null); // O not allowed second
}

test "uk_nino — invalid suffix" {
    try testing.expect(matchUkNino("AB123456E", 0) == null); // Only A-D
    try testing.expect(matchUkNino("AB123456Z", 0) == null);
}

test "uk_nhs — valid" {
    try testing.expect(matchUkNhs("1234567890", 0) != null);
    try testing.expect(matchUkNhs("123 456 7890", 0) != null);
}

test "uk_nhs — too few digits" {
    try testing.expect(matchUkNhs("123456789", 0) == null); // only 9
}

test "uk_nhs — too many digits" {
    // 11 digits should not match
    try testing.expect(matchUkNhs("12345678901", 0) == null);
}

test "ca_sin — valid" {
    try testing.expect(matchCaSin("123-456-789", 0) != null);
    try testing.expect(matchCaSin("123 456 789", 0) != null);
}

test "ca_sin — invalid starting digits" {
    try testing.expect(matchCaSin("023-456-789", 0) == null); // starts with 0
    try testing.expect(matchCaSin("823-456-789", 0) == null); // starts with 8
}

test "ca_sin — inconsistent separators" {
    try testing.expect(matchCaSin("123-456 789", 0) == null); // mixed separators
}

test "au_tfn — valid" {
    try testing.expect(matchAuTfn("123 456 789", 0) != null); // 9 digits
    try testing.expect(matchAuTfn("123 456 78", 0) != null); // 8 digits
}

test "au_tfn — too few digits" {
    try testing.expect(matchAuTfn("123 456 7", 0) == null); // only 7
}

test "eu_vat — valid" {
    try testing.expect(matchEuVat("DE123456789", 0) != null);
    try testing.expect(matchEuVat("GB123456789", 0) != null);
    try testing.expect(matchEuVat("FR12345678901", 0) != null);
    try testing.expect(matchEuVat("FRXX999999999", 0) != null); // letters allowed
}

test "eu_vat — invalid country" {
    try testing.expect(matchEuVat("US123456789", 0) == null);
    try testing.expect(matchEuVat("XX123456789", 0) == null);
}

test "eu_vat — too short" {
    try testing.expect(matchEuVat("DE1", 0) == null);
}

test "passport_number — with colon" {
    try testing.expect(matchPassport("passport: AB1234567", 0) != null);
    try testing.expect(matchPassport("Passport: AB1234567", 0) != null);
}

test "passport_number — with 'no'" {
    try testing.expect(matchPassport("passport no AB1234567", 0) != null);
}

test "passport_number — must have digits" {
    try testing.expect(matchPassport("passport: ABCDEFGHI", 0) == null); // no digits
}

test "passport_number — too short" {
    try testing.expect(matchPassport("passport: AB123", 0) == null); // only 5 chars
}

test "ipv4_address — valid" {
    try testing.expectEqual(@as(?usize, 9), matchIpv4("10.0.0.55", 0));
    try testing.expectEqual(@as(?usize, 15), matchIpv4("192.168.100.200", 0));
    try testing.expectEqual(@as(?usize, 7), matchIpv4("0.0.0.0", 0));
    try testing.expectEqual(@as(?usize, 15), matchIpv4("255.255.255.255", 0));
}

test "ipv4_address — invalid" {
    try testing.expect(matchIpv4("256.0.0.1", 0) == null); // octet > 255
    try testing.expect(matchIpv4("10.0.0", 0) == null); // too few octets
    try testing.expect(matchIpv4("10.0.0.1.5", 0) == null); // too many octets (followed by .)
    try testing.expect(matchIpv4("01.02.03.04", 0) == null); // leading zeros
}

test "mac_address — colon separated" {
    try testing.expectEqual(@as(?usize, 17), matchMac("00:1A:2B:3C:4D:5E", 0));
    try testing.expectEqual(@as(?usize, 17), matchMac("aa:bb:cc:dd:ee:ff", 0));
}

test "mac_address — dash separated" {
    try testing.expectEqual(@as(?usize, 17), matchMac("00-1A-2B-3C-4D-5E", 0));
}

test "mac_address — invalid" {
    try testing.expect(matchMac("00:1A:2B:3C:4D", 0) == null); // only 5 groups
    try testing.expect(matchMac("00:1A:2B:3C:4D:GG", 0) == null); // non-hex
    try testing.expect(matchMac("00:1A-2B:3C:4D:5E", 0) == null); // mixed separators
}

test "date_of_birth — MM/DD/YYYY" {
    try testing.expect(matchDob("DOB: 01/15/1990", 0) != null);
    try testing.expect(matchDob("dob: 12/25/1985", 0) != null);
}

test "date_of_birth — YYYY-MM-DD" {
    try testing.expect(matchDob("date of birth: 1990-01-15", 0) != null);
}

test "date_of_birth — born keyword" {
    try testing.expect(matchDob("born: 15/01/1990", 0) != null);
}

test "date_of_birth — birthday keyword" {
    try testing.expect(matchDob("birthday: 1990-12-25", 0) != null);
}

test "date_of_birth — no keyword fails" {
    try testing.expect(matchDob("01/15/1990", 0) == null);
}
