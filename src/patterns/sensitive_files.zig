// OpenClaw Shield — Sensitive File Path Patterns
//
// Ported from openclaw-shield by Knostic (https://knostic.ai/) — Apache 2.0
// Original: 18 patterns covering .env, credentials, keys, SSH, AWS, Kubernetes, etc.

const std = @import("std");

// ── Path Checking ──────────────────────────────────────────────────────

/// Check if a file path matches any known sensitive file pattern.
pub fn isSensitivePath(file_path: []const u8) bool {
    for (&checkers) |checker| {
        if (checker(file_path)) return true;
    }
    return false;
}

/// Return the name of the matched sensitive pattern, or null.
pub fn matchSensitivePath(file_path: []const u8) ?[]const u8 {
    for (&checkers, &checker_names) |checker, name| {
        if (checker(file_path)) return name;
    }
    return null;
}

// ── Checker Table ──────────────────────────────────────────────────────

const CheckFn = *const fn ([]const u8) bool;

const checkers = [_]CheckFn{
    checkDotEnv,
    checkCredentialsJson,
    checkPemFile,
    checkKeyFile,
    checkP12File,
    checkPfxFile,
    checkSshIdentity,
    checkKnownHosts,
    checkSshConfig,
    checkNetrc,
    checkNpmrc,
    checkPypirc,
    checkTokensJson,
    checkSecretsConfig,
    checkAwsCredentials,
    checkKubeConfig,
    checkEtcShadow,
    checkEtcPasswd,
};

const checker_names = [_][]const u8{
    "dot_env",
    "credentials_json",
    "pem_file",
    "key_file",
    "p12_file",
    "pfx_file",
    "ssh_identity",
    "known_hosts",
    "ssh_config",
    "netrc",
    "npmrc",
    "pypirc",
    "tokens_json",
    "secrets_config",
    "aws_credentials",
    "kube_config",
    "etc_shadow",
    "etc_passwd",
};

// ── Helpers ────────────────────────────────────────────────────────────

fn toLowerByte(c: u8) u8 {
    return std.ascii.toLower(c);
}

fn endsWithInsensitive(path: []const u8, suffix: []const u8) bool {
    if (path.len < suffix.len) return false;
    const tail = path[path.len - suffix.len ..];
    for (tail, suffix) |a, b| {
        if (toLowerByte(a) != toLowerByte(b)) return false;
    }
    return true;
}

fn containsComponent(path: []const u8, component: []const u8) bool {
    // Check if path contains /component/ or starts with component/ or ends with /component
    var i: usize = 0;
    while (i + component.len <= path.len) {
        if (std.mem.eql(u8, path[i..][0..component.len], component)) {
            const before_ok = i == 0 or path[i - 1] == '/' or path[i - 1] == '\\';
            const after_pos = i + component.len;
            const after_ok = after_pos == path.len or path[after_pos] == '/' or path[after_pos] == '\\';
            if (before_ok and after_ok) return true;
        }
        i += 1;
    }
    return false;
}

// ── Checker Implementations ────────────────────────────────────────────

/// .env, .env.local, .env.production, etc.
fn checkDotEnv(path: []const u8) bool {
    const basename = getBasename(path);
    if (basename.len < 4) return false;
    // Must start with ".env"
    if (!eqlLower(basename[0..4], ".env")) return false;
    // Must be exactly ".env" or ".env." followed by something
    if (basename.len == 4) return true;
    if (basename[4] == '.') return true;
    return false;
}

/// credentials.json
fn checkCredentialsJson(path: []const u8) bool {
    return eqlLower(getBasename(path), "credentials.json");
}

/// *.pem
fn checkPemFile(path: []const u8) bool {
    return endsWithInsensitive(path, ".pem");
}

/// *.key
fn checkKeyFile(path: []const u8) bool {
    return endsWithInsensitive(path, ".key");
}

/// *.p12
fn checkP12File(path: []const u8) bool {
    return endsWithInsensitive(path, ".p12");
}

/// *.pfx
fn checkPfxFile(path: []const u8) bool {
    return endsWithInsensitive(path, ".pfx");
}

/// id_rsa, id_ed25519, id_ecdsa, id_dsa (and .pub variants)
fn checkSshIdentity(path: []const u8) bool {
    const basename = getBasename(path);
    var name = basename;
    // Strip .pub suffix
    if (endsWithInsensitive(name, ".pub")) {
        name = name[0 .. name.len - 4];
    }
    const prefixes = [_][]const u8{ "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa" };
    for (prefixes) |prefix| {
        if (eqlLower(name, prefix)) return true;
    }
    return false;
}

/// known_hosts
fn checkKnownHosts(path: []const u8) bool {
    return eqlLower(getBasename(path), "known_hosts");
}

/// .ssh/config
fn checkSshConfig(path: []const u8) bool {
    return containsComponent(path, ".ssh") and eqlLower(getBasename(path), "config");
}

/// .netrc
fn checkNetrc(path: []const u8) bool {
    return eqlLower(getBasename(path), ".netrc");
}

/// .npmrc
fn checkNpmrc(path: []const u8) bool {
    return eqlLower(getBasename(path), ".npmrc");
}

/// .pypirc
fn checkPypirc(path: []const u8) bool {
    return eqlLower(getBasename(path), ".pypirc");
}

/// token.json, tokens.json
fn checkTokensJson(path: []const u8) bool {
    const basename = getBasename(path);
    return eqlLower(basename, "token.json") or eqlLower(basename, "tokens.json");
}

/// secret.yml, secret.yaml, secret.json, secret.toml, secrets.* variants
fn checkSecretsConfig(path: []const u8) bool {
    const basename = getBasename(path);
    const config_exts = [_][]const u8{ ".yml", ".yaml", ".json", ".toml" };
    for (config_exts) |ext| {
        // "secret" + ext
        if (basename.len == 6 + ext.len and eqlLower(basename[0..6], "secret") and endsWithInsensitive(basename, ext)) return true;
        // "secrets" + ext
        if (basename.len == 7 + ext.len and eqlLower(basename[0..7], "secrets") and endsWithInsensitive(basename, ext)) return true;
    }
    return false;
}

/// .aws/credentials, .aws/config
fn checkAwsCredentials(path: []const u8) bool {
    if (!containsComponent(path, ".aws")) return false;
    const basename = getBasename(path);
    return eqlLower(basename, "credentials") or eqlLower(basename, "config");
}

/// .kube/config
fn checkKubeConfig(path: []const u8) bool {
    return containsComponent(path, ".kube") and eqlLower(getBasename(path), "config");
}

/// /etc/shadow
fn checkEtcShadow(path: []const u8) bool {
    return std.mem.eql(u8, path, "/etc/shadow");
}

/// /etc/passwd
fn checkEtcPasswd(path: []const u8) bool {
    return std.mem.eql(u8, path, "/etc/passwd");
}

// ── Utility ────────────────────────────────────────────────────────────

fn getBasename(path: []const u8) []const u8 {
    var i = path.len;
    while (i > 0) {
        i -= 1;
        if (path[i] == '/' or path[i] == '\\') return path[i + 1 ..];
    }
    return path;
}

fn eqlLower(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (toLowerByte(ac) != toLowerByte(bc)) return false;
    }
    return true;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "dot_env" {
    try testing.expect(isSensitivePath(".env"));
    try testing.expect(isSensitivePath("/app/.env"));
    try testing.expect(isSensitivePath("/app/.env.local"));
    try testing.expect(isSensitivePath("/app/.env.production"));
    try testing.expect(!isSensitivePath("/app/environment.ts"));
    try testing.expect(!isSensitivePath("/app/.envrc")); // not .env
}

test "credentials" {
    try testing.expect(isSensitivePath("credentials.json"));
    try testing.expect(isSensitivePath("/app/credentials.json"));
}

test "key_files" {
    try testing.expect(isSensitivePath("server.pem"));
    try testing.expect(isSensitivePath("private.key"));
    try testing.expect(isSensitivePath("cert.p12"));
    try testing.expect(isSensitivePath("cert.pfx"));
}

test "ssh" {
    try testing.expect(isSensitivePath("id_rsa"));
    try testing.expect(isSensitivePath("/home/user/.ssh/id_rsa"));
    try testing.expect(isSensitivePath("id_ed25519"));
    try testing.expect(isSensitivePath("id_rsa.pub"));
    try testing.expect(isSensitivePath("known_hosts"));
    try testing.expect(isSensitivePath("/home/user/.ssh/config"));
}

test "dot_configs" {
    try testing.expect(isSensitivePath(".netrc"));
    try testing.expect(isSensitivePath(".npmrc"));
    try testing.expect(isSensitivePath(".pypirc"));
}

test "tokens_and_secrets" {
    try testing.expect(isSensitivePath("token.json"));
    try testing.expect(isSensitivePath("tokens.json"));
    try testing.expect(isSensitivePath("secret.yml"));
    try testing.expect(isSensitivePath("secrets.yaml"));
    try testing.expect(isSensitivePath("secret.json"));
    try testing.expect(isSensitivePath("secrets.toml"));
}

test "cloud_configs" {
    try testing.expect(isSensitivePath("/home/user/.aws/credentials"));
    try testing.expect(isSensitivePath("/home/user/.aws/config"));
    try testing.expect(isSensitivePath("/home/user/.kube/config"));
}

test "system_files" {
    try testing.expect(isSensitivePath("/etc/shadow"));
    try testing.expect(isSensitivePath("/etc/passwd"));
    try testing.expect(!isSensitivePath("/etc/hostname"));
}

test "non_sensitive" {
    try testing.expect(!isSensitivePath("README.md"));
    try testing.expect(!isSensitivePath("src/main.zig"));
    try testing.expect(!isSensitivePath("package.json"));
}

test "matchSensitivePath returns name" {
    try testing.expectEqualStrings("dot_env", matchSensitivePath(".env").?);
    try testing.expectEqualStrings("ssh_identity", matchSensitivePath("id_rsa").?);
    try testing.expectEqual(@as(?[]const u8, null), matchSensitivePath("README.md"));
}
