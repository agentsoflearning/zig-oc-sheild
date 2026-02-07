# Deploying OpenClaw Shield

Two deployment paths: **download a release** (recommended) or **build from source**.

---

## Option 1: Download Release (Recommended)

### Prerequisites

- Node.js >= 18
- An OpenClaw gateway instance

### Steps

**1. Download the gateway package from GitHub Releases:**

```bash
# Replace v0.0.1 with the desired version
curl -LO https://github.com/agentsoflearning/zig-oc-sheild/releases/download/v0.0.1/ocshield-gateway-v0.0.1.tar.gz
```

**2. Extract into your OpenClaw plugins directory:**

```bash
cd ~/.openclaw/plugins    # or your gateway's plugin directory
tar xzf /path/to/ocshield-gateway-v0.0.1.tar.gz
```

This creates a ready-to-load directory:

```
ocshield/
├── package.json          ← Plugin manifest
├── ocshield.json         ← Default policy config (auto-discovered)
├── dist/                 ← Compiled TypeScript bridge
├── src/                  ← Source for jiti fallback loading
├── ocshield.wasm         ← Zig security engine (WASM)
├── node_modules/         ← Dependencies (pre-installed)
├── profiles/             ← Alternative security profiles
│   ├── ocshield-home-lab.json
│   ├── ocshield-corp-dev.json
│   ├── ocshield-prod.json
│   └── ocshield-research.json
├── LICENSE
├── NOTICE
└── README.md
```

**3. Register the plugin with OpenClaw:**

Add the plugin path to your OpenClaw gateway configuration:

```jsonc
// ~/.openclaw/config.json
{
  "plugins": {
    "load": {
      "paths": ["~/.openclaw/plugins/ocshield"]
    }
  }
}
```

**4. Choose a security profile:**

The default config ships with the `corp-dev` profile. To switch:

```bash
# Lockdown mode (production)
cp ocshield/profiles/ocshield-prod.json ocshield/ocshield.json

# Permissive mode (local development)
cp ocshield/profiles/ocshield-home-lab.json ocshield/ocshield.json

# Research mode (open network, controlled process)
cp ocshield/profiles/ocshield-research.json ocshield/ocshield.json
```

Or edit `ocshield/ocshield.json` directly — see [Configuration](#configuration) below.

**5. Restart your OpenClaw gateway.**

The shield will log initialization on startup:

```
[OC-SHIELD] Loaded policy from: /path/to/ocshield/ocshield.json
[OC-SHIELD] Initialized — profile=corp-dev, mode=enforce, binding=pure-ts
```

### Verifying the Installation

Use the operator tool to check status:

```jsonc
// Via OpenClaw tool call
{ "tool": "oc_shield", "args": { "action": "status" } }
```

Expected response:

```json
{
  "profile": "corp-dev",
  "mode": "enforce",
  "binding": "pure-ts",
  "version": "0.0.1"
}
```

---

## Option 2: Build from Source

### Prerequisites

- [Zig 0.13.0](https://ziglang.org/download/)
- Node.js >= 18
- npm
- Git

### Steps

**1. Clone the repository:**

```bash
git clone https://github.com/agentsoflearning/zig-oc-sheild.git
cd zig-oc-sheild
```

**2. Run the test suite to verify your build environment:**

```bash
# Zig tests (362 tests)
zig build test

# Bridge tests (44 tests)
cd bridge && npm ci && npm test && cd ..
```

**3. Build the WASM module:**

```bash
zig build wasm
# Output: zig-out/bin/ocshield.wasm
```

**4. Build the TypeScript bridge:**

```bash
cd bridge
npm ci
npm run build
cd ..
```

**5. Assemble the plugin directory:**

```bash
mkdir -p ~/.openclaw/plugins/ocshield

# Compiled bridge
cp -r bridge/dist ~/.openclaw/plugins/ocshield/
cp -r bridge/src ~/.openclaw/plugins/ocshield/
cp bridge/package.json ~/.openclaw/plugins/ocshield/
cp bridge/tsconfig.json ~/.openclaw/plugins/ocshield/

# Install production dependencies
cd ~/.openclaw/plugins/ocshield && npm install --omit=dev && cd -

# WASM engine
cp zig-out/bin/ocshield.wasm ~/.openclaw/plugins/ocshield/

# Default config
cp ocshield.json ~/.openclaw/plugins/ocshield/

# Profile configs
cp -r examples ~/.openclaw/plugins/ocshield/profiles
```

**6. Register with OpenClaw** (same as Option 1, step 3):

```jsonc
// ~/.openclaw/config.json
{
  "plugins": {
    "load": {
      "paths": ["~/.openclaw/plugins/ocshield"]
    }
  }
}
```

**7. Restart your OpenClaw gateway.**

### Building the Standalone CLI

The Zig core also compiles as a standalone CLI for scanning files outside of OpenClaw:

```bash
zig build
# Output: zig-out/bin/ocshield

# Scan a file
./zig-out/bin/ocshield scan myfile.txt

# Cross-compile for other platforms
zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
```

---

## Configuration

The shield auto-discovers `ocshield.json` in the plugin directory on startup.

### Full Configuration Reference

```jsonc
{
  // "enforce" blocks violations, "audit" logs without blocking
  "mode": "enforce",

  // Base profile: "home-lab", "corp-dev", "prod", "research"
  // Profile defaults are applied first, then your overrides on top
  "profile": "corp-dev",

  // ── Network Controls ────────────────────────────────────────────
  "network": {
    // Domain allowlist. Empty = block all. ["*"] = allow all.
    // Supports wildcards: ["*.internal.corp", "api.github.com"]
    "allowedHosts": [],

    // Port allowlist
    "allowedPorts": [80, 443],

    // Block connections to private IP ranges
    "blockRFC1918": true,      // 10.x, 172.16-31.x, 192.168.x
    "blockLocalhost": true,    // 127.0.0.0/8
    "blockLinkLocal": true,    // 169.254.0.0/16
    "blockMetadata": true,     // 169.254.169.254 (cloud metadata)

    // Egress rate limit (bytes per minute)
    "maxEgressBytesPerMin": 52428800
  },

  // ── Process Controls ────────────────────────────────────────────
  "process": {
    // Master switch for subprocess creation
    "allowSpawn": true,

    // Binary allowlist. Empty = block all. ["*"] = allow all.
    "allowedBinaries": ["git", "node", "npx", "python"],

    // Block shell interpreters (sh, bash, cmd, powershell)
    "denyShells": true,

    // Max subprocess launches per minute
    "maxExecPerMin": 30
  },

  // ── Filesystem Controls ─────────────────────────────────────────
  "filesystem": {
    // Block reads/writes to sensitive paths (.env, .ssh/*, .aws/*, etc.)
    "blockSensitivePaths": true,

    // Block all file writes except to allowed paths
    "blockWrites": true,

    // Write path allowlist. Empty = block all writes.
    // Supports directory wildcards: ["/tmp/*", "/var/tmp/*"]
    "allowedWritePaths": ["/tmp/*"],

    // Block path traversal attempts (../, null bytes)
    "blockPathTraversal": true
  },

  // ── DNS Controls ────────────────────────────────────────────────
  "dns": {
    // Block DNS responses that resolve to private IPs (rebinding defense)
    "blockPrivateResolution": true,

    // Domain allowlist for DNS queries. Empty = block all.
    // ["*"] = allow all. Supports wildcards.
    "allowedDomains": ["*"],

    // Nuclear option: block all DNS resolution
    "blockAllDns": false
  },

  // ── Taint & Quarantine ──────────────────────────────────────────
  "taint": {
    // Auto-escalate taint level on repeated violations
    "autoEscalate": true,

    // Number of violations before auto-quarantine
    "quarantineThreshold": 10,

    // Seconds before taint level can de-escalate
    "coolDownSeconds": 300
  },

  // ── Content Scanning ────────────────────────────────────────────
  "redaction": {
    // How to redact detected secrets/PII
    // "mask" = [REDACTED], "partial" = sk-...xxxx, "hash" = SHA256, "drop" = remove entirely
    "strategy": "mask"
  },

  "entropy": {
    // Enable Shannon entropy detection for unknown secrets
    "enabled": true,
    "base64Threshold": 4.5,
    "hexThreshold": 3.5
  }
}
```

### Security Profiles

| Profile | Mode | Network | Process | Filesystem | DNS | Use Case |
|---------|------|---------|---------|------------|-----|----------|
| `home-lab` | audit | all open | all open | sensitive blocked | all open | Local development, learning |
| `corp-dev` | enforce | corp only | allowlist | write-controlled | corp only | Corporate development |
| `prod` | enforce | locked down | no spawn | all writes blocked | locked down | Production gateways |
| `research` | enforce | open network | allowlist | write-controlled | open | Security research, testing |

---

## Troubleshooting

### Shield not loading

Check that the plugin path in your OpenClaw config points to the directory containing `package.json`:

```bash
ls ~/.openclaw/plugins/ocshield/package.json
# Should exist
```

### "binding=pure-ts" in status

This means the WASM module wasn't found. Verify:

```bash
ls ~/.openclaw/plugins/ocshield/ocshield.wasm
# Should exist
```

The pure-TS fallback works identically but is slower for high-throughput scanning.

### Policy file not loading

The shield searches for these filenames in the plugin directory:
1. `ocshield.json`
2. `openclaw-shield.json`
3. `.ocshield.json`

Check the logs for:
```
[OC-SHIELD] Loaded policy from: /path/to/ocshield.json
```

If you see `using defaults` instead, validate your config:

```bash
node -e "
const { validateConfig } = require('./dist/policy');
const config = require('./ocshield.json');
const result = validateConfig(config);
console.log(JSON.stringify(result, null, 2));
"
```

### Operator commands

```jsonc
// Check status
{ "tool": "oc_shield", "args": { "action": "status", "sessionId": "session-123" } }

// Quarantine a session
{ "tool": "oc_shield", "args": { "action": "quarantine", "sessionId": "session-123" } }

// Switch profile at runtime
{ "tool": "oc_shield", "args": { "action": "set-profile", "profile": "prod" } }

// Export audit log
{ "tool": "oc_shield", "args": { "action": "export-audit" } }
```
