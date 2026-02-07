# OpenClaw Shield (Zig)

Zig-native security guardrail plugin for [OpenClaw](https://github.com/openclaw/openclaw).
Based on [openclaw-shield](https://github.com/knostic/openclaw-shield) by [Knostic](https://knostic.ai/).

## What It Does

Protects OpenClaw users from leaking PII, secrets, and credentials through their AI assistant.
Blocks destructive commands, intercepts unauthorized network/process/filesystem/DNS activity,
detects nefarious skill behavior, and maintains an audit trail of all sensitive data interactions.

## Architecture

7-layer defense-in-depth with 31 runtime interceptor hooks:

| Layer | Name | Defense Type |
|-------|------|-------------|
| **L1** | Prompt Guard | Injects security policy into agent context |
| **L2** | Output Scanner | Redacts secrets/PII from tool results |
| **L3** | Tool Blocker | Hard-blocks dangerous tool calls |
| **L4** | Input Audit | Logs inbound messages with sensitive data flags |
| **L5** | Security Gate | Gate tool the agent must call before exec/read |
| **L6** | Rate Limiter | Prevents rapid-fire sensitive operations |
| **L7** | Preventive Enforcement | Intercepts network, process, filesystem, and DNS before execution |

### L7 Interceptor Coverage

| Category | Hooks | What It Blocks |
|----------|-------|----------------|
| **Network** (7) | fetch, http/https.request, http/https.get, net/tls.connect | RFC1918, localhost, cloud metadata, unauthorized hosts/ports, SSRF |
| **Process** (7) | spawn, spawnSync, execFile, execFileSync, exec, execSync, fork | Unauthorized binaries, shell injection, exec rate limits |
| **Filesystem** (8) | readFile(Sync), writeFile(Sync), open(Sync), createRead/WriteStream | Sensitive path access, unauthorized writes, path traversal |
| **DNS** (9) | lookup, resolve, resolve4/6, resolveMx/Txt/Srv/Cname/Ns | Domain allowlist, DNS rebinding (public domain → private IP) |

All 26 intercepted functions are frozen via `Object.defineProperty` with 1-second tamper detection.

## Detection Coverage

| Category | Count | Examples |
|----------|-------|---------|
| **Secrets** | 15 | AWS keys, Stripe, GitHub PATs, OpenAI/Anthropic keys, Slack tokens, JWTs, private keys |
| **PII** | 6 | Email, SSN, credit card, phone (US + intl), IBAN |
| **Intl PII** | 9 | UK NIN/NHS, EU VAT, Canada SIN, Australia TFN/Medicare, passport, IP/MAC, DOB |
| **Destructive** | 7 | rm, rmdir, unlink, del, format, mkfs, dd |
| **Sensitive Files** | 18 | .env, .pem, .key, .ssh/\*, .aws/\*, .kube/config, /etc/shadow |
| **Skill Threats** | 7 | Shell exec, eval, crypto-mining, data exfil, env harvesting |
| **Prompt Injection** | 6 | Ignore instructions, role override, system prompt extraction |

Plus Shannon entropy analysis for detecting unknown high-entropy secrets.

All pattern matching is O(n) with custom prefix/charset matchers — no regex.

## Quick Start

### Download a Release

```bash
# Download the gateway package
curl -LO https://github.com/agentsoflearning/zig-oc-sheild/releases/latest/download/ocshield-gateway-v0.0.1.tar.gz

# Extract into your OpenClaw plugins directory
cd ~/.openclaw/plugins
tar xzf /path/to/ocshield-gateway-v0.0.1.tar.gz
```

Add to your OpenClaw config:

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

Restart your gateway. The shield auto-discovers `ocshield.json` and starts enforcing.

### Build from Source

```bash
# Prerequisites: Zig 0.13.0, Node.js >= 18

# Run tests
zig build test                     # 362 Zig tests
cd bridge && npm ci && npm test    # 44 jiti integration tests

# Build
zig build                          # CLI → zig-out/bin/ocshield
zig build wasm                     # WASM → zig-out/bin/ocshield.wasm
cd bridge && npm run build         # TS bridge → bridge/dist/
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for full deployment instructions.

## Security Profiles

Four built-in profiles — switch by editing `ocshield.json` or at runtime:

| Profile | Mode | Network | Process | Filesystem | DNS | Use Case |
|---------|------|---------|---------|------------|-----|----------|
| `home-lab` | audit | all open | all open | sensitive blocked | all open | Local dev |
| `corp-dev` | enforce | corp only | allowlist | write-controlled | corp only | Corporate |
| `prod` | enforce | locked down | no spawn | all blocked | locked down | Production |
| `research` | enforce | open | allowlist | write-controlled | open | Research |

```bash
# Switch profiles
cp ~/.openclaw/plugins/ocshield/profiles/ocshield-prod.json \
   ~/.openclaw/plugins/ocshield/ocshield.json
```

## Configuration

```jsonc
{
  "profile": "corp-dev",
  "mode": "enforce",
  "network": {
    "allowedHosts": ["*.internal.corp"],
    "allowedPorts": [80, 443],
    "blockRFC1918": true,
    "blockMetadata": true
  },
  "process": {
    "allowSpawn": true,
    "allowedBinaries": ["git", "node", "npx", "python"],
    "denyShells": true
  },
  "filesystem": {
    "blockSensitivePaths": true,
    "blockWrites": true,
    "allowedWritePaths": ["/tmp/*"],
    "blockPathTraversal": true
  },
  "dns": {
    "blockPrivateResolution": true,
    "allowedDomains": ["*.internal.corp"]
  },
  "redaction": { "strategy": "mask" },
  "entropy": { "enabled": true }
}
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full configuration reference.

## Standalone CLI

```bash
# Scan text for secrets and PII
./ocshield scan "my key is AKIA1234567890ABCDEF"

# Cross-compile for any platform
zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
```

## Project Structure

```
src/                    32 Zig files — pattern engine, layers L1-L7, policy engine
bridge/                 TypeScript bridge — interceptors, tamper detection, profiles
examples/               4 profile configs (home-lab, corp-dev, prod, research)
docs/                   PLAN.md, DEPLOYMENT.md
.github/workflows/      CI (Zig + Node 18/20/22 matrix) + release pipeline
```

**Zero external dependencies** — Zig standard library only. The TypeScript bridge
uses only Node.js built-in modules.

## Credits

This project is a derivative work based on
[openclaw-shield](https://github.com/knostic/openclaw-shield)
by [Knostic](https://knostic.ai/), licensed under Apache 2.0.

The original 5-layer architecture, pattern definitions, and defense-in-depth
approach are credited to Knostic's work. See [NOTICE](NOTICE) for full attribution.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
