# OpenClaw Shield — Zig Port Plan

> Zig-native security guardrail plugin for [OpenClaw](https://github.com/openclaw/openclaw)
> Based on [knostic/openclaw-shield](https://github.com/knostic/openclaw-shield) by [Knostic](https://knostic.ai/) (Apache 2.0)

---

## Table of Contents

1. [Background & Motivation](#1-background--motivation)
2. [Original Architecture Review](#2-original-architecture-review)
3. [Why Zig](#3-why-zig)
4. [Bridge Strategy](#4-bridge-strategy)
5. [Expanded Capabilities](#5-expanded-capabilities)
6. [Project Structure](#6-project-structure)
7. [Module Design](#7-module-design)
8. [Build System](#8-build-system)
9. [TypeScript Bridge](#9-typescript-bridge)
10. [Configuration](#10-configuration)
11. [Testing Strategy](#11-testing-strategy)
12. [Implementation Phases](#12-implementation-phases)
13. [Attribution](#13-attribution)

---

## 1. Background & Motivation

OpenClaw is an open-source, self-hosted AI assistant platform (~171k stars) that routes
messages from chat platforms (WhatsApp, Telegram, Slack, Discord, etc.) through a central
gateway to AI agent sessions. It supports a plugin system for extending functionality.

The original **openclaw-shield** by Knostic is a TypeScript plugin providing 5-layer
defense-in-depth security: blocking destructive commands, redacting secrets and PII from
agent output, and gating sensitive operations. It's a critical safety layer for anyone
running an AI assistant that has access to their files, shell, and credentials.

**This project ports the shield to Zig** for:
- High-performance pattern matching on every message and tool call
- Memory-safe scanning without garbage collection pauses
- Cross-compilation to any target (native shared lib, WASM, standalone binary)
- Expanded detection capabilities that benefit from systems-level performance

---

## 2. Original Architecture Review

The original knostic/openclaw-shield implements 5 defense layers:

### Layer 1: Prompt Guard (`before_agent_start` hook, priority 100)
- Injects a security policy into the agent's system prompt
- Instructs the agent to call the `knostic_shield` gate tool before every `exec` or `read`
- Soft defense — relies on LLM compliance

### Layer 2: Output Scanner (`tool_result_persist` hook, priority 200)
- Scans tool results for secrets and PII before transcript persistence
- Replaces matches with `[REDACTED:pattern_name]` placeholders
- Uses `walkStrings()` to deep-walk nested objects
- Hard defense — redaction happens regardless of LLM behavior

### Layer 3: Tool Blocker (`before_tool_call` hook, priority 200)
- Intended to hard-block dangerous tool calls before execution
- Returns `{ block: true, blockReason: "..." }` for destructive commands
- **Note**: This hook is not wired in the current OpenClaw binary (v2026.1.30)

### Layer 4: Input Audit (`message_received` hook, priority 50)
- Observe-only layer that logs inbound messages
- Flags any embedded secrets or PII in user input
- Does not block — provides audit trail

### Layer 5: Security Gate (`registerTool` API)
- Registers a `knostic_shield` tool the agent must call before exec/read
- Checks commands against destructive patterns, file paths against sensitive patterns
- Returns structured ALLOWED/DENIED responses
- **Key innovation**: Works on all OpenClaw versions via tool registration API

### Pattern Coverage (Original)
| Category | Count | Examples |
|----------|-------|---------|
| Secrets | 15 | AWS keys, Stripe, GitHub tokens, OpenAI/Anthropic keys, JWTs, private keys |
| PII | 6 | Email, US SSN, credit card, US/intl phone, IBAN |
| Destructive commands | 7 | rm, rmdir, unlink, del, format, mkfs, dd |
| Sensitive files | 18 | .env, .pem, .key, .ssh/*, .aws/*, .kube/config, /etc/shadow |

### Known Limitations
1. L3 (`before_tool_call`) is not wired in the published OpenClaw binary
2. L2 has a timing gap — LLM sees raw content for the current turn before redaction
3. L5 is advisory — relies on LLM following the injected security policy
4. Only 3 of 14 OpenClaw hooks fire in the published version

---

## 3. Why Zig

| Concern | TypeScript (Original) | Zig (This Port) |
|---------|----------------------|------------------|
| Pattern matching | Regex engine, no control over backtracking | Custom scanner, bounded execution, SIMD-capable |
| Memory | V8 GC pauses on large payloads | Arena allocators, zero-copy scanning |
| Secrets in memory | Strings persist in GC heap | Explicit zeroing after scan |
| Cross-compilation | Node.js required | Single static binary, WASM, or shared lib |
| Dependencies | Zero (good), but Node.js runtime | Zero — Zig standard library only |
| Entropy detection | Expensive in JS for large payloads | Fast Shannon entropy via SIMD |
| Audit logging | Console.log | Structured binary log with memory-mapped I/O |

The security domain specifically benefits from Zig because:
- **Sensitive data handling**: We can zero memory after scanning, preventing secrets from lingering in heap
- **Bounded execution**: Pattern matching has deterministic time bounds, preventing ReDoS
- **No runtime**: The scanner is a pure function — no event loop, no GC, no async overhead
- **WASM target**: Same codebase compiles to WASM for sandboxed execution

---

## 4. Bridge Strategy

OpenClaw plugins **must** be TypeScript modules loaded via `jiti`. There is no native
plugin interface. Our strategy:

```
┌─────────────────────────────────────────────────────┐
│                   OpenClaw Gateway                   │
│                                                      │
│  Plugin Loader (jiti) ──> TypeScript Bridge (thin)   │
│                              │                       │
│                    ┌─────────┴─────────┐             │
│                    │  3-Tier Binding    │             │
│                    │ N-API > WASM > TS  │             │
│                    └─────────┬─────────┘             │
│                              │                       │
│                    ┌─────────┴─────────┐             │
│                    │   Zig Core Lib     │             │
│                    │   (libocshield)    │             │
│                    └───────────────────┘             │
└─────────────────────────────────────────────────────┘
```

### Primary: Node N-API Shared Library
- Zig compiles to a shared library (`.so` / `.dylib` / `.dll`) with N-API exports
- TypeScript bridge loads it via `require('./libocshield.node')`
- Fastest path — zero serialization overhead for string scanning

### Fallback: WASM Module
- Same Zig source compiles to `ocshield.wasm`
- TypeScript bridge loads via `WebAssembly.instantiate()`
- More portable, runs in any WASM runtime

### Last Resort: Pure TypeScript
- Pattern matching re-implemented in TypeScript
- No native dependencies — works everywhere Node.js runs
- Slower, but functionally identical

### Standalone: CLI Binary
- Zig compiles to a standalone `ocshield` binary
- Can be used outside OpenClaw for CI/CD pipelines, git hooks, etc.

All targets share the **same Zig source code** — only the entry point differs.

---

## 5. Expanded Capabilities

Beyond the original 5 layers, this port adds:

### 5.1 Entropy-Based Secret Detection
Shannon entropy analysis to detect high-entropy strings that don't match known patterns:
- Base64-encoded blobs with entropy > 4.5 bits/char
- Hex strings with entropy > 3.5 bits/char
- Configurable thresholds per context

### 5.2 International PII Patterns
- **UK**: National Insurance Number (NIN), NHS number
- **EU**: VAT numbers, national ID formats
- **Canada**: SIN (Social Insurance Number)
- **Australia**: TFN (Tax File Number), Medicare number
- **Passport numbers**: Generic pattern for common formats
- **IP addresses**: IPv4 and IPv6
- **MAC addresses**: Hardware identification
- **Date of birth patterns**: Common DOB formats

### 5.3 Skill Trust Analysis
Static analysis of skill/plugin code:
- Detect `child_process` usage, `eval()`, `new Function()`
- Detect crypto-mining patterns (stratum URLs, coinhive, xmrig)
- Detect data exfiltration patterns (file read + network send)
- Detect obfuscated code (hex-encoded strings, large base64)
- Detect environment variable harvesting (`process.env` + network)
- Prompt injection detection (6 patterns)
- Privilege escalation detection (sudo, chmod, chown)

### 5.4 Configurable Policy Engine
Declarative policy format:
- JSON configuration with per-pattern overrides
- 4 deployment profiles (home-lab, corp-dev, prod, research)
- Runtime profile switching without restart
- Policy file auto-discovery and validation

### 5.5 L7: Preventive Boundary Enforcement
Intercepts side-effect APIs *before* execution:
- **Network**: fetch, http/https.request, net/tls.connect (7 hooks)
- **Process**: spawn, spawnSync, execFile, execFileSync, exec, execSync, fork (7 hooks)
- **Filesystem**: readFile, readFileSync, writeFile, writeFileSync, open, openSync, createReadStream, createWriteStream (8 hooks)
- **DNS**: lookup, resolve, resolve4, resolve6, resolveMx, resolveTxt, resolveSrv, resolveCname, resolveNs (9 hooks)
- **Tamper detection**: 26 frozen function references, 1s check interval

### 5.6 Redaction Strategies
Configurable redaction:
- `mask`: Replace with `[REDACTED:type]` (default)
- `partial`: Show first/last N characters (`sk-...abc123`)
- `hash`: Replace with deterministic hash (allows correlation without exposure)
- `drop`: Remove the entire containing field

---

## 6. Project Structure

```
zig-oc-shield/
├── docs/
│   ├── PLAN.md                      # This document
│   └── DEPLOYMENT.md                # Deployment guide
├── LICENSE                          # Apache 2.0 (with Knostic attribution)
├── NOTICE                           # Attribution notice
├── README.md                        # Project overview
├── build.zig                        # Zig build system
├── build.zig.zon                    # Zig package manifest
├── ocshield.json                    # Default policy config
│
├── src/                             # Zig source code (32 files)
│   ├── lib.zig                      # Library root — public API surface
│   ├── main.zig                     # CLI binary entry point
│   ├── wasm_entry.zig               # WASM entry point
│   │
│   ├── core/                        # Core scanning engine
│   │   ├── scanner.zig              # Main scan/redact functions
│   │   ├── pattern.zig              # Pattern definition and matching
│   │   └── entropy.zig              # Shannon entropy analysis
│   │
│   ├── patterns/                    # Pattern definitions (36+ matchers)
│   │   ├── secrets.zig              # 15 secret patterns
│   │   ├── pii.zig                  # 6 US PII patterns
│   │   ├── pii_intl.zig             # 9 international PII patterns
│   │   ├── destructive.zig          # 7 destructive command patterns
│   │   ├── sensitive_files.zig      # 18 sensitive file path patterns
│   │   ├── skill_threats.zig        # 7 skill threat patterns
│   │   └── prompt_injection.zig     # 6 prompt injection patterns
│   │
│   ├── layers/                      # Defense layers L1–L6
│   │   ├── config.zig               # Layer configuration
│   │   ├── prompt_guard.zig         # L1: System prompt injection
│   │   ├── output_scanner.zig       # L2: Tool result redaction
│   │   ├── tool_blocker.zig         # L3: Pre-execution blocking
│   │   ├── input_audit.zig          # L4: Inbound message auditing
│   │   ├── security_gate.zig        # L5: Gate tool logic
│   │   └── rate_limiter.zig         # L6: Rate limiting
│   │
│   ├── enforcement/                 # L7: Preventive enforcement
│   │   ├── ip_ranges.zig            # IP classification (RFC1918, metadata, etc.)
│   │   ├── domain.zig               # Host allowlist matching
│   │   ├── counters.zig             # Sliding window rate limiting
│   │   ├── taint_policy.zig         # Taint state machine
│   │   ├── net.zig                  # Network decision function
│   │   ├── proc.zig                 # Process decision function
│   │   └── reason_codes.zig         # Stable numeric reason codes
│   │
│   └── policy/                      # Policy engine
│       ├── types.zig                # Policy types
│       ├── validator.zig            # Config validation
│       ├── loader.zig               # JSON policy loader
│       ├── engine.zig               # Policy evaluation
│       └── hardening.zig            # 33 hardening tests
│
├── bridge/                          # TypeScript bridge (@ocshield/bridge)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts                 # Plugin entry point, profile resolution
│   │   ├── native.ts                # 3-tier binding loader (N-API > WASM > pure-TS)
│   │   ├── types.ts                 # Shared types (Decision, ReasonCode, Config)
│   │   ├── policy.ts                # Policy file discovery and validation
│   │   └── intercept/
│   │       ├── net.ts               # Network interceptors (7 hooks)
│   │       ├── proc.ts              # Process interceptors (7 hooks)
│   │       ├── fs.ts                # Filesystem interceptors (8 hooks)
│   │       ├── dns.ts               # DNS interceptors (9 hooks)
│   │       ├── freeze.ts            # Tamper detection (26 frozen refs)
│   │       └── state.ts             # Session state manager
│   └── test/
│       └── jiti-integration.mjs     # 44 integration tests
│
├── examples/                        # Profile configs
│   ├── ocshield-home-lab.json
│   ├── ocshield-corp-dev.json
│   ├── ocshield-prod.json
│   └── ocshield-research.json
│
└── .github/workflows/
    ├── ci.yml                       # PR/push CI (Zig + Node matrix)
    └── release.yml                  # Tag-triggered release builds
```

---

## 7. Module Design

### 7.1 Pattern Matching Engine (`src/core/pattern.zig`)

Custom pattern matcher optimized for security scanning — no regex:

```zig
pub const Pattern = struct {
    name: []const u8,         // e.g., "aws_access_key"
    category: Category,       // .secret, .pii, .destructive, .sensitive_file, .skill_threat
    severity: Severity,       // .critical, .warning, .info
    matcher: Matcher,         // The matching strategy
};
```

**Matching strategies** (in order of preference):
1. **Prefix match**: For patterns with known prefixes (`AKIA`, `ghp_`, `sk-ant-`, `xox`)
2. **Prefix + charset validation**: Prefix match followed by character class check
3. **Literal match**: Exact string comparison (for keywords like `rm`, `format`)
4. **State machine**: Pre-compiled DFA for complex patterns (PII formats, JWTs)

All strategies are O(n) — no backtracking, bounded execution.

### 7.2 Scanner (`src/core/scanner.zig`)

```zig
pub fn scan(input: []const u8, patterns: []const Pattern, allocator: Allocator) !ScanResult
pub fn redact(input: []const u8, matches: []const Match, options: RedactOptions, allocator: Allocator) ![]u8
pub fn scanAndRedact(input: []const u8, patterns: []const Pattern, options: RedactOptions, allocator: Allocator) !struct { redacted: []u8, matches: []const Match }
pub fn walkJson(json_bytes: []const u8, patterns: []const Pattern, options: RedactOptions, allocator: Allocator) ![]u8
```

### 7.3 Entropy Analyzer (`src/core/entropy.zig`)

```zig
pub fn shannonEntropy(data: []const u8) f64
pub fn detectHighEntropy(input: []const u8, config: EntropyConfig) []EntropyFlag
```

### 7.4 L7 Decision Functions (pure, no I/O)

```zig
pub fn decideNetConnect(host: []const u8, port: u16, taint: TaintState, ...) Decision
pub fn decideSpawn(binary: []const u8, taint: TaintState, ...) Decision
```

---

## 8. Build System

Three build targets from the same source:

```bash
zig build           # CLI binary → zig-out/bin/ocshield
zig build wasm      # WASM module → zig-out/bin/ocshield.wasm
zig build test      # Run 362 unit tests

# Cross-compile
zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
```

---

## 9. TypeScript Bridge

The bridge implements the OpenClaw plugin interface and provides L7 enforcement via
monkey-patching Node.js built-in modules.

### Interceptor Coverage (31 hooks total)

| Layer | Module | Hooks |
|-------|--------|-------|
| Network | `net.ts` | fetch, http.request, https.request, net.connect, tls.connect, http.get, https.get |
| Process | `proc.ts` | spawn, spawnSync, execFile, execFileSync, exec, execSync, fork |
| Filesystem | `fs.ts` | readFile, readFileSync, writeFile, writeFileSync, open, openSync, createReadStream, createWriteStream |
| DNS | `dns.ts` | lookup, resolve, resolve4, resolve6, resolveMx, resolveTxt, resolveSrv, resolveCname, resolveNs |
| Tamper | `freeze.ts` | 26 frozen references, 1s detection interval |

### jiti Compatibility
- Uses `require()` for mutable CJS module references (ESM namespaces have `configurable: false`)
- `Object.defineProperty` freeze uses `configurable: true` to allow shutdown/reinit
- Tamper detection loop-checks all 26 references every second

---

## 10. Configuration

See `docs/DEPLOYMENT.md` for the full configuration reference.

### Security Profiles

| Profile | Mode | Network | Process | Filesystem | DNS |
|---------|------|---------|---------|------------|-----|
| `home-lab` | audit | all open | all open | sensitive blocked | all open |
| `corp-dev` | enforce | corp only | allowlist | write-controlled | corp only |
| `prod` | enforce | locked down | no spawn | all writes blocked | locked down |
| `research` | enforce | open network | allowlist | write-controlled | open |

### Reason Codes (stable, never reordered)

| Code | Name | Category |
|------|------|----------|
| 1001–1007 | NET_* | Network blocks |
| 1101–1103 | PROC_* | Process blocks |
| 1201 | RATE_LIMIT_EXCEEDED | Rate limiting |
| 1301–1302 | TAINT_*/QUARANTINED | Taint escalation |
| 1401–1403 | FS_* | Filesystem blocks |
| 1501–1502 | DNS_* | DNS blocks |

---

## 11. Testing Strategy

### Zig Tests (362 tests)
- Pattern matching: every pattern type, boundary conditions, unicode, adversarial input
- Scanner: scan, redact, scanAndRedact, walkJson
- Entropy: Shannon entropy, high-entropy detection, edge cases
- Layers L1–L6: each layer independently
- Enforcement: IP classification, domain matching, counters, taint escalation
- Policy: validation, loading, per-pattern overrides
- Hardening: 33 adversarial tests (malformed JSON, huge inputs, etc.)

### jiti Integration Tests (44 tests)
- Module loading and export verification (9 tests)
- Config resolution across all 4 profiles (5 tests)
- Policy validation with errors/warnings (5 tests)
- Native binding pure-TS fallback (9 tests)
- State manager taint tracking and audit export (4 tests)
- OpenClaw register() simulation with mock API (8 tests)
- Lifecycle init/shutdown idempotency (3 tests)
- Policy flags encoding (1 test)

### CI Pipeline
- **Zig job**: Install Zig 0.13.0 → build CLI → build WASM → run 362 tests
- **Bridge job**: Node 18/20/22 matrix → type check → build → 44 jiti tests
- **Release job**: Cross-compile 4 platforms + gateway package on tag push

---

## 12. Implementation Phases

### Phase 1: Core Scanner ✅
- Pattern type and matching engine (prefix, charset, literal, state machine)
- 15 secret + 6 PII + 7 destructive + 18 sensitive file patterns
- scan(), redact(), scanAndRedact(), walkJson()
- Shannon entropy analyzer
- CLI binary

### Phase 2: Defense Layers ✅
- L1–L6: prompt guard, output scanner, tool blocker, input audit, security gate, rate limiter
- L7: Preventive enforcement (ip_ranges, domain, counters, taint_policy, net, proc, reason_codes)

### Phase 3: Expanded Detection ✅
- 9 international PII patterns, 7 skill threat patterns, 6 prompt injection patterns

### Phase 4: WASM Bridge & TypeScript Interceptors ✅
- WASM entry point with packed u64 decision encoding
- TypeScript bridge with 3-tier binding (N-API > WASM > pure-TS)
- Network + process interceptors with tamper detection
- Profile resolution, operator commands, session state manager

### Phase 5: Policy Engine & Hardening ✅
- JSON policy configuration with validation
- Per-pattern redaction overrides
- 33 hardening tests

### Phase 6: Packaging & CI/CD ✅
- Example configs for all 4 profiles
- CI pipeline (Zig + Node matrix)
- Release workflow with cross-compiled binaries + gateway package
- Default `ocshield.json` with filesystem and DNS sections
- Deployment documentation

### Security Hardening ✅
- Prototype pollution guard in deepMerge
- Audit log cap (10K entries, evict oldest 25%)
- Complete child_process coverage (all 7 APIs)
- SSRF via hex/octal/decimal IP encoding bypass
- Filesystem interceptor (8 hooks, sensitive path + write + traversal)
- DNS interceptor (9 hooks, domain allowlist + rebinding detection)
- 26 frozen tamper-detection references, 1s check interval

### Phase 7: OpenClaw Plugin Registration (future)
- [ ] Hook wiring into live OpenClaw lifecycle
- [ ] npm publish `@ocshield/bridge`
- [ ] OpenClaw plugin registry submission

**Current stats**: 362 Zig tests + 44 jiti tests, v0.0.1, 36+ pattern matchers, 7 defense layers, 31 interceptor hooks

---

## 13. Attribution

This project is a derivative work based on
[openclaw-shield](https://github.com/knostic/openclaw-shield) by
[Knostic](https://knostic.ai/), licensed under the Apache License 2.0.

**Original authors**: Knostic (https://knostic.ai/)
**Original repository**: https://github.com/knostic/openclaw-shield
**Original license**: Apache 2.0

All modifications are clearly marked. The original pattern definitions, layer
architecture, and defense-in-depth approach are credited to Knostic's work.

This port extends the original with Zig-native implementation, expanded pattern
coverage, entropy-based detection, L7 preventive enforcement (network, process,
filesystem, DNS), configurable policy engine, and tamper-resistant interceptors.
