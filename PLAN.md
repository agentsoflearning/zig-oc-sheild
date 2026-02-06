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
│                    │   Node N-API       │             │
│                    │   (.node addon)    │             │
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
- N-API is stable across Node.js versions

### Fallback: WASM Module
- Same Zig source compiles to `ocshield.wasm`
- TypeScript bridge loads via `WebAssembly.instantiate()`
- More portable, runs in any WASM runtime
- Slightly slower due to WASM sandbox overhead

### Standalone: CLI Binary
- Zig compiles to a standalone `ocshield` binary
- Can be used outside OpenClaw for CI/CD pipelines, git hooks, etc.
- TypeScript bridge can invoke via `child_process` as last resort

All three targets share the **same Zig source code** — only the entry point differs.

---

## 5. Expanded Capabilities

Beyond the original 5 layers, this port adds:

### 5.1 Entropy-Based Secret Detection
The original relies solely on regex patterns. We add **Shannon entropy analysis** to
detect high-entropy strings that look like secrets but don't match known patterns:
- Base64-encoded blobs with entropy > 4.5 bits/char
- Hex strings with entropy > 3.5 bits/char
- Configurable thresholds per context

### 5.2 International PII Patterns
Expand beyond US-centric detection:
- **UK**: National Insurance Number (NIN), NHS number
- **EU**: VAT numbers, national ID formats
- **Canada**: SIN (Social Insurance Number)
- **Australia**: TFN (Tax File Number), Medicare number
- **Passport numbers**: Generic pattern for common formats
- **IP addresses**: IPv4 and IPv6 (can indicate infrastructure leaks)
- **MAC addresses**: Hardware identification
- **Date of birth patterns**: Common DOB formats

### 5.3 Skill Trust Analysis
Static analysis of skill/plugin code (mirroring OpenClaw's built-in `skill-scanner.ts`
but running in Zig for performance):
- Detect `child_process` usage, `eval()`, `new Function()`
- Detect crypto-mining patterns (stratum URLs, coinhive, xmrig)
- Detect data exfiltration patterns (file read + network send)
- Detect obfuscated code (hex-encoded strings, large base64)
- Detect environment variable harvesting (`process.env` + network)
- **New**: Detect prompt injection patterns in skill definitions
- **New**: Detect privilege escalation attempts (sudo, chmod, chown patterns)

### 5.4 Data Flow Tracking
Track sensitive data as it flows through the system:
- Tag detected secrets/PII with unique IDs at first detection
- Track if the same secret appears in multiple contexts (input → tool → output)
- Alert if a secret detected in a tool result appears in an outbound message
- Maintain a session-scoped taint map (cleared on session end)

### 5.5 Rate Limiting for Sensitive Operations
Prevent rapid-fire sensitive operations that may indicate automated attacks:
- Configurable rate limits per tool (e.g., max 5 `exec` calls per minute)
- Burst detection for file reads on sensitive paths
- Escalating response: warn → throttle → block

### 5.6 Configurable Policy Engine
Move from hardcoded patterns to a declarative policy format:
- Policies defined in TOML/JSON configuration
- Support for allow/deny lists per channel, per user, per session
- Policy inheritance (global → channel → user)
- Runtime policy reloading without restart

### 5.7 Structured Audit Log
Replace `console.log` with a structured, append-only audit log:
- Binary format for performance, with human-readable export
- Fields: timestamp, layer, action, finding, context, session_key, channel
- Log rotation and size limits
- Query interface for security review

### 5.8 Redaction Strategies
Configurable redaction beyond simple replacement:
- `mask`: Replace with `[REDACTED:type]` (default, matches original)
- `partial`: Show first/last N characters (`sk-...abc123`)
- `hash`: Replace with deterministic hash (allows correlation without exposure)
- `tokenize`: Replace with reversible token (for authorized recovery)
- `drop`: Remove the entire containing message/field

---

## 6. Project Structure

```
zig-oc-shield/
├── PLAN.md                          # This document
├── LICENSE                          # Apache 2.0 (with Knostic attribution)
├── README.md                        # Project overview and usage
├── build.zig                        # Zig build system
├── build.zig.zon                    # Zig package manifest
│
├── src/                             # Zig source code
│   ├── lib.zig                      # Library root — public API surface
│   ├── main.zig                     # CLI binary entry point
│   │
│   ├── core/                        # Core scanning engine
│   │   ├── scanner.zig              # Main scan/redact functions
│   │   ├── pattern.zig              # Pattern definition and matching
│   │   ├── entropy.zig              # Shannon entropy analysis
│   │   └── taint.zig                # Data flow taint tracking
│   │
│   ├── patterns/                    # Pattern definitions
│   │   ├── secrets.zig              # Secret detection patterns (API keys, tokens, etc.)
│   │   ├── pii.zig                  # PII detection patterns (SSN, email, phone, etc.)
│   │   ├── pii_intl.zig             # International PII patterns
│   │   ├── destructive.zig          # Destructive command patterns
│   │   ├── sensitive_files.zig      # Sensitive file path patterns
│   │   └── skill_threats.zig        # Malicious skill/plugin patterns
│   │
│   ├── layers/                      # Defense layers (maps to OpenClaw hooks)
│   │   ├── prompt_guard.zig         # L1: System prompt injection
│   │   ├── output_scanner.zig       # L2: Tool result redaction
│   │   ├── tool_blocker.zig         # L3: Pre-execution tool blocking
│   │   ├── input_audit.zig          # L4: Inbound message auditing
│   │   ├── security_gate.zig        # L5: Gate tool logic
│   │   └── rate_limiter.zig         # L6: Rate limiting (new)
│   │
│   ├── policy/                      # Policy engine
│   │   ├── engine.zig               # Policy evaluation
│   │   ├── config.zig               # Policy configuration parsing
│   │   └── types.zig                # Policy types
│   │
│   ├── audit/                       # Audit logging
│   │   ├── logger.zig               # Structured audit logger
│   │   └── format.zig               # Log format and serialization
│   │
│   ├── napi/                        # Node N-API bindings
│   │   └── exports.zig              # N-API function exports
│   │
│   └── wasm/                        # WASM entry point
│       └── exports.zig              # WASM function exports
│
├── bridge/                          # TypeScript bridge (thin wrapper)
│   ├── package.json                 # npm package metadata
│   ├── openclaw.plugin.json         # OpenClaw plugin manifest
│   ├── src/
│   │   ├── index.ts                 # Plugin entry point
│   │   ├── native.ts                # N-API binding loader
│   │   └── wasm.ts                  # WASM fallback loader
│   └── tsconfig.json
│
├── test/                            # Test suites
│   ├── patterns/                    # Pattern matching tests
│   │   ├── test_secrets.zig
│   │   ├── test_pii.zig
│   │   ├── test_pii_intl.zig
│   │   ├── test_destructive.zig
│   │   └── test_sensitive_files.zig
│   ├── core/                        # Core engine tests
│   │   ├── test_scanner.zig
│   │   ├── test_entropy.zig
│   │   └── test_taint.zig
│   ├── layers/                      # Layer integration tests
│   │   ├── test_prompt_guard.zig
│   │   ├── test_output_scanner.zig
│   │   └── test_security_gate.zig
│   ├── policy/                      # Policy engine tests
│   │   └── test_engine.zig
│   └── fixtures/                    # Test data
│       ├── secrets.txt
│       ├── pii_samples.txt
│       └── skill_samples/
│
└── docs/                            # Documentation
    ├── architecture.md              # Detailed architecture docs
    ├── patterns.md                  # Pattern reference
    ├── configuration.md             # Configuration guide
    └── openclaw-integration.md      # OpenClaw plugin integration guide
```

---

## 7. Module Design

### 7.1 Pattern Matching Engine (`src/core/pattern.zig`)

The core of the scanner. Unlike the original which uses JavaScript RegExp, we implement
a custom pattern matcher optimized for security scanning:

```zig
pub const Pattern = struct {
    name: []const u8,         // e.g., "aws_access_key"
    category: Category,       // .secret, .pii, .destructive, .sensitive_file, .skill_threat
    severity: Severity,       // .critical, .warning, .info
    matcher: Matcher,         // The matching strategy

    pub const Category = enum { secret, pii, destructive, sensitive_file, skill_threat };
    pub const Severity = enum { critical, warning, info };
    pub const Matcher = union(enum) {
        literal: []const u8,           // Exact string match (fastest)
        prefix: []const u8,            // Prefix match (e.g., "AKIA" for AWS keys)
        prefix_then_charset: PrefixCharset, // Prefix + character class validation
        state_machine: *const StateMachine, // Pre-compiled DFA for complex patterns
    };
};

pub const Match = struct {
    pattern_name: []const u8,
    category: Pattern.Category,
    severity: Pattern.Severity,
    start: usize,
    end: usize,
    preview: []const u8,      // Truncated to 12 chars
};
```

**Matching strategies** (in order of preference):
1. **Prefix match**: For patterns with known prefixes (`AKIA`, `ghp_`, `sk-ant-`, `xox`)
2. **Prefix + charset validation**: Prefix match followed by character class check (avoids regex entirely for most secret patterns)
3. **Literal match**: Exact string comparison (for keywords like `rm`, `format`)
4. **State machine**: Pre-compiled DFA for complex patterns (PII formats, JWTs). No backtracking — bounded O(n) execution time

### 7.2 Scanner (`src/core/scanner.zig`)

```zig
pub const ScanResult = struct {
    matches: []const Match,
    entropy_flags: []const EntropyFlag,
    taint_ids: []const TaintId,
};

pub const RedactOptions = struct {
    strategy: RedactStrategy,
    tag: []const u8,
};

pub const RedactStrategy = enum {
    mask,       // [REDACTED:pattern_name]
    partial,    // sk-...abc123
    hash,       // [SHA256:a1b2c3d4]
    drop,       // (empty string)
};

/// Scan a byte slice for all patterns. Returns matches sorted by position.
pub fn scan(input: []const u8, patterns: []const Pattern, allocator: Allocator) !ScanResult

/// Redact all matches in-place, returning the redacted output.
pub fn redact(input: []const u8, matches: []const Match, options: RedactOptions, allocator: Allocator) ![]u8

/// Scan and redact in a single pass (more efficient than scan + redact separately).
pub fn scanAndRedact(input: []const u8, patterns: []const Pattern, options: RedactOptions, allocator: Allocator) !struct { redacted: []u8, matches: []const Match }

/// Deep-walk a JSON value, scanning/redacting all string leaves.
pub fn walkJson(json_bytes: []const u8, patterns: []const Pattern, options: RedactOptions, allocator: Allocator) ![]u8
```

### 7.3 Entropy Analyzer (`src/core/entropy.zig`)

```zig
pub const EntropyFlag = struct {
    start: usize,
    end: usize,
    entropy: f64,           // Shannon entropy in bits/char
    encoding: Encoding,
    confidence: f64,        // 0.0 - 1.0

    pub const Encoding = enum { base64, hex, raw };
};

/// Calculate Shannon entropy of a byte slice.
pub fn shannonEntropy(data: []const u8) f64

/// Scan for high-entropy substrings that may be undiscovered secrets.
pub fn detectHighEntropy(input: []const u8, config: EntropyConfig) []EntropyFlag
```

### 7.4 Taint Tracker (`src/core/taint.zig`)

```zig
pub const TaintId = u64;  // Hash-based identifier for a detected secret

pub const TaintEntry = struct {
    id: TaintId,
    first_seen_layer: Layer,
    first_seen_context: []const u8,
    pattern_name: []const u8,
    seen_count: u32,
};

pub const TaintMap = struct {
    /// Record a new detection. Returns the taint ID.
    pub fn record(self: *TaintMap, match: Match, layer: Layer, context: []const u8) TaintId

    /// Check if a string contains any previously tainted values.
    pub fn check(self: *TaintMap, input: []const u8) []const TaintEntry

    /// Clear all entries (call on session end).
    pub fn clear(self: *TaintMap) void
};
```

### 7.5 Layer Implementations

Each layer is a pure function that takes input and configuration, returns a result:

```zig
// L1: Prompt Guard
pub fn generateSecurityPrompt(config: PolicyConfig) []const u8

// L2: Output Scanner
pub fn scanToolResult(result_json: []const u8, patterns: []const Pattern, options: RedactOptions, allocator: Allocator) !ScanAndRedactResult

// L3: Tool Blocker
pub fn evaluateToolCall(tool_name: []const u8, params_json: []const u8, policy: PolicyConfig) ToolDecision

// L4: Input Audit
pub fn auditMessage(message: []const u8, patterns: []const Pattern, allocator: Allocator) !AuditEntry

// L5: Security Gate
pub fn evaluateGateRequest(request: GateRequest, policy: PolicyConfig) GateDecision

// L6: Rate Limiter
pub fn checkRateLimit(operation: Operation, session: []const u8, limiter: *RateLimiter) RateLimitDecision
```

---

## 8. Build System

### `build.zig`

Three build targets from the same source:

```zig
// Target 1: Shared library for Node N-API
const napi_lib = b.addSharedLibrary(.{
    .name = "ocshield",
    .root_source_file = "src/napi/exports.zig",
    .target = target,
    .optimize = optimize,
});

// Target 2: WASM module
const wasm = b.addSharedLibrary(.{
    .name = "ocshield",
    .root_source_file = "src/wasm/exports.zig",
    .target = .{ .cpu_arch = .wasm32, .os_tag = .freestanding },
    .optimize = .ReleaseSmall,
});

// Target 3: CLI binary
const exe = b.addExecutable(.{
    .name = "ocshield",
    .root_source_file = "src/main.zig",
    .target = target,
    .optimize = optimize,
});

// Target 4: Test suite
const tests = b.addTest(.{
    .root_source_file = "src/lib.zig",
    .target = target,
});
```

### Build Commands

```bash
# Build shared library (for Node N-API)
zig build lib

# Build WASM module
zig build wasm

# Build CLI binary
zig build cli

# Run all tests
zig build test

# Build everything
zig build all

# Cross-compile for specific target
zig build lib -Dtarget=aarch64-linux-gnu
zig build lib -Dtarget=x86_64-macos
zig build lib -Dtarget=x86_64-windows-gnu
```

---

## 9. TypeScript Bridge

The bridge is a thin TypeScript wrapper that implements the OpenClaw plugin interface
and delegates all scanning/decision logic to the Zig core:

### `bridge/src/index.ts`

```typescript
// Thin wrapper — all logic lives in Zig
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { loadNative, loadWasm, type ShieldCore } from "./native.js";

export default {
  id: "zig-oc-shield",
  name: "OpenClaw Shield (Zig)",
  version: "0.2.0",
  description: "Zig-native security shield — blocks destructive commands, redacts secrets/PII",

  async register(api: OpenClawPluginApi) {
    const core: ShieldCore = await loadNative() ?? await loadWasm();
    const config = api.pluginConfig ?? {};

    // L1: Prompt Guard
    api.on("before_agent_start", async () => ({
      prependContext: core.generateSecurityPrompt(config),
    }), { priority: 100 });

    // L2: Output Scanner
    api.on("tool_result_persist", (event) => {
      const result = core.scanAndRedactJson(JSON.stringify(event.result), config);
      if (result.matches.length > 0) {
        return { result: JSON.parse(result.redacted) };
      }
    });

    // L3: Tool Blocker
    api.on("before_tool_call", async (event) => {
      const decision = core.evaluateToolCall(event.toolName, JSON.stringify(event.params), config);
      if (decision.blocked) {
        return { block: true, blockReason: decision.reason };
      }
    }, { priority: 200 });

    // L4: Input Audit
    api.on("message_received", async (event) => {
      const audit = core.auditMessage(event.body, config);
      if (audit.findings.length > 0) {
        api.logger.warn(`[zig-oc-shield] Input contains ${audit.findings.length} sensitive items`);
      }
    }, { priority: 50 });

    // L5: Security Gate Tool
    api.registerTool(core.createGateTool(config));

    api.logger.info("[zig-oc-shield] All layers active");
  },
};
```

### `bridge/src/native.ts`

```typescript
export interface ShieldCore {
  generateSecurityPrompt(config: unknown): string;
  scanAndRedactJson(json: string, config: unknown): { redacted: string; matches: Match[] };
  evaluateToolCall(name: string, params: string, config: unknown): { blocked: boolean; reason?: string };
  auditMessage(body: string, config: unknown): { findings: Finding[] };
  createGateTool(config: unknown): AnyAgentTool;
}

export async function loadNative(): Promise<ShieldCore | null> {
  try {
    const addon = require("../build/ocshield.node");
    return addon as ShieldCore;
  } catch {
    return null;
  }
}

export async function loadWasm(): Promise<ShieldCore> {
  const wasmBytes = await readFile(join(__dirname, "../build/ocshield.wasm"));
  const { instance } = await WebAssembly.instantiate(wasmBytes);
  // ... wrap WASM exports in ShieldCore interface
}
```

---

## 10. Configuration

### Plugin Configuration Schema (`openclaw.plugin.json`)

```json
{
  "id": "zig-oc-shield",
  "name": "OpenClaw Shield (Zig)",
  "description": "Zig-native security shield — blocks destructive commands, redacts secrets and PII",
  "version": "0.2.0",
  "configSchema": {
    "type": "object",
    "properties": {
      "mode": {
        "type": "string",
        "enum": ["enforce", "audit"],
        "default": "enforce",
        "description": "enforce = block+redact, audit = log only"
      },
      "layers": {
        "type": "object",
        "properties": {
          "promptGuard":    { "type": "boolean", "default": true },
          "outputScanner":  { "type": "boolean", "default": true },
          "toolBlocker":    { "type": "boolean", "default": true },
          "inputAudit":     { "type": "boolean", "default": true },
          "securityGate":   { "type": "boolean", "default": true },
          "rateLimiter":    { "type": "boolean", "default": true }
        }
      },
      "redaction": {
        "type": "object",
        "properties": {
          "strategy": { "type": "string", "enum": ["mask", "partial", "hash", "drop"], "default": "mask" },
          "partialChars": { "type": "integer", "default": 4 }
        }
      },
      "entropy": {
        "type": "object",
        "properties": {
          "enabled":        { "type": "boolean", "default": true },
          "base64Threshold": { "type": "number", "default": 4.5 },
          "hexThreshold":   { "type": "number", "default": 3.5 }
        }
      },
      "pii": {
        "type": "object",
        "properties": {
          "regions": {
            "type": "array",
            "items": { "type": "string", "enum": ["us", "uk", "eu", "ca", "au"] },
            "default": ["us"]
          }
        }
      },
      "rateLimits": {
        "type": "object",
        "properties": {
          "execPerMinute":     { "type": "integer", "default": 10 },
          "sensitiveReadPerMinute": { "type": "integer", "default": 5 }
        }
      },
      "sensitiveFilePaths":   { "type": "array", "items": { "type": "string" } },
      "destructiveCommands":  { "type": "array", "items": { "type": "string" } },
      "auditLog": {
        "type": "object",
        "properties": {
          "enabled":   { "type": "boolean", "default": true },
          "path":      { "type": "string", "default": ".openclaw/shield-audit.log" },
          "maxSizeMb": { "type": "integer", "default": 50 }
        }
      }
    }
  }
}
```

---

## 11. Testing Strategy

### Unit Tests (Zig)
Every pattern and every scanner function has dedicated tests:

```zig
test "aws_access_key detects AKIA prefix" {
    const matches = scan("my key is AKIA1234567890ABCDEF", secret_patterns, allocator);
    try expect(matches.len == 1);
    try expectEqualStrings(matches[0].pattern_name, "aws_access_key");
}

test "us_ssn rejects 000 and 666 prefixes" {
    const matches = scan("000-12-3456", pii_patterns, allocator);
    try expect(matches.len == 0);
}

test "redact replaces with mask tag" {
    const result = scanAndRedact("key: sk-abc123def456ghi789", patterns, .{ .strategy = .mask, .tag = "REDACTED" }, allocator);
    try expectEqualStrings(result.redacted, "key: [REDACTED:openai_key]");
}
```

### Integration Tests
- End-to-end tests with mock OpenClaw plugin API
- Test each layer independently and all layers combined
- Adversarial prompt injection tests
- Performance benchmarks (scan throughput in MB/s)

### Fuzzing
- Zig's built-in fuzz testing on the scanner with random byte inputs
- Ensure no crashes, no unbounded memory growth, no false negatives on known patterns

---

## 12. Implementation Phases

### Phase 1: Core Scanner (Foundation)
**Goal**: Port all pattern definitions and scanning logic to Zig

- [ ] Set up `build.zig` with all targets (lib, wasm, cli, test)
- [ ] Implement `Pattern` type and matching engine
- [ ] Port all 15 secret patterns from `patterns.ts`
- [ ] Port all 6 PII patterns
- [ ] Port destructive command patterns
- [ ] Port 18 sensitive file path patterns
- [ ] Implement `scan()`, `redact()`, `scanAndRedact()` functions
- [ ] Implement `walkJson()` for deep object scanning
- [ ] Write comprehensive unit tests for all patterns
- [ ] Benchmark against TypeScript original

### Phase 2: Defense Layers
**Goal**: Implement all 5 original layers plus rate limiter

- [ ] L1: Prompt guard — security prompt generation
- [ ] L2: Output scanner — tool result scanning and redaction
- [ ] L3: Tool blocker — pre-execution evaluation
- [ ] L4: Input audit — inbound message scanning
- [ ] L5: Security gate — gate tool request evaluation
- [ ] L6: Rate limiter — sliding window rate limiting (new)
- [ ] Integration tests for each layer

### Phase 3: Expanded Detection
**Goal**: Add capabilities beyond the original

- [ ] Shannon entropy analyzer for unknown secrets
- [ ] International PII patterns (UK, EU, CA, AU)
- [ ] Skill trust analysis (static code scanning)
- [ ] Prompt injection detection patterns
- [ ] IP address and MAC address detection
- [ ] Privilege escalation pattern detection

### Phase 4: Infrastructure
**Goal**: Build the bridge and supporting systems

- [ ] N-API bindings (`src/napi/exports.zig`)
- [ ] WASM exports (`src/wasm/exports.zig`)
- [ ] CLI binary (`src/main.zig`)
- [ ] TypeScript bridge (`bridge/src/index.ts`)
- [ ] OpenClaw plugin manifest
- [ ] Structured audit logger
- [ ] Data flow taint tracking

### Phase 5: Policy Engine & Hardening
**Goal**: Configurable policies and production hardening

- [ ] Policy configuration parser (TOML/JSON)
- [ ] Policy evaluation engine
- [ ] Per-channel/user/session policies
- [ ] Multiple redaction strategies
- [ ] Fuzz testing
- [ ] Performance optimization (SIMD where applicable)
- [ ] Documentation

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
coverage, entropy-based detection, data flow tracking, rate limiting, and a
configurable policy engine.

---

## Appendix A — Preventive Layer for Exfiltration & Lateral Movement

### A.1 Threat Model Addendum

Layers L1–L6 are **reactive** — they scan content that has already been produced or
requested. They do not prevent an agent from:

| Threat | How it bypasses L1–L6 |
|--------|----------------------|
| **Data exfiltration** | Agent `fetch`es an attacker-controlled URL with secrets in body/query string |
| **Lateral movement** | Agent connects to internal services (RFC1918 / localhost / link-local) |
| **Cloud metadata theft** | Agent hits `169.254.169.254` (IMDS) to harvest IAM credentials |
| **Subprocess abuse** | Agent spawns unrestricted shells (`bash -c ...`) or crypto-miners |
| **Covert channels** | DNS exfil, large base64 payloads, slow-drip via multiple requests |

**L7 adds a preventive boundary**: intercept side-effect APIs (network, subprocess)
*before* they execute, consult the Zig decision engine, and allow/block/audit in
real-time.

### A.2 Policy Capsule

Every L7 decision receives a **PolicyCapsule** — an immutable snapshot of the
resolved policy for the current session:

```
PolicyCapsule {
    profile:          string          // "home-lab" | "corp-dev" | "prod" | "research"
    mode:             Mode            // enforce | audit
    taint_state:      TaintState      // CLEAN | TAINTED | QUARANTINED
    session_id:       string
    network: {
        allowed_hosts:    []HostSpec   // exact or wildcard
        allowed_ports:    []u16
        block_rfc1918:    bool
        block_localhost:  bool
        block_link_local: bool
        block_metadata:   bool
        max_egress_bytes_per_min: u64
    }
    process: {
        allow_spawn:      bool          // global toggle
        allowed_binaries: []string      // basename allowlist
        deny_shells:      bool          // block bash/sh/zsh/fish/cmd/powershell
        max_exec_per_min: u32
    }
    filesystem: {                       // v1.1+ enforcement
        writable_roots:   []string
        deny_dotfiles:    bool
    }
    taint: {
        auto_escalate:         bool
        quarantine_threshold:  u32      // block count before QUARANTINED
        cool_down_seconds:     u64      // quiet window for de-escalation
    }
}
```

### A.3 L7: Side-Effect Enforcement

L7 interposes on side-effect APIs at the TypeScript bridge layer, delegating
decisions to the Zig core for speed and consistency.

#### Interception Points (v1)

| API | Interceptor | What it checks |
|-----|-------------|----------------|
| `globalThis.fetch` | `bridge/src/intercept/net.ts` | host, port, payload size |
| `http.request` / `https.request` | `net.ts` | host, port, payload size |
| `net.connect` / `tls.connect` | `net.ts` | host, port |
| `child_process.spawn` / `.execFile` | `bridge/src/intercept/proc.ts` | binary name, argv |
| `child_process.exec` | `proc.ts` | discouraged; block or audit |

#### Interception Points (v1.1+, deferred)

| API | Notes |
|-----|-------|
| `fs.writeFile` / `fs.mkdir` | FS boundary enforcement |
| `dns.resolve` | DNS covert channel detection |
| Content-based DLP on outbound payloads | Slow path — beyond existing scanner |

### A.4 Exfiltration Controls

1. **Host allowlist**: Only connections to explicitly allowed hosts are permitted.
   - Exact match: `api.openai.com`
   - Wildcard: `*.slack.com` (suffix match)
   - Default: deny all unless profile overrides
2. **RFC1918 / localhost / link-local / metadata blocking**:
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` → blocked
   - `127.0.0.0/8`, `::1` → blocked
   - `169.254.0.0/16`, `fe80::/10` → blocked
   - `169.254.169.254` (AWS/GCP IMDS) → blocked
   - `fd00:ec2::254` (AWS IMDSv2 IPv6) → blocked
3. **Port allowlist**: Default `[80, 443]`; configurable per profile.
4. **Egress byte cap**: Sliding window rate limit on outbound bytes per session.

### A.5 Lateral Movement Controls

1. **Subprocess deny-by-default**: `child_process.spawn` is blocked unless the
   binary is in `allowed_binaries`.
2. **Shell denial**: `bash`, `sh`, `zsh`, `fish`, `cmd`, `powershell` are denied
   by default (prevents arbitrary command injection).
3. **Exec rate limit**: Max spawns per minute per session.
4. **FS boundary** (v1.1): Restrict writes to `writable_roots` only.

### A.6 Taint & Quarantine Escalation

Sessions progress through taint states:

```
CLEAN ──trigger──▶ TAINTED ──threshold──▶ QUARANTINED
  ▲                   │                        │
  └── cool_down ──────┘                        │
                                               ▼
                                    All side-effects blocked.
                                    Operator must unquarantine.
```

**Triggers** (CLEAN → TAINTED):
- Secret detected in output
- High-entropy flag (high confidence)
- Blocked operation (any L7 deny)
- Untrusted content marker (from TS layer)

**Escalation** (TAINTED → QUARANTINED):
- Block count exceeds `quarantine_threshold`
- Critical severity finding (e.g., cloud metadata access attempt)

**De-escalation** (TAINTED → CLEAN):
- No triggers for `cool_down_seconds` (TS passes timestamps to Zig)

**QUARANTINED** sessions:
- All L7 operations blocked (network, process, FS)
- Requires operator `shield unquarantine <sessionId>` to resume

### A.7 New Zig Modules

```
src/enforcement/
  ip_ranges.zig      # RFC1918/localhost/link-local/metadata IP checks
  domain.zig         # Host parsing + allowlist/wildcard matching
  counters.zig       # Sliding window rate limiter (egress bytes + exec count)
  taint_policy.zig   # Taint state machine (CLEAN/TAINTED/QUARANTINED)
  net.zig            # decideNetConnect() — top-level network decision
  proc.zig           # decideSpawn() — top-level subprocess decision
  reason_codes.zig   # Stable numeric reason codes for audit
```

### A.8 Zig Decision API

```zig
pub const Decision = struct {
    allow: bool,
    reason_code: u32,
    risk: enum { low, medium, high },
    taint_update: ?TaintState,
};

pub fn decideNetConnect(capsule: PolicyCapsule, host: []const u8, port: u16, bytes_planned: u32) Decision
pub fn decideSpawn(capsule: PolicyCapsule, argv_json: []const u8) Decision
```

Decisions are **deterministic** — given the same capsule + inputs, the result is
always identical. No I/O, no randomness, no system calls.

### A.9 TypeScript Bridge Interceptors

```
bridge/src/intercept/
  net.ts       # Patches fetch, http.request, net.connect, tls.connect
  proc.ts      # Patches child_process.spawn, execFile
  freeze.ts    # Object.defineProperty freeze + tamper detection
  state.ts     # Session taint state management
```

### A.10 Config Schema Additions

```json
{
  "network": {
    "allowedHosts": ["api.openai.com", "*.anthropic.com"],
    "allowedPorts": [80, 443],
    "blockRFC1918": true,
    "blockLocalhost": true,
    "blockLinkLocal": true,
    "blockMetadata": true,
    "maxEgressBytesPerMin": 10485760
  },
  "process": {
    "allowSpawn": false,
    "allowedBinaries": ["git", "node", "npx"],
    "denyShells": true,
    "maxExecPerMin": 10
  },
  "taint": {
    "autoEscalate": true,
    "quarantineThreshold": 5,
    "coolDownSeconds": 300
  },
  "profile": "prod"
}
```

### A.11 Testing Additions

| Test category | Examples |
|--------------|---------|
| IP classification | RFC1918 ranges, edge cases (10.0.0.0, 10.255.255.255), IPv6 |
| Domain matching | Exact, wildcard, normalization, trailing dot |
| Counter enforcement | Byte accumulation, exec counting, window expiry |
| Taint escalation | CLEAN→TAINTED→QUARANTINED, de-escalation timing |
| Net decision | Allowed host, blocked IP, blocked port, rate limited |
| Proc decision | Allowed binary, denied shell, rate limited |
| Integration (TS) | Patched fetch blocked, spawn blocked, freeze tamper detected |

---

## Appendix B — Phase Updates (Minimal Disruption)

The existing Phases 1–5 remain unchanged. Additions:

### Phase 4 Additions (Infrastructure)

Add to Phase 4's task list:

- [ ] N-API exports for `decideNetConnect`, `decideSpawn`, `setSessionTaint`, `getSessionState`
- [ ] WASM exports mirroring N-API
- [ ] TypeScript interceptors: `net.ts`, `proc.ts`, `freeze.ts`, `state.ts`
- [ ] Plugin profile resolution in `bridge/src/index.ts`

### Phase 6: Preventive Layer Shipping (NEW)

**Goal**: Ship L7 side-effect enforcement with network + process interception.

- [ ] `src/enforcement/ip_ranges.zig` — IP classification helpers
- [ ] `src/enforcement/domain.zig` — Allowlist matching with wildcard
- [ ] `src/enforcement/counters.zig` — Egress byte + exec count rate limiting
- [ ] `src/enforcement/taint_policy.zig` — Taint state machine
- [ ] `src/enforcement/net.zig` — `decideNetConnect` decision function
- [ ] `src/enforcement/proc.zig` — `decideSpawn` decision function
- [ ] `src/enforcement/reason_codes.zig` — Stable audit reason codes
- [ ] Operator commands: `shield status`, `quarantine`, `unquarantine`, `set-profile`
- [ ] Audit log JSONL export with reason codes
- [ ] Deployment profiles: `home-lab`, `corp-dev`, `prod`, `research`
- [ ] Integration tests: IP blocks, domain matching, counters, taint escalation
- [ ] Documentation: L7 architecture, configuration guide, profile reference

---

## Appendix C — Recommended Defaults, Deployment Profiles, and Break-Glass Ops

### C.1 Recommended Default Policy

```json
{
  "mode": "enforce",
  "profile": "prod",
  "layers": {
    "promptGuard": true,
    "outputScanner": true,
    "toolBlocker": true,
    "inputAudit": true,
    "securityGate": true,
    "rateLimiter": true,
    "preventiveEnforcement": true
  },
  "network": {
    "allowedHosts": [],
    "allowedPorts": [80, 443],
    "blockRFC1918": true,
    "blockLocalhost": true,
    "blockLinkLocal": true,
    "blockMetadata": true,
    "maxEgressBytesPerMin": 10485760
  },
  "process": {
    "allowSpawn": false,
    "allowedBinaries": [],
    "denyShells": true,
    "maxExecPerMin": 10
  },
  "taint": {
    "autoEscalate": true,
    "quarantineThreshold": 5,
    "coolDownSeconds": 300
  },
  "redaction": {
    "strategy": "mask"
  },
  "entropy": {
    "enabled": true,
    "base64Threshold": 4.5,
    "hexThreshold": 3.5
  },
  "rateLimits": {
    "execPerMinute": 10,
    "sensitiveReadPerMinute": 5
  }
}
```

### C.2 Deployment Profiles

| Setting | `home-lab` | `corp-dev` | `prod` | `research` |
|---------|-----------|-----------|--------|-----------|
| `mode` | audit | enforce | enforce | enforce |
| `network.allowedHosts` | `["*"]` | `["*.internal.corp"]` | `[]` (deny all) | `["*"]` |
| `network.allowedPorts` | `[80,443,8080,3000]` | `[80,443]` | `[443]` | `[80,443]` |
| `network.blockRFC1918` | false | true | true | true |
| `network.blockLocalhost` | false | false | true | true |
| `network.blockMetadata` | true | true | true | true |
| `process.allowSpawn` | true | true | false | true |
| `process.denyShells` | false | true | true | true |
| `process.allowedBinaries` | `["*"]` | `["git","node","npx","python"]` | `[]` | `["git","node","npx","python","pip"]` |
| `taint.autoEscalate` | false | true | true | true |
| `taint.quarantineThreshold` | 999 | 10 | 5 | 10 |

### C.3 Break-Glass Workflow

```
1. Normal operation (enforce mode)
   └── Agent hits a block → logged, actionable error returned

2. Operator suspects issue
   └── shield status → shows taint state, recent blocks, profile

3. Escalation
   └── shield quarantine <sessionId> → all side-effects blocked

4. Investigation
   └── shield export-audit --since 1h → JSONL dump for review

5. Resolution
   └── shield unquarantine <sessionId> --reason "reviewed, false positive"
   └── shield set-profile <name> → switch profile if needed

6. Emergency override
   └── shield set-profile home-lab → maximum permissiveness (audit mode)
```

### C.4 Required Operator Commands

| Command | Description |
|---------|-------------|
| `shield status` | Print current profile, taint state, recent blocks (last 10) |
| `shield quarantine <sessionId>` | Force session to QUARANTINED state |
| `shield unquarantine <sessionId> --reason "..."` | Restore session to CLEAN with audit trail |
| `shield set-profile <name>` | Switch deployment profile |
| `shield export-audit --since <duration>` | Export audit log as JSONL |

### C.5 UX Recommendations

1. **Actionable error messages**: Every block includes a reason code and a
   human-readable explanation. Example:
   ```
   [OC-SHIELD L7] Connection blocked: 10.0.0.5:8080
   Reason: NET_RFC1918_BLOCKED (code 1001)
   Action: Add host to network.allowedHosts or switch to home-lab profile
   ```

2. **Stable reason codes**: Numeric codes never change meaning across versions.
   Operators can build alerting/dashboards on these codes.

3. **Log hygiene**: Audit entries never contain the actual secret/PII — only
   pattern names, reason codes, and metadata.

### C.6 Engineering Recommendations

1. **Priority interceptors**: Ship `net.ts` and `proc.ts` first. FS and DNS
   interception can wait for v1.1.
2. **Tamper detection**: `freeze.ts` should detect if a skill un-patches the
   interceptors. On tamper → quarantine session.
3. **Zig purity**: Zig modules must never perform I/O. All I/O (logging, config
   loading, timer queries) happens in the TypeScript layer.
