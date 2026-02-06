# OpenClaw Shield (Zig)

Zig-native security guardrail plugin for [OpenClaw](https://github.com/openclaw/openclaw).

Based on [openclaw-shield](https://github.com/knostic/openclaw-shield) by [Knostic](https://knostic.ai/).

## What It Does

Protects OpenClaw users from leaking PII, secrets, and credentials through their AI assistant.
Blocks destructive commands, detects nefarious skill behavior, and maintains an audit trail
of all sensitive data interactions.

## Architecture

6-layer defense-in-depth, with the core scanning engine written in Zig:

| Layer | Name | Hook | Defense Type |
|-------|------|------|-------------|
| **L1** | Prompt Guard | `before_agent_start` | Injects security policy into agent context |
| **L2** | Output Scanner | `tool_result_persist` | Redacts secrets/PII from tool results |
| **L3** | Tool Blocker | `before_tool_call` | Hard-blocks dangerous tool calls |
| **L4** | Input Audit | `message_received` | Logs inbound messages with sensitive data flags |
| **L5** | Security Gate | `registerTool` | Gate tool the agent must call before exec/read |
| **L6** | Rate Limiter | custom | Prevents rapid-fire sensitive operations |

## Detection Coverage

**Secrets**: AWS keys, Stripe keys, GitHub tokens (classic + fine-grained PATs), OpenAI keys,
Anthropic keys, Slack tokens/webhooks, SendGrid keys, npm tokens, private keys (PEM),
JWTs, Bearer tokens, generic API keys — plus Shannon entropy detection for unknown secrets.

**PII**: Email, SSN, credit card, phone (US + international), IBAN — with regional
extensions for UK (NIN, NHS), EU (VAT, national ID), Canada (SIN), Australia (TFN, Medicare).

**Destructive Commands**: rm, rmdir, unlink, del, format, mkfs, dd — user-extensible.

**Sensitive Files**: .env, .pem, .key, .ssh/*, .aws/*, .kube/config, /etc/shadow, and more.

**Skill Threats**: Shell execution, eval/Function, crypto-mining, data exfiltration,
obfuscated code, environment harvesting, prompt injection, privilege escalation.

## Build Targets

The same Zig source compiles to three targets:

```bash
zig build lib     # Shared library (.so/.dylib/.dll) for Node N-API
zig build wasm    # WebAssembly module
zig build cli     # Standalone CLI binary
zig build test    # Run test suite
```

## Integration with OpenClaw

A thin TypeScript bridge in `bridge/` implements the OpenClaw plugin interface and
delegates all scanning logic to the Zig core via N-API (primary) or WASM (fallback).

Install as a plugin:
```bash
# From source
cd bridge && npm link
openclaw plugins install ./bridge

# Or point to the directory
# In ~/.openclaw/config.json:
{
  "plugins": {
    "load": {
      "paths": ["./path/to/zig-oc-shield/bridge"]
    }
  }
}
```

## Configuration

```json
{
  "plugins": {
    "zig-oc-shield": {
      "mode": "enforce",
      "layers": {
        "promptGuard": true,
        "outputScanner": true,
        "toolBlocker": true,
        "inputAudit": true,
        "securityGate": true,
        "rateLimiter": true
      },
      "redaction": {
        "strategy": "mask"
      },
      "entropy": {
        "enabled": true,
        "base64Threshold": 4.5
      },
      "pii": {
        "regions": ["us"]
      }
    }
  }
}
```

## Standalone CLI

```bash
# Scan a file for secrets and PII
ocshield scan myfile.txt

# Scan and redact
ocshield redact myfile.txt --strategy mask

# Audit a directory of skills/plugins
ocshield audit-skills ./skills/

# Check entropy of a string
echo "dG9wLXNlY3JldC1rZXk=" | ocshield entropy
```

## Credits

This project is a derivative work based on
[openclaw-shield](https://github.com/knostic/openclaw-shield)
by [Knostic](https://knostic.ai/), licensed under Apache 2.0.

The original 5-layer architecture, pattern definitions, and defense-in-depth
approach are credited to Knostic's work. See [NOTICE](NOTICE) for full attribution.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
