// OpenClaw Shield — Network Interceptor
//
// Patches globalThis.fetch, http.request, https.request, net.connect,
// and tls.connect to enforce L7 network policies. Every outbound
// connection is checked against the Zig decision engine before it
// can proceed.

import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import * as url from 'url';
import { NativeBinding, buildPolicyFlags } from '../native';
import { ShieldConfig, Decision, ReasonCode, REASON_LABELS, TaintState } from '../types';
import { StateManager } from './state';

// Get mutable CJS module objects for monkey-patching.
// When loaded via jiti, ESM namespace imports have configurable:false
// properties that prevent reassignment. require() returns the actual
// mutable CJS module object that works in both tsc and jiti contexts.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const httpMod: typeof http = require('http');
const httpsMod: typeof https = require('https');
const netMod: typeof net = require('net');
const tlsMod: typeof tls = require('tls');

/** Error thrown when a network connection is blocked */
export class ShieldNetworkError extends Error {
  public readonly reasonCode: number;
  public readonly host: string;
  public readonly port: number;

  constructor(decision: Decision, host: string, port: number) {
    const label = REASON_LABELS[decision.reasonCode] ?? 'UNKNOWN';
    super(
      `[OC-SHIELD L7] Connection blocked: ${host}:${port}\n` +
      `Reason: ${label} (code ${decision.reasonCode})\n` +
      `Action: Add host to network.allowedHosts or switch to a more permissive profile`,
    );
    this.name = 'ShieldNetworkError';
    this.reasonCode = decision.reasonCode;
    this.host = host;
    this.port = port;
  }
}

// Original references saved before patching
const originals = {
  fetch: globalThis.fetch,
  httpRequest: httpMod.request,
  httpsRequest: httpsMod.request,
  netConnect: netMod.connect,
  tlsConnect: tlsMod.connect,
};

/** Check if connection should be allowed */
function checkConnection(
  binding: NativeBinding,
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
  host: string,
  port: number,
  payloadBytes: number = 0,
): Decision {
  // Check de-escalation first
  state.checkDeescalation(sessionId);

  const taint = state.getTaintState(sessionId);
  const policyFlags = buildPolicyFlags(config.network);

  // IP-level checks via Zig engine
  const ipDecision = binding.decideNetConnect(host, port, taint, policyFlags);
  if (!ipDecision.allow) return ipDecision;

  // Port allowlist (TS-side check for both N-API and WASM paths)
  if (!config.network.allowedPorts.includes(port)) {
    return {
      allow: false,
      reasonCode: ReasonCode.NET_PORT_NOT_ALLOWED,
      risk: 1, // medium
      taintUpdate: TaintState.TAINTED,
    };
  }

  // Domain allowlist (TS-side check)
  if (!isHostAllowed(host, config.network.allowedHosts)) {
    return {
      allow: false,
      reasonCode: ReasonCode.NET_DOMAIN_NOT_ALLOWED,
      risk: 1, // medium
      taintUpdate: TaintState.TAINTED,
    };
  }

  // Egress rate limit
  if (payloadBytes > 0) {
    const totalBytes = state.addEgressBytes(sessionId, payloadBytes);
    if (totalBytes > config.network.maxEgressBytesPerMin) {
      return {
        allow: false,
        reasonCode: ReasonCode.NET_EGRESS_RATE_LIMIT,
        risk: 2, // high
        taintUpdate: TaintState.TAINTED,
      };
    }
  }

  return ipDecision; // allowed
}

/** Domain allowlist matching (mirrors Zig domain.zig logic) */
function isHostAllowed(host: string, allowedHosts: string[]): boolean {
  if (allowedHosts.length === 0) return false;
  const h = host.toLowerCase().replace(/\.$/, '');

  for (const entry of allowedHosts) {
    if (entry === '*') return true;
    const e = entry.toLowerCase().replace(/\.$/, '');

    if (e.startsWith('*.')) {
      const suffix = e.slice(2);
      if (h === suffix || h.endsWith('.' + suffix)) return true;
    } else {
      if (h === e) return true;
    }
  }
  return false;
}

/** Extract host and port from various request argument formats */
function extractHostPort(args: unknown[]): { host: string; port: number } | null {
  const first = args[0];

  // URL string
  if (typeof first === 'string') {
    try {
      const u = new url.URL(first);
      return {
        host: u.hostname,
        port: u.port ? parseInt(u.port) : (u.protocol === 'https:' ? 443 : 80),
      };
    } catch {
      return null;
    }
  }

  // URL object
  if (first instanceof url.URL) {
    return {
      host: first.hostname,
      port: first.port ? parseInt(first.port) : (first.protocol === 'https:' ? 443 : 80),
    };
  }

  // Options object
  if (first && typeof first === 'object') {
    const opts = first as Record<string, unknown>;
    const host = (opts.hostname ?? opts.host ?? '') as string;
    const port = (opts.port ?? (opts.protocol === 'https:' ? 443 : 80)) as number;
    return { host: host.replace(/:\d+$/, ''), port: typeof port === 'string' ? parseInt(port) : port };
  }

  return null;
}

/** Install all network interceptors */
export function installNetInterceptors(
  binding: NativeBinding,
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
): void {
  // ── Patch fetch ────────────────────────────────────────────────────
  if (typeof globalThis.fetch === 'function') {
    (globalThis as Record<string, unknown>).fetch = function shieldFetch(
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> {
      let hostPort: { host: string; port: number } | null = null;

      if (typeof input === 'string') {
        hostPort = extractHostPort([input]);
      } else if (input instanceof URL) {
        hostPort = extractHostPort([input]);
      } else if (typeof Request !== 'undefined' && input instanceof Request) {
        hostPort = extractHostPort([input.url]);
      }

      if (hostPort) {
        const bodySize = init?.body ? (typeof init.body === 'string' ? init.body.length : 0) : 0;
        const decision = checkConnection(binding, config, state, sessionId, hostPort.host, hostPort.port, bodySize);

        state.recordDecision(sessionId, decision, 'net_connect', {
          host: hostPort.host,
          port: hostPort.port,
          method: 'fetch',
        });

        if (!decision.allow && config.mode === 'enforce') {
          return Promise.reject(new ShieldNetworkError(decision, hostPort.host, hostPort.port));
        }
      }

      return originals.fetch.call(globalThis, input, init);
    };
  }

  // ── Patch http.request ────────────────────────────────────────────
  httpMod.request = function shieldHttpRequest(...args: unknown[]): http.ClientRequest {
    const hostPort = extractHostPort(args);
    if (hostPort) {
      const decision = checkConnection(binding, config, state, sessionId, hostPort.host, hostPort.port);
      state.recordDecision(sessionId, decision, 'net_connect', {
        host: hostPort.host,
        port: hostPort.port,
        method: 'http.request',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldNetworkError(decision, hostPort.host, hostPort.port);
      }
    }
    return (originals.httpRequest as Function).apply(http, args);
  };

  // ── Patch https.request ───────────────────────────────────────────
  httpsMod.request = function shieldHttpsRequest(...args: unknown[]): http.ClientRequest {
    const hostPort = extractHostPort(args);
    if (hostPort) {
      const decision = checkConnection(binding, config, state, sessionId, hostPort.host, hostPort.port);
      state.recordDecision(sessionId, decision, 'net_connect', {
        host: hostPort.host,
        port: hostPort.port,
        method: 'https.request',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldNetworkError(decision, hostPort.host, hostPort.port);
      }
    }
    return (originals.httpsRequest as Function).apply(https, args);
  };

  // ── Patch net.connect ─────────────────────────────────────────────
  netMod.connect = function shieldNetConnect(...args: unknown[]): net.Socket {
    const opts = args[0];
    let host = 'localhost';
    let port = 0;

    if (typeof opts === 'object' && opts !== null && !Array.isArray(opts)) {
      const o = opts as Record<string, unknown>;
      host = (o.host ?? 'localhost') as string;
      port = (o.port ?? 0) as number;
    } else if (typeof opts === 'number') {
      port = opts;
      if (typeof args[1] === 'string') host = args[1] as string;
    }

    if (port > 0) {
      const decision = checkConnection(binding, config, state, sessionId, host, port);
      state.recordDecision(sessionId, decision, 'net_connect', { host, port, method: 'net.connect' });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldNetworkError(decision, host, port);
      }
    }

    return (originals.netConnect as Function).apply(net, args);
  };

  // ── Patch tls.connect ─────────────────────────────────────────────
  tlsMod.connect = function shieldTlsConnect(...args: unknown[]): tls.TLSSocket {
    const opts = args[0];
    let host = 'localhost';
    let port = 443;

    if (typeof opts === 'object' && opts !== null) {
      const o = opts as Record<string, unknown>;
      host = (o.host ?? 'localhost') as string;
      port = (o.port ?? 443) as number;
    }

    const decision = checkConnection(binding, config, state, sessionId, host, port);
    state.recordDecision(sessionId, decision, 'net_connect', { host, port, method: 'tls.connect' });
    if (!decision.allow && config.mode === 'enforce') {
      throw new ShieldNetworkError(decision, host, port);
    }

    return (originals.tlsConnect as Function).apply(tls, args);
  };
}

/** Restore original network functions (for testing/cleanup) */
export function uninstallNetInterceptors(): void {
  if (originals.fetch) (globalThis as Record<string, unknown>).fetch = originals.fetch;
  httpMod.request = originals.httpRequest;
  httpsMod.request = originals.httpsRequest;
  netMod.connect = originals.netConnect;
  tlsMod.connect = originals.tlsConnect;
}

/** Get original references (for tamper detection) */
export function getOriginals() {
  return { ...originals };
}
