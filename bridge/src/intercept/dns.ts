// OpenClaw Shield — DNS Interceptor
//
// Patches dns.resolve, dns.resolve4, dns.resolve6, dns.lookup, and
// dns.promises equivalents to enforce L7 DNS policies. Every DNS
// resolution is checked against the domain allowlist and the resolved
// addresses are inspected for DNS rebinding attacks.
//
// DNS is the covert channel people forget about. An attacker who can
// resolve arbitrary domains can exfiltrate data one subdomain at a time:
//   stolen-data-chunk-1.evil.com
//   stolen-data-chunk-2.evil.com
// It's like passing notes in class, except each note is a TXT query
// and the teacher is your SIEM that isn't watching UDP/53.

import * as dns from 'dns';
import * as net from 'net';
import { ShieldConfig, Decision, ReasonCode, REASON_LABELS, TaintState } from '../types';
import { StateManager } from './state';

// Get mutable CJS module object for monkey-patching.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const dnsMod: typeof dns = require('dns');

/** Error thrown when a DNS resolution is blocked */
export class ShieldDnsError extends Error {
  public readonly reasonCode: number;
  public readonly hostname: string;

  constructor(decision: Decision, hostname: string) {
    const label = REASON_LABELS[decision.reasonCode] ?? 'UNKNOWN';
    super(
      `[OC-SHIELD L7] DNS resolution blocked: ${hostname}\n` +
      `Reason: ${label} (code ${decision.reasonCode})\n` +
      `Action: Add domain to dns.allowedDomains or switch to a more permissive profile`,
    );
    this.name = 'ShieldDnsError';
    this.reasonCode = decision.reasonCode;
    this.hostname = hostname;
  }
}

// Original references saved before patching
const originals = {
  lookup: dnsMod.lookup,
  resolve: dnsMod.resolve,
  resolve4: dnsMod.resolve4,
  resolve6: dnsMod.resolve6,
  resolveMx: dnsMod.resolveMx,
  resolveTxt: dnsMod.resolveTxt,
  resolveSrv: dnsMod.resolveSrv,
  resolveCname: dnsMod.resolveCname,
  resolveNs: dnsMod.resolveNs,
};

// ── RFC1918 / private IP detection for rebind checks ───────────────────

function isPrivateIp(ip: string): boolean {
  if (!net.isIP(ip)) return false;

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 127.0.0.0/8
    if (parts[0] === 127) return true;
    // 169.254.0.0/16 (link-local)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0
    if (parts.every(p => p === 0)) return true;
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    // ::1 (loopback)
    if (lower === '::1' || lower === '0000:0000:0000:0000:0000:0000:0000:0001') return true;
    // fe80::/10 (link-local)
    if (lower.startsWith('fe80:') || lower.startsWith('fe80')) return true;
    // fc00::/7 (unique local)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  }

  return false;
}

// ── Domain allowlist checking ──────────────────────────────────────────

function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) return false;
  const h = hostname.toLowerCase().replace(/\.$/, '');

  for (const entry of allowedDomains) {
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

// ── Core check function ────────────────────────────────────────────────

function checkDnsQuery(
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
  hostname: string,
): Decision {
  state.checkDeescalation(sessionId);

  // Block all DNS if configured
  if (config.dns.blockAllDns) {
    return {
      allow: false,
      reasonCode: ReasonCode.DNS_BLOCKED_DOMAIN,
      risk: 1,
      taintUpdate: TaintState.TAINTED,
    };
  }

  // Check domain allowlist
  if (config.dns.allowedDomains.length > 0 && !isDomainAllowed(hostname, config.dns.allowedDomains)) {
    return {
      allow: false,
      reasonCode: ReasonCode.DNS_BLOCKED_DOMAIN,
      risk: 1,
      taintUpdate: TaintState.TAINTED,
    };
  }

  return {
    allow: true,
    reasonCode: ReasonCode.NONE,
    risk: 0,
    taintUpdate: null,
  };
}

/** Check resolved addresses for DNS rebinding (public domain → private IP) */
function checkRebind(
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
  hostname: string,
  addresses: string[],
): Decision | null {
  if (!config.dns.blockPrivateResolution) return null;

  for (const addr of addresses) {
    if (isPrivateIp(addr)) {
      const decision: Decision = {
        allow: false,
        reasonCode: ReasonCode.DNS_REBIND_DETECTED,
        risk: 2, // high — this is an active attack
        taintUpdate: TaintState.TAINTED,
      };
      state.recordDecision(sessionId, decision, 'dns_rebind', {
        hostname,
        resolvedTo: addr,
        message: 'DNS rebinding detected: public domain resolved to private IP',
      });
      return decision;
    }
  }
  return null;
}

/** Install DNS interceptors */
export function installDnsInterceptors(
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
): void {
  // ── lookup (used by http.request, net.connect, etc.) ──────────────
  dnsMod.lookup = function shieldLookup(
    hostname: string,
    ...rest: unknown[]
  ): void {
    // Skip IP addresses — they don't need resolution
    if (net.isIP(hostname)) {
      return (originals.lookup as Function).call(dns, hostname, ...rest);
    }

    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_lookup', {
      hostname,
      method: 'lookup',
    });

    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) {
        cb(new ShieldDnsError(decision, hostname));
        return;
      }
      throw new ShieldDnsError(decision, hostname);
    }

    // Wrap callback for rebind detection
    if (config.dns.blockPrivateResolution) {
      const cbIndex = rest.findIndex(a => typeof a === 'function');
      if (cbIndex !== -1) {
        const originalCb = rest[cbIndex] as Function;
        rest[cbIndex] = function rebindCheckCb(err: Error | null, address: string | dns.LookupAddress[], family?: number) {
          if (!err && address) {
            const addrs = typeof address === 'string' ? [address] : (address as dns.LookupAddress[]).map(a => a.address);
            const rebindDecision = checkRebind(config, state, sessionId, hostname, addrs);
            if (rebindDecision && config.mode === 'enforce') {
              originalCb(new ShieldDnsError(rebindDecision, hostname));
              return;
            }
          }
          originalCb(err, address, family);
        };
      }
    }

    return (originals.lookup as Function).call(dns, hostname, ...rest);
  } as typeof dns.lookup;

  // ── resolve ───────────────────────────────────────────────────────
  dnsMod.resolve = function shieldResolve(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', {
      hostname,
      method: 'resolve',
    });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) {
        cb(new ShieldDnsError(decision, hostname));
        return;
      }
      throw new ShieldDnsError(decision, hostname);
    }
    return (originals.resolve as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolve;

  // ── resolve4 ──────────────────────────────────────────────────────
  dnsMod.resolve4 = function shieldResolve4(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', {
      hostname,
      method: 'resolve4',
    });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) {
        cb(new ShieldDnsError(decision, hostname));
        return;
      }
      throw new ShieldDnsError(decision, hostname);
    }

    // Wrap callback for rebind detection
    if (config.dns.blockPrivateResolution) {
      const cbIndex = rest.findIndex(a => typeof a === 'function');
      if (cbIndex !== -1) {
        const originalCb = rest[cbIndex] as Function;
        rest[cbIndex] = function rebindCheck4(err: Error | null, addresses: string[]) {
          if (!err && addresses) {
            const rebindDecision = checkRebind(config, state, sessionId, hostname, addresses);
            if (rebindDecision && config.mode === 'enforce') {
              originalCb(new ShieldDnsError(rebindDecision, hostname));
              return;
            }
          }
          originalCb(err, addresses);
        };
      }
    }

    return (originals.resolve4 as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolve4;

  // ── resolve6 ──────────────────────────────────────────────────────
  dnsMod.resolve6 = function shieldResolve6(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', {
      hostname,
      method: 'resolve6',
    });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) {
        cb(new ShieldDnsError(decision, hostname));
        return;
      }
      throw new ShieldDnsError(decision, hostname);
    }

    if (config.dns.blockPrivateResolution) {
      const cbIndex = rest.findIndex(a => typeof a === 'function');
      if (cbIndex !== -1) {
        const originalCb = rest[cbIndex] as Function;
        rest[cbIndex] = function rebindCheck6(err: Error | null, addresses: string[]) {
          if (!err && addresses) {
            const rebindDecision = checkRebind(config, state, sessionId, hostname, addresses);
            if (rebindDecision && config.mode === 'enforce') {
              originalCb(new ShieldDnsError(rebindDecision, hostname));
              return;
            }
          }
          originalCb(err, addresses);
        };
      }
    }

    return (originals.resolve6 as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolve6;

  // ── resolveMx ─────────────────────────────────────────────────────
  dnsMod.resolveMx = function shieldResolveMx(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', { hostname, method: 'resolveMx' });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) { cb(new ShieldDnsError(decision, hostname)); return; }
      throw new ShieldDnsError(decision, hostname);
    }
    return (originals.resolveMx as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolveMx;

  // ── resolveTxt ────────────────────────────────────────────────────
  dnsMod.resolveTxt = function shieldResolveTxt(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', { hostname, method: 'resolveTxt' });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) { cb(new ShieldDnsError(decision, hostname)); return; }
      throw new ShieldDnsError(decision, hostname);
    }
    return (originals.resolveTxt as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolveTxt;

  // ── resolveSrv ────────────────────────────────────────────────────
  dnsMod.resolveSrv = function shieldResolveSrv(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', { hostname, method: 'resolveSrv' });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) { cb(new ShieldDnsError(decision, hostname)); return; }
      throw new ShieldDnsError(decision, hostname);
    }
    return (originals.resolveSrv as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolveSrv;

  // ── resolveCname ──────────────────────────────────────────────────
  dnsMod.resolveCname = function shieldResolveCname(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', { hostname, method: 'resolveCname' });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) { cb(new ShieldDnsError(decision, hostname)); return; }
      throw new ShieldDnsError(decision, hostname);
    }
    return (originals.resolveCname as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolveCname;

  // ── resolveNs ─────────────────────────────────────────────────────
  dnsMod.resolveNs = function shieldResolveNs(
    hostname: string,
    ...rest: unknown[]
  ): void {
    const decision = checkDnsQuery(config, state, sessionId, hostname);
    state.recordDecision(sessionId, decision, 'dns_resolve', { hostname, method: 'resolveNs' });
    if (!decision.allow && config.mode === 'enforce') {
      const cb = rest.find(a => typeof a === 'function') as Function | undefined;
      if (cb) { cb(new ShieldDnsError(decision, hostname)); return; }
      throw new ShieldDnsError(decision, hostname);
    }
    return (originals.resolveNs as Function).call(dns, hostname, ...rest);
  } as typeof dns.resolveNs;
}

/** Restore original DNS functions */
export function uninstallDnsInterceptors(): void {
  dnsMod.lookup = originals.lookup;
  dnsMod.resolve = originals.resolve;
  dnsMod.resolve4 = originals.resolve4;
  dnsMod.resolve6 = originals.resolve6;
  dnsMod.resolveMx = originals.resolveMx;
  dnsMod.resolveTxt = originals.resolveTxt;
  dnsMod.resolveSrv = originals.resolveSrv;
  dnsMod.resolveCname = originals.resolveCname;
  dnsMod.resolveNs = originals.resolveNs;
}

/** Get original references (for tamper detection) */
export function getOriginals() {
  return { ...originals };
}
