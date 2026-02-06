// OpenClaw Shield — Native Binding Loader
//
// Loads the Zig-compiled shared library via N-API addon, with WASM fallback.
// Provides a unified interface regardless of the underlying binding method.

import * as path from 'path';
import * as fs from 'fs';
import { Decision, ReasonCode, Risk, TaintState } from './types';

// WebAssembly is available in Node.js ≥ 12 but TS needs DOM lib for types.
// Declare just enough to satisfy the compiler.
declare const WebAssembly: {
  instantiate(bytes: ArrayBuffer | Uint8Array, importObject?: Record<string, unknown>): Promise<{ instance: { exports: Record<string, unknown> } }>;
  Memory: new (descriptor: { initial: number; maximum?: number }) => { buffer: ArrayBuffer };
};

/** Unified interface for calling Zig decision functions */
export interface NativeBinding {
  /** Classify an IP address: 0=public, 1=rfc1918, 2=localhost, 3=link_local, 4=metadata, 255=not-IP */
  classifyIp(host: string): number;

  /** Check if a network connection should be allowed (IP-level checks only) */
  decideNetConnect(host: string, port: number, taint: TaintState, policyFlags: number): Decision;

  /** Check if a subprocess spawn should be allowed */
  decideSpawn(binary: string, taint: TaintState, allowSpawn: boolean, denyShells: boolean): Decision;

  /** Return the engine version */
  version(): string;

  /** Binding type for diagnostics */
  readonly bindingType: 'napi' | 'wasm' | 'pure-ts';
}

/**
 * Unpack a u64 decision from WASM into our Decision interface.
 * Bit layout:
 *   0:     allow
 *   1-16:  reason_code
 *   17-18: risk
 *   19-20: taint_update (0=none, 1=clean, 2=tainted, 3=quarantined)
 */
function unpackDecision(packed: bigint): Decision {
  const allow = (packed & 1n) === 1n;
  const reasonCode = Number((packed >> 1n) & 0xFFFFn) as ReasonCode;
  const risk = Number((packed >> 17n) & 0x3n) as Risk;
  const taintRaw = Number((packed >> 19n) & 0x3n);
  const taintUpdate = taintRaw === 0 ? null : (taintRaw - 1) as TaintState;

  return { allow, reasonCode, risk, taintUpdate };
}

/**
 * Build policy flags byte from booleans.
 *   bit 0: block_rfc1918
 *   bit 1: block_localhost
 *   bit 2: block_link_local
 *   bit 3: block_metadata
 */
export function buildPolicyFlags(opts: {
  blockRFC1918: boolean;
  blockLocalhost: boolean;
  blockLinkLocal: boolean;
  blockMetadata: boolean;
}): number {
  let flags = 0;
  if (opts.blockRFC1918) flags |= 1;
  if (opts.blockLocalhost) flags |= 2;
  if (opts.blockLinkLocal) flags |= 4;
  if (opts.blockMetadata) flags |= 8;
  return flags;
}

/** Try to load the N-API addon */
function tryLoadNapi(): NativeBinding | null {
  const addonPaths = [
    path.join(__dirname, '..', '..', 'zig-out', 'lib', 'ocshield.node'),
    path.join(__dirname, '..', 'native', 'ocshield.node'),
    path.join(__dirname, '..', '..', 'build', 'Release', 'ocshield.node'),
  ];

  for (const addonPath of addonPaths) {
    if (fs.existsSync(addonPath)) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const addon = require(addonPath);
        return {
          bindingType: 'napi',
          classifyIp: addon.classifyIp,
          decideNetConnect: addon.decideNetConnect,
          decideSpawn: addon.decideSpawn,
          version: () => addon.version(),
        };
      } catch {
        // N-API loading failed, continue to next path
      }
    }
  }
  return null;
}

/** Try to load the WASM module */
async function tryLoadWasm(): Promise<NativeBinding | null> {
  const wasmPaths = [
    path.join(__dirname, '..', '..', 'zig-out', 'lib', 'ocshield.wasm'),
    path.join(__dirname, '..', 'wasm', 'ocshield.wasm'),
  ];

  for (const wasmPath of wasmPaths) {
    if (fs.existsSync(wasmPath)) {
      try {
        const wasmBuffer = fs.readFileSync(wasmPath);
        const memory = new WebAssembly.Memory({ initial: 256, maximum: 4096 });
        const wasmModule = await WebAssembly.instantiate(wasmBuffer, {
          env: { memory },
        });
        const exports = wasmModule.instance.exports as Record<string, (...args: number[]) => number | bigint>;

        const encoder = new TextEncoder();

        function writeString(str: string): [number, number] {
          const bytes = encoder.encode(str);
          const ptr = Number(exports.wasm_alloc(bytes.length));
          if (!ptr) throw new Error('WASM alloc failed');
          const wasmMem = (wasmModule.instance.exports as Record<string, unknown>).memory as { buffer: ArrayBuffer };
          const mem = new Uint8Array(wasmMem.buffer);
          mem.set(bytes, ptr);
          return [ptr, bytes.length];
        }

        function freeString(ptr: number, len: number): void {
          exports.wasm_free(ptr, len);
        }

        return {
          bindingType: 'wasm',

          classifyIp(host: string): number {
            const [ptr, len] = writeString(host);
            try {
              return Number(exports.classify_ip(ptr, len));
            } finally {
              freeString(ptr, len);
            }
          },

          decideNetConnect(host: string, port: number, taint: TaintState, policyFlags: number): Decision {
            const [ptr, len] = writeString(host);
            try {
              const packed = BigInt(exports.decide_net_connect(ptr, len, port, taint, policyFlags));
              return unpackDecision(packed);
            } finally {
              freeString(ptr, len);
            }
          },

          decideSpawn(binary: string, taint: TaintState, allowSpawn: boolean, denyShells: boolean): Decision {
            const [ptr, len] = writeString(binary);
            try {
              const packed = BigInt(exports.decide_spawn(
                ptr, len, taint,
                allowSpawn ? 1 : 0,
                denyShells ? 1 : 0,
              ));
              return unpackDecision(packed);
            } finally {
              freeString(ptr, len);
            }
          },

          version(): string {
            const v = Number(exports.version());
            const major = (v >> 16) & 0xFF;
            const minor = (v >> 8) & 0xFF;
            const patch = v & 0xFF;
            return `${major}.${minor}.${patch}`;
          },
        };
      } catch {
        // WASM loading failed, continue
      }
    }
  }
  return null;
}

/**
 * Pure TypeScript fallback — implements the same decision logic without
 * native code. Slower but works everywhere.
 */
function createPureTsFallback(): NativeBinding {
  const RFC1918_RANGES = [
    { prefix: '10.', check: () => true },
    { prefix: '172.', check: (ip: string) => { const o = parseInt(ip.split('.')[1]); return o >= 16 && o <= 31; } },
    { prefix: '192.168.', check: () => true },
  ];

  return {
    bindingType: 'pure-ts',

    classifyIp(host: string): number {
      if (host === '169.254.169.254') return 4; // metadata
      if (host.startsWith('127.') || host === '::1' || host === 'localhost') return 2; // localhost
      if (host.startsWith('169.254.') || host.startsWith('fe80:')) return 3; // link_local
      for (const range of RFC1918_RANGES) {
        if (host.startsWith(range.prefix) && range.check(host)) return 1; // rfc1918
      }
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return 0; // public
      return 255; // not an IP
    },

    decideNetConnect(host: string, _port: number, taint: TaintState, policyFlags: number): Decision {
      if (taint === TaintState.QUARANTINED) {
        return { allow: false, reasonCode: ReasonCode.QUARANTINED, risk: Risk.HIGH, taintUpdate: TaintState.QUARANTINED };
      }

      const cls = this.classifyIp(host);
      const blockRfc = (policyFlags & 1) !== 0;
      const blockLocal = (policyFlags & 2) !== 0;
      const blockLink = (policyFlags & 4) !== 0;
      const blockMeta = (policyFlags & 8) !== 0;

      if (cls === 4 && blockMeta) return { allow: false, reasonCode: ReasonCode.NET_METADATA_BLOCKED, risk: Risk.HIGH, taintUpdate: TaintState.TAINTED };
      if (cls === 2 && blockLocal) return { allow: false, reasonCode: ReasonCode.NET_LOCALHOST_BLOCKED, risk: Risk.MEDIUM, taintUpdate: TaintState.TAINTED };
      if (cls === 3 && blockLink) return { allow: false, reasonCode: ReasonCode.NET_LINK_LOCAL_BLOCKED, risk: Risk.MEDIUM, taintUpdate: TaintState.TAINTED };
      if (cls === 1 && blockRfc) return { allow: false, reasonCode: ReasonCode.NET_RFC1918_BLOCKED, risk: Risk.MEDIUM, taintUpdate: TaintState.TAINTED };

      // "localhost" hostname check
      if (host.toLowerCase() === 'localhost' && blockLocal) {
        return { allow: false, reasonCode: ReasonCode.NET_LOCALHOST_BLOCKED, risk: Risk.MEDIUM, taintUpdate: TaintState.TAINTED };
      }

      return { allow: true, reasonCode: ReasonCode.NONE, risk: Risk.LOW, taintUpdate: null };
    },

    decideSpawn(binary: string, taint: TaintState, allowSpawn: boolean, denyShells: boolean): Decision {
      if (taint === TaintState.QUARANTINED) {
        return { allow: false, reasonCode: ReasonCode.QUARANTINED, risk: Risk.HIGH, taintUpdate: TaintState.QUARANTINED };
      }
      if (!allowSpawn) {
        return { allow: false, reasonCode: ReasonCode.PROC_SPAWN_DENIED, risk: Risk.HIGH, taintUpdate: TaintState.TAINTED };
      }
      const shells = ['bash', 'sh', 'zsh', 'fish', 'csh', 'tcsh', 'ksh', 'dash', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'];
      const name = binary.split('/').pop()?.split('\\').pop() ?? binary;
      if (denyShells && shells.includes(name.toLowerCase())) {
        return { allow: false, reasonCode: ReasonCode.PROC_SHELL_DENIED, risk: Risk.HIGH, taintUpdate: TaintState.TAINTED };
      }
      return { allow: true, reasonCode: ReasonCode.NONE, risk: Risk.LOW, taintUpdate: null };
    },

    version(): string {
      return '0.3.0-pure-ts';
    },
  };
}

/** Cached binding instance */
let cachedBinding: NativeBinding | null = null;

/**
 * Load the best available native binding.
 * Priority: N-API addon > WASM > pure TypeScript fallback
 */
export async function loadBinding(): Promise<NativeBinding> {
  if (cachedBinding) return cachedBinding;

  // Try N-API first (fastest)
  const napi = tryLoadNapi();
  if (napi) {
    cachedBinding = napi;
    return napi;
  }

  // Try WASM next
  const wasm = await tryLoadWasm();
  if (wasm) {
    cachedBinding = wasm;
    return wasm;
  }

  // Fall back to pure TypeScript
  cachedBinding = createPureTsFallback();
  return cachedBinding;
}

/**
 * Synchronous binding loader — returns N-API if available, else pure-TS.
 * Use this when async is not possible (e.g., in hook registration).
 */
export function loadBindingSync(): NativeBinding {
  if (cachedBinding) return cachedBinding;

  const napi = tryLoadNapi();
  if (napi) {
    cachedBinding = napi;
    return napi;
  }

  cachedBinding = createPureTsFallback();
  return cachedBinding;
}
