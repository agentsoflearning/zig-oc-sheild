// OpenClaw Shield — Filesystem Interceptor
//
// Patches fs.readFile, fs.readFileSync, fs.writeFile, fs.writeFileSync,
// fs.open, fs.openSync, fs.createReadStream, and fs.createWriteStream
// to enforce L7 filesystem policies. Every file operation is checked
// against the sensitive path list and write policy before it can proceed.
//
// A security tool that doesn't watch the filesystem is like a bouncer
// who only checks the front door but ignores the windows.

import * as fs from 'fs';
import * as path from 'path';
import { ShieldConfig, Decision, ReasonCode, REASON_LABELS, TaintState } from '../types';
import { StateManager } from './state';

// Get mutable CJS module object for monkey-patching.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const fsMod: typeof fs = require('fs');

/** Error thrown when a filesystem operation is blocked */
export class ShieldFilesystemError extends Error {
  public readonly reasonCode: number;
  public readonly filePath: string;

  constructor(decision: Decision, filePath: string) {
    const label = REASON_LABELS[decision.reasonCode] ?? 'UNKNOWN';
    super(
      `[OC-SHIELD L7] File operation blocked: ${filePath}\n` +
      `Reason: ${label} (code ${decision.reasonCode})\n` +
      `Action: Add path to filesystem.allowedWritePaths or switch to a more permissive profile`,
    );
    this.name = 'ShieldFilesystemError';
    this.reasonCode = decision.reasonCode;
    this.filePath = filePath;
  }
}

// Original references saved before patching
const originals = {
  readFile: fsMod.readFile,
  readFileSync: fsMod.readFileSync,
  writeFile: fsMod.writeFile,
  writeFileSync: fsMod.writeFileSync,
  open: fsMod.open,
  openSync: fsMod.openSync,
  createReadStream: fsMod.createReadStream,
  createWriteStream: fsMod.createWriteStream,
};

// ── Sensitive path patterns (mirrors Zig sensitive_files.zig) ──────────

const SENSITIVE_BASENAMES = new Set([
  'credentials.json', 'known_hosts', '.netrc', '.npmrc', '.pypirc',
  'token.json', 'tokens.json', '/etc/shadow', '/etc/passwd',
]);

const SENSITIVE_BASENAME_PREFIXES = [
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa',
  'secret.', 'secrets.',
];

const SENSITIVE_EXTENSIONS = new Set(['.pem', '.key', '.p12', '.pfx']);

const SENSITIVE_DIRS = ['.ssh', '.aws', '.kube', '.gnupg'];

function isSensitivePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const base = path.basename(normalized).toLowerCase();
  const ext = path.extname(normalized).toLowerCase();

  // Exact match on full path
  if (normalized === '/etc/shadow' || normalized === '/etc/passwd') return true;

  // .env files
  if (base === '.env' || base.startsWith('.env.')) return true;

  // Known sensitive basenames
  if (SENSITIVE_BASENAMES.has(base)) return true;

  // Sensitive extensions
  if (SENSITIVE_EXTENSIONS.has(ext)) return true;

  // SSH identity files
  const baseNoExt = base.endsWith('.pub') ? base.slice(0, -4) : base;
  for (const prefix of SENSITIVE_BASENAME_PREFIXES) {
    if (baseNoExt === prefix || base.startsWith(prefix)) return true;
  }

  // Sensitive parent directories
  const parts = normalized.split('/');
  for (const dir of SENSITIVE_DIRS) {
    if (parts.includes(dir)) return true;
  }

  return false;
}

// ── Path traversal detection ───────────────────────────────────────────

// If your file path looks like it was designed by someone playing
// chutes-and-ladders with directory separators, we're going to
// have words about it.
function hasPathTraversal(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');

  // Null bytes — the classic "I learned hacking from a 2003 tutorial"
  if (normalized.includes('\0')) return true;

  // Resolve and compare — if the resolved path differs in unexpected ways
  // from what was requested, someone's playing path games
  const parts = normalized.split('/');
  if (parts.includes('..')) {
    // Check if .. escapes beyond CWD
    try {
      const resolved = path.resolve(filePath);
      const cwd = process.cwd();
      if (!resolved.startsWith(cwd)) return true;
    } catch {
      return true; // If we can't even resolve it, that's suspicious
    }
  }

  return false;
}

// ── Write path allowlist ───────────────────────────────────────────────

function isWriteAllowed(filePath: string, allowedPaths: string[]): boolean {
  if (allowedPaths.length === 0) return false;

  const resolved = path.resolve(filePath);

  for (const entry of allowedPaths) {
    if (entry === '*') return true;

    const allowedResolved = path.resolve(entry);

    // Exact match
    if (resolved === allowedResolved) return true;

    // Directory prefix match (entry ends with /)
    if (entry.endsWith('/') || entry.endsWith('/*')) {
      const dir = allowedResolved.replace(/\/?\*?$/, '');
      if (resolved.startsWith(dir + '/')) return true;
    }
  }

  return false;
}

// ── Core check function ────────────────────────────────────────────────

function checkFileOp(
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
  filePath: string,
  isWrite: boolean,
): Decision {
  state.checkDeescalation(sessionId);

  // Path traversal check — top priority
  if (config.filesystem.blockPathTraversal && hasPathTraversal(filePath)) {
    return {
      allow: false,
      reasonCode: ReasonCode.FS_PATH_TRAVERSAL,
      risk: 2, // high
      taintUpdate: TaintState.TAINTED,
    };
  }

  // Sensitive file check (reads and writes)
  if (config.filesystem.blockSensitivePaths && isSensitivePath(filePath)) {
    return {
      allow: false,
      reasonCode: ReasonCode.FS_SENSITIVE_PATH,
      risk: 2, // high
      taintUpdate: TaintState.TAINTED,
    };
  }

  // Write-specific checks
  if (isWrite && config.filesystem.blockWrites) {
    if (!isWriteAllowed(filePath, config.filesystem.allowedWritePaths)) {
      return {
        allow: false,
        reasonCode: ReasonCode.FS_WRITE_BLOCKED,
        risk: 1, // medium
        taintUpdate: TaintState.TAINTED,
      };
    }
  }

  return {
    allow: true,
    reasonCode: ReasonCode.NONE,
    risk: 0,
    taintUpdate: null,
  };
}

// ── Helper to extract path from fs call arguments ──────────────────────

function extractPath(arg: unknown): string | null {
  if (typeof arg === 'string') return arg;
  if (Buffer.isBuffer(arg)) return arg.toString();
  if (arg instanceof URL) return arg.pathname;
  return null;
}

/** Install filesystem interceptors */
export function installFsInterceptors(
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
): void {
  // ── readFile ──────────────────────────────────────────────────────
  fsMod.readFile = function shieldReadFile(
    filePath: unknown,
    ...rest: unknown[]
  ): void {
    const p = extractPath(filePath);
    if (p) {
      const decision = checkFileOp(config, state, sessionId, p, false);
      state.recordDecision(sessionId, decision, 'fs_read', {
        path: p,
        method: 'readFile',
      });
      if (!decision.allow && config.mode === 'enforce') {
        // Call the callback with an error if provided, otherwise throw
        const cb = rest.find(a => typeof a === 'function') as Function | undefined;
        if (cb) {
          cb(new ShieldFilesystemError(decision, p));
          return;
        }
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.readFile as Function).call(fs, filePath, ...rest);
  } as typeof fs.readFile;

  // ── readFileSync ──────────────────────────────────────────────────
  fsMod.readFileSync = function shieldReadFileSync(
    filePath: unknown,
    ...rest: unknown[]
  ): string | Buffer {
    const p = extractPath(filePath);
    if (p) {
      const decision = checkFileOp(config, state, sessionId, p, false);
      state.recordDecision(sessionId, decision, 'fs_read', {
        path: p,
        method: 'readFileSync',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.readFileSync as Function).call(fs, filePath, ...rest);
  } as typeof fs.readFileSync;

  // ── writeFile ─────────────────────────────────────────────────────
  fsMod.writeFile = function shieldWriteFile(
    filePath: unknown,
    ...rest: unknown[]
  ): void {
    const p = extractPath(filePath);
    if (p) {
      const decision = checkFileOp(config, state, sessionId, p, true);
      state.recordDecision(sessionId, decision, 'fs_write', {
        path: p,
        method: 'writeFile',
      });
      if (!decision.allow && config.mode === 'enforce') {
        const cb = rest.find(a => typeof a === 'function') as Function | undefined;
        if (cb) {
          cb(new ShieldFilesystemError(decision, p));
          return;
        }
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.writeFile as Function).call(fs, filePath, ...rest);
  } as typeof fs.writeFile;

  // ── writeFileSync ─────────────────────────────────────────────────
  fsMod.writeFileSync = function shieldWriteFileSync(
    filePath: unknown,
    ...rest: unknown[]
  ): void {
    const p = extractPath(filePath);
    if (p) {
      const decision = checkFileOp(config, state, sessionId, p, true);
      state.recordDecision(sessionId, decision, 'fs_write', {
        path: p,
        method: 'writeFileSync',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.writeFileSync as Function).call(fs, filePath, ...rest);
  } as typeof fs.writeFileSync;

  // ── open ──────────────────────────────────────────────────────────
  fsMod.open = function shieldOpen(
    filePath: unknown,
    ...rest: unknown[]
  ): void {
    const p = extractPath(filePath);
    if (p) {
      // Determine if this is a write open by checking flags
      const flags = typeof rest[0] === 'string' ? rest[0] : 'r';
      const isWrite = /[wax+]/.test(flags);
      const decision = checkFileOp(config, state, sessionId, p, isWrite);
      state.recordDecision(sessionId, decision, isWrite ? 'fs_write' : 'fs_read', {
        path: p,
        flags,
        method: 'open',
      });
      if (!decision.allow && config.mode === 'enforce') {
        const cb = rest.find(a => typeof a === 'function') as Function | undefined;
        if (cb) {
          cb(new ShieldFilesystemError(decision, p));
          return;
        }
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.open as Function).call(fs, filePath, ...rest);
  } as typeof fs.open;

  // ── openSync ──────────────────────────────────────────────────────
  fsMod.openSync = function shieldOpenSync(
    filePath: unknown,
    ...rest: unknown[]
  ): number {
    const p = extractPath(filePath);
    if (p) {
      const flags = typeof rest[0] === 'string' ? rest[0] : 'r';
      const isWrite = /[wax+]/.test(flags);
      const decision = checkFileOp(config, state, sessionId, p, isWrite);
      state.recordDecision(sessionId, decision, isWrite ? 'fs_write' : 'fs_read', {
        path: p,
        flags,
        method: 'openSync',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.openSync as Function).call(fs, filePath, ...rest);
  } as typeof fs.openSync;

  // ── createReadStream ──────────────────────────────────────────────
  fsMod.createReadStream = function shieldCreateReadStream(
    filePath: unknown,
    ...rest: unknown[]
  ): fs.ReadStream {
    const p = extractPath(filePath);
    if (p) {
      const decision = checkFileOp(config, state, sessionId, p, false);
      state.recordDecision(sessionId, decision, 'fs_read', {
        path: p,
        method: 'createReadStream',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.createReadStream as Function).call(fs, filePath, ...rest);
  } as typeof fs.createReadStream;

  // ── createWriteStream ─────────────────────────────────────────────
  fsMod.createWriteStream = function shieldCreateWriteStream(
    filePath: unknown,
    ...rest: unknown[]
  ): fs.WriteStream {
    const p = extractPath(filePath);
    if (p) {
      const decision = checkFileOp(config, state, sessionId, p, true);
      state.recordDecision(sessionId, decision, 'fs_write', {
        path: p,
        method: 'createWriteStream',
      });
      if (!decision.allow && config.mode === 'enforce') {
        throw new ShieldFilesystemError(decision, p);
      }
    }
    return (originals.createWriteStream as Function).call(fs, filePath, ...rest);
  } as typeof fs.createWriteStream;
}

/** Restore original fs functions */
export function uninstallFsInterceptors(): void {
  fsMod.readFile = originals.readFile;
  fsMod.readFileSync = originals.readFileSync;
  fsMod.writeFile = originals.writeFile;
  fsMod.writeFileSync = originals.writeFileSync;
  fsMod.open = originals.open;
  fsMod.openSync = originals.openSync;
  fsMod.createReadStream = originals.createReadStream;
  fsMod.createWriteStream = originals.createWriteStream;
}

/** Get original references (for tamper detection) */
export function getOriginals() {
  return { ...originals };
}
