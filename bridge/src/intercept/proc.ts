// OpenClaw Shield — Process Interceptor
//
// Patches child_process.spawn, execFile, and exec to enforce L7
// subprocess policies. Every spawn attempt is checked against the
// Zig decision engine before it can proceed.

import * as child_process from 'child_process';
import { NativeBinding } from '../native';
import { ShieldConfig, Decision, ReasonCode, REASON_LABELS, TaintState } from '../types';
import { StateManager } from './state';

/** Error thrown when a subprocess spawn is blocked */
export class ShieldProcessError extends Error {
  public readonly reasonCode: number;
  public readonly binary: string;

  constructor(decision: Decision, binary: string) {
    const label = REASON_LABELS[decision.reasonCode] ?? 'UNKNOWN';
    super(
      `[OC-SHIELD L7] Subprocess blocked: ${binary}\n` +
      `Reason: ${label} (code ${decision.reasonCode})\n` +
      `Action: Add binary to process.allowedBinaries or switch to a more permissive profile`,
    );
    this.name = 'ShieldProcessError';
    this.reasonCode = decision.reasonCode;
    this.binary = binary;
  }
}

// Original references saved before patching
const originals = {
  spawn: child_process.spawn,
  execFile: child_process.execFile,
  exec: child_process.exec,
};

/** Extract basename from a binary path */
function basename(binary: string): string {
  const parts = binary.split('/');
  const last = parts[parts.length - 1];
  const winParts = last.split('\\');
  return winParts[winParts.length - 1];
}

/** Check if a binary spawn should be allowed */
function checkSpawn(
  binding: NativeBinding,
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
  binary: string,
): Decision {
  // Check de-escalation first
  state.checkDeescalation(sessionId);

  const taint = state.getTaintState(sessionId);
  const name = basename(binary);

  // Zig-level checks (quarantine, shell denial)
  const zigDecision = binding.decideSpawn(name, taint, config.process.allowSpawn, config.process.denyShells);
  if (!zigDecision.allow) return zigDecision;

  // Binary allowlist (TS-side — easier to manage arrays here)
  if (!isBinaryAllowed(name, config.process.allowedBinaries)) {
    return {
      allow: false,
      reasonCode: ReasonCode.PROC_BINARY_NOT_ALLOWED,
      risk: 1, // medium
      taintUpdate: TaintState.TAINTED,
    };
  }

  // Exec rate limit
  const execCount = state.addExecCount(sessionId);
  if (execCount > config.process.maxExecPerMin) {
    return {
      allow: false,
      reasonCode: ReasonCode.RATE_LIMIT_EXCEEDED,
      risk: 1, // medium
      taintUpdate: TaintState.TAINTED,
    };
  }

  return zigDecision; // allowed
}

/** Binary allowlist matching */
function isBinaryAllowed(name: string, allowedBinaries: string[]): boolean {
  if (allowedBinaries.length === 0) return false;
  const lower = name.toLowerCase();
  for (const entry of allowedBinaries) {
    if (entry === '*') return true;
    if (entry.toLowerCase() === lower) return true;
  }
  return false;
}

/** Install process interceptors */
export function installProcInterceptors(
  binding: NativeBinding,
  config: ShieldConfig,
  state: StateManager,
  sessionId: string,
): void {
  // ── Patch spawn ────────────────────────────────────────────────────
  (child_process as { spawn: typeof child_process.spawn }).spawn = function shieldSpawn(
    command: string,
    ...rest: unknown[]
  ): child_process.ChildProcess {
    const decision = checkSpawn(binding, config, state, sessionId, command);
    state.recordDecision(sessionId, decision, 'spawn', {
      binary: command,
      method: 'spawn',
    });

    if (!decision.allow && config.mode === 'enforce') {
      throw new ShieldProcessError(decision, command);
    }

    return (originals.spawn as Function).call(child_process, command, ...rest);
  } as typeof child_process.spawn;

  // ── Patch execFile ─────────────────────────────────────────────────
  (child_process as { execFile: typeof child_process.execFile }).execFile = function shieldExecFile(
    file: string,
    ...rest: unknown[]
  ): child_process.ChildProcess {
    const decision = checkSpawn(binding, config, state, sessionId, file);
    state.recordDecision(sessionId, decision, 'spawn', {
      binary: file,
      method: 'execFile',
    });

    if (!decision.allow && config.mode === 'enforce') {
      throw new ShieldProcessError(decision, file);
    }

    return (originals.execFile as Function).call(child_process, file, ...rest);
  } as typeof child_process.execFile;

  // ── Patch exec (discouraged, audit by default) ─────────────────────
  (child_process as { exec: typeof child_process.exec }).exec = function shieldExec(
    command: string,
    ...rest: unknown[]
  ): child_process.ChildProcess {
    // exec runs through a shell — extract the implicit shell
    const shell = process.platform === 'win32' ? 'cmd.exe' : 'sh';
    const decision = checkSpawn(binding, config, state, sessionId, shell);
    state.recordDecision(sessionId, decision, 'spawn', {
      binary: shell,
      command: command.substring(0, 200), // Truncate for logging
      method: 'exec',
    });

    if (!decision.allow && config.mode === 'enforce') {
      throw new ShieldProcessError(decision, `${shell} (exec: ${command.substring(0, 50)})`);
    }

    return (originals.exec as Function).call(child_process, command, ...rest);
  } as typeof child_process.exec;
}

/** Restore original process functions (for testing/cleanup) */
export function uninstallProcInterceptors(): void {
  (child_process as { spawn: typeof child_process.spawn }).spawn = originals.spawn;
  (child_process as { execFile: typeof child_process.execFile }).execFile = originals.execFile;
  (child_process as { exec: typeof child_process.exec }).exec = originals.exec;
}

/** Get original references (for tamper detection) */
export function getOriginals() {
  return { ...originals };
}
