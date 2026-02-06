// OpenClaw Shield — Freeze & Tamper Detection
//
// After interceptors are installed, this module:
//   1. Freezes patched function references so skills can't un-patch them
//   2. Periodically verifies references still match (tamper detection)
//   3. On tamper → quarantines the session and emits audit event

import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import * as child_process from 'child_process';
import { StateManager } from './state';
import { ReasonCode } from '../types';

/** References to the patched (shield) functions */
interface PatchedRefs {
  fetch?: typeof globalThis.fetch;
  httpRequest: typeof http.request;
  httpsRequest: typeof https.request;
  netConnect: typeof net.connect;
  tlsConnect: typeof tls.connect;
  spawn: typeof child_process.spawn;
  execFile: typeof child_process.execFile;
  exec: typeof child_process.exec;
}

let frozenRefs: PatchedRefs | null = null;
let tamperTimer: ReturnType<typeof setInterval> | null = null;

/**
 * Capture current references and freeze them using Object.defineProperty.
 * Call this AFTER installing interceptors.
 */
export function freezeInterceptors(): void {
  // Capture current (patched) references
  frozenRefs = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpsRequest: https.request,
    netConnect: net.connect,
    tlsConnect: tls.connect,
    spawn: child_process.spawn,
    execFile: child_process.execFile,
    exec: child_process.exec,
  };

  // Best-effort freeze: make properties non-writable
  tryFreeze(http, 'request', frozenRefs.httpRequest);
  tryFreeze(https, 'request', frozenRefs.httpsRequest);
  tryFreeze(net, 'connect', frozenRefs.netConnect);
  tryFreeze(tls, 'connect', frozenRefs.tlsConnect);
  tryFreeze(child_process, 'spawn', frozenRefs.spawn);
  tryFreeze(child_process, 'execFile', frozenRefs.execFile);
  tryFreeze(child_process, 'exec', frozenRefs.exec);
}

function tryFreeze(obj: object, prop: string, value: unknown): void {
  try {
    Object.defineProperty(obj, prop, {
      value,
      writable: false,
      configurable: false,
    });
  } catch {
    // Some environments don't allow freezing built-in modules
    // That's OK — tamper detection will still catch changes
  }
}

/**
 * Check if any interceptor has been tampered with.
 * Returns an array of tampered function names, or empty if clean.
 */
export function detectTamper(): string[] {
  if (!frozenRefs) return [];

  const tampered: string[] = [];

  if (frozenRefs.fetch && globalThis.fetch !== frozenRefs.fetch) {
    tampered.push('fetch');
  }
  if (http.request !== frozenRefs.httpRequest) {
    tampered.push('http.request');
  }
  if (https.request !== frozenRefs.httpsRequest) {
    tampered.push('https.request');
  }
  if (net.connect !== frozenRefs.netConnect) {
    tampered.push('net.connect');
  }
  if (tls.connect !== frozenRefs.tlsConnect) {
    tampered.push('tls.connect');
  }
  if (child_process.spawn !== frozenRefs.spawn) {
    tampered.push('child_process.spawn');
  }
  if (child_process.execFile !== frozenRefs.execFile) {
    tampered.push('child_process.execFile');
  }
  if (child_process.exec !== frozenRefs.exec) {
    tampered.push('child_process.exec');
  }

  return tampered;
}

/**
 * Start periodic tamper detection. On tamper:
 *   1. Quarantines the session
 *   2. Emits an audit event
 *   3. Attempts to re-freeze the interceptors
 *
 * @param state - Session state manager
 * @param sessionId - Current session ID
 * @param intervalMs - Check interval (default: 5000ms)
 */
export function startTamperDetection(
  state: StateManager,
  sessionId: string,
  intervalMs: number = 5000,
): void {
  if (tamperTimer) return; // Already running

  tamperTimer = setInterval(() => {
    const tampered = detectTamper();
    if (tampered.length > 0) {
      // Quarantine immediately
      state.quarantineSession(sessionId);

      // Audit
      state.recordDecision(
        sessionId,
        {
          allow: false,
          reasonCode: ReasonCode.QUARANTINED,
          risk: 2, // high
          taintUpdate: null,
        },
        'tamper_detected',
        {
          tamperedFunctions: tampered,
          message: 'Interceptor tamper detected — session quarantined',
        },
      );

      // Attempt to re-freeze
      freezeInterceptors();
    }
  }, intervalMs);

  // Don't let the timer keep the process alive
  if (tamperTimer && typeof tamperTimer === 'object' && 'unref' in tamperTimer) {
    tamperTimer.unref();
  }
}

/** Stop tamper detection timer */
export function stopTamperDetection(): void {
  if (tamperTimer) {
    clearInterval(tamperTimer);
    tamperTimer = null;
  }
}

/** Reset freeze state (for testing) */
export function resetFreeze(): void {
  stopTamperDetection();
  frozenRefs = null;
}
