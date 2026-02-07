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
import * as fs from 'fs';
import * as dns from 'dns';
import { StateManager } from './state';
import { ReasonCode } from '../types';

// Get mutable CJS module objects for freeze/unfreeze operations.
// When loaded via jiti, ESM namespace imports have configurable:false
// properties that prevent Object.defineProperty calls.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const httpMod: typeof http = require('http');
const httpsMod: typeof https = require('https');
const netMod: typeof net = require('net');
const tlsMod: typeof tls = require('tls');
const cpMod: typeof child_process = require('child_process');
const fsMod: typeof fs = require('fs');
const dnsMod: typeof dns = require('dns');

/** References to the patched (shield) functions */
interface PatchedRefs {
  fetch?: typeof globalThis.fetch;
  httpRequest: typeof http.request;
  httpsRequest: typeof https.request;
  httpGet: typeof http.get;
  httpsGet: typeof https.get;
  netConnect: typeof net.connect;
  tlsConnect: typeof tls.connect;
  spawn: typeof child_process.spawn;
  spawnSync: typeof child_process.spawnSync;
  execFile: typeof child_process.execFile;
  execFileSync: typeof child_process.execFileSync;
  exec: typeof child_process.exec;
  execSync: typeof child_process.execSync;
  fork: typeof child_process.fork;
  fsReadFile: typeof fs.readFile;
  fsReadFileSync: typeof fs.readFileSync;
  fsWriteFile: typeof fs.writeFile;
  fsWriteFileSync: typeof fs.writeFileSync;
  fsOpen: typeof fs.open;
  fsOpenSync: typeof fs.openSync;
  fsCreateReadStream: typeof fs.createReadStream;
  fsCreateWriteStream: typeof fs.createWriteStream;
  dnsLookup: typeof dns.lookup;
  dnsResolve: typeof dns.resolve;
  dnsResolve4: typeof dns.resolve4;
  dnsResolve6: typeof dns.resolve6;
}

let frozenRefs: PatchedRefs | null = null;
let tamperTimer: ReturnType<typeof setInterval> | null = null;

/**
 * Capture current references and freeze them using Object.defineProperty.
 * Call this AFTER installing interceptors.
 *
 * Every patched function gets frozen. If a skill swaps one out, we notice
 * on the next tamper check and quarantine the session faster than you can
 * say "I thought nobody would notice."
 */
export function freezeInterceptors(): void {
  // Capture current (patched) references from mutable CJS modules
  frozenRefs = {
    fetch: globalThis.fetch,
    httpRequest: httpMod.request,
    httpsRequest: httpsMod.request,
    httpGet: httpMod.get,
    httpsGet: httpsMod.get,
    netConnect: netMod.connect,
    tlsConnect: tlsMod.connect,
    spawn: cpMod.spawn,
    spawnSync: cpMod.spawnSync,
    execFile: cpMod.execFile,
    execFileSync: cpMod.execFileSync,
    exec: cpMod.exec,
    execSync: cpMod.execSync,
    fork: cpMod.fork,
    fsReadFile: fsMod.readFile,
    fsReadFileSync: fsMod.readFileSync,
    fsWriteFile: fsMod.writeFile,
    fsWriteFileSync: fsMod.writeFileSync,
    fsOpen: fsMod.open,
    fsOpenSync: fsMod.openSync,
    fsCreateReadStream: fsMod.createReadStream,
    fsCreateWriteStream: fsMod.createWriteStream,
    dnsLookup: dnsMod.lookup,
    dnsResolve: dnsMod.resolve,
    dnsResolve4: dnsMod.resolve4,
    dnsResolve6: dnsMod.resolve6,
  };

  // Best-effort freeze: make properties non-writable
  // Network
  tryFreeze(httpMod, 'request', frozenRefs.httpRequest);
  tryFreeze(httpsMod, 'request', frozenRefs.httpsRequest);
  tryFreeze(httpMod, 'get', frozenRefs.httpGet);
  tryFreeze(httpsMod, 'get', frozenRefs.httpsGet);
  tryFreeze(netMod, 'connect', frozenRefs.netConnect);
  tryFreeze(tlsMod, 'connect', frozenRefs.tlsConnect);
  // Process
  tryFreeze(cpMod, 'spawn', frozenRefs.spawn);
  tryFreeze(cpMod, 'spawnSync', frozenRefs.spawnSync);
  tryFreeze(cpMod, 'execFile', frozenRefs.execFile);
  tryFreeze(cpMod, 'execFileSync', frozenRefs.execFileSync);
  tryFreeze(cpMod, 'exec', frozenRefs.exec);
  tryFreeze(cpMod, 'execSync', frozenRefs.execSync);
  tryFreeze(cpMod, 'fork', frozenRefs.fork);
  // Filesystem
  tryFreeze(fsMod, 'readFile', frozenRefs.fsReadFile);
  tryFreeze(fsMod, 'readFileSync', frozenRefs.fsReadFileSync);
  tryFreeze(fsMod, 'writeFile', frozenRefs.fsWriteFile);
  tryFreeze(fsMod, 'writeFileSync', frozenRefs.fsWriteFileSync);
  tryFreeze(fsMod, 'open', frozenRefs.fsOpen);
  tryFreeze(fsMod, 'openSync', frozenRefs.fsOpenSync);
  tryFreeze(fsMod, 'createReadStream', frozenRefs.fsCreateReadStream);
  tryFreeze(fsMod, 'createWriteStream', frozenRefs.fsCreateWriteStream);
  // DNS
  tryFreeze(dnsMod, 'lookup', frozenRefs.dnsLookup);
  tryFreeze(dnsMod, 'resolve', frozenRefs.dnsResolve);
  tryFreeze(dnsMod, 'resolve4', frozenRefs.dnsResolve4);
  tryFreeze(dnsMod, 'resolve6', frozenRefs.dnsResolve6);
}

function tryFreeze(obj: object, prop: string, value: unknown): void {
  try {
    Object.defineProperty(obj, prop, {
      value,
      writable: false,
      configurable: true, // Must stay configurable so we can unfreeze during shutdown
    });
  } catch {
    // Some environments don't allow freezing built-in modules
    // That's OK — tamper detection will still catch changes
  }
}

function tryUnfreeze(obj: object, prop: string): void {
  try {
    Object.defineProperty(obj, prop, {
      writable: true,
      configurable: true,
    });
  } catch {
    // Best effort — may already be writable
  }
}

/**
 * Check if any interceptor has been tampered with.
 * Returns an array of tampered function names, or empty if clean.
 */
export function detectTamper(): string[] {
  if (!frozenRefs) return [];

  const tampered: string[] = [];

  // Check every patched function. If you're wondering why we check this many,
  // it's because we learned the hard way that attackers read source code.
  // We now guard 26 entry points. Miss one, and the attacker gets a free pass —
  // like having a 25-digit PIN but leaving the last digit on a sticky note.
  const checks: [unknown, unknown, string][] = [
    [globalThis.fetch, frozenRefs.fetch, 'fetch'],
    [httpMod.request, frozenRefs.httpRequest, 'http.request'],
    [httpsMod.request, frozenRefs.httpsRequest, 'https.request'],
    [httpMod.get, frozenRefs.httpGet, 'http.get'],
    [httpsMod.get, frozenRefs.httpsGet, 'https.get'],
    [netMod.connect, frozenRefs.netConnect, 'net.connect'],
    [tlsMod.connect, frozenRefs.tlsConnect, 'tls.connect'],
    [cpMod.spawn, frozenRefs.spawn, 'child_process.spawn'],
    [cpMod.spawnSync, frozenRefs.spawnSync, 'child_process.spawnSync'],
    [cpMod.execFile, frozenRefs.execFile, 'child_process.execFile'],
    [cpMod.execFileSync, frozenRefs.execFileSync, 'child_process.execFileSync'],
    [cpMod.exec, frozenRefs.exec, 'child_process.exec'],
    [cpMod.execSync, frozenRefs.execSync, 'child_process.execSync'],
    [cpMod.fork, frozenRefs.fork, 'child_process.fork'],
    [fsMod.readFile, frozenRefs.fsReadFile, 'fs.readFile'],
    [fsMod.readFileSync, frozenRefs.fsReadFileSync, 'fs.readFileSync'],
    [fsMod.writeFile, frozenRefs.fsWriteFile, 'fs.writeFile'],
    [fsMod.writeFileSync, frozenRefs.fsWriteFileSync, 'fs.writeFileSync'],
    [fsMod.open, frozenRefs.fsOpen, 'fs.open'],
    [fsMod.openSync, frozenRefs.fsOpenSync, 'fs.openSync'],
    [fsMod.createReadStream, frozenRefs.fsCreateReadStream, 'fs.createReadStream'],
    [fsMod.createWriteStream, frozenRefs.fsCreateWriteStream, 'fs.createWriteStream'],
    [dnsMod.lookup, frozenRefs.dnsLookup, 'dns.lookup'],
    [dnsMod.resolve, frozenRefs.dnsResolve, 'dns.resolve'],
    [dnsMod.resolve4, frozenRefs.dnsResolve4, 'dns.resolve4'],
    [dnsMod.resolve6, frozenRefs.dnsResolve6, 'dns.resolve6'],
  ];

  for (const [current, expected, name] of checks) {
    if (expected && current !== expected) {
      tampered.push(name);
    }
  }

  return tampered;
}

/**
 * Start periodic tamper detection. On tamper:
 *   1. Quarantines the session
 *   2. Emits an audit event
 *   3. Attempts to re-freeze the interceptors
 *
 * Default interval: 1000ms. Because 5 seconds is an eternity when someone
 * is trying to exfiltrate your AWS credentials through a forked Node process
 * they snuck past the guards.
 *
 * @param state - Session state manager
 * @param sessionId - Current session ID
 * @param intervalMs - Check interval (default: 1000ms)
 */
export function startTamperDetection(
  state: StateManager,
  sessionId: string,
  intervalMs: number = 1000,
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

/** Reset freeze state — unfreeze all properties so they can be re-assigned */
export function resetFreeze(): void {
  stopTamperDetection();
  if (frozenRefs) {
    // Network
    tryUnfreeze(httpMod, 'request');
    tryUnfreeze(httpsMod, 'request');
    tryUnfreeze(httpMod, 'get');
    tryUnfreeze(httpsMod, 'get');
    tryUnfreeze(netMod, 'connect');
    tryUnfreeze(tlsMod, 'connect');
    // Process
    tryUnfreeze(cpMod, 'spawn');
    tryUnfreeze(cpMod, 'spawnSync');
    tryUnfreeze(cpMod, 'execFile');
    tryUnfreeze(cpMod, 'execFileSync');
    tryUnfreeze(cpMod, 'exec');
    tryUnfreeze(cpMod, 'execSync');
    tryUnfreeze(cpMod, 'fork');
    // Filesystem
    tryUnfreeze(fsMod, 'readFile');
    tryUnfreeze(fsMod, 'readFileSync');
    tryUnfreeze(fsMod, 'writeFile');
    tryUnfreeze(fsMod, 'writeFileSync');
    tryUnfreeze(fsMod, 'open');
    tryUnfreeze(fsMod, 'openSync');
    tryUnfreeze(fsMod, 'createReadStream');
    tryUnfreeze(fsMod, 'createWriteStream');
    // DNS
    tryUnfreeze(dnsMod, 'lookup');
    tryUnfreeze(dnsMod, 'resolve');
    tryUnfreeze(dnsMod, 'resolve4');
    tryUnfreeze(dnsMod, 'resolve6');
  }
  frozenRefs = null;
}
