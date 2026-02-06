// OpenClaw Shield — Session State Manager
//
// Maintains per-session taint state, counters, and audit log.
// This is the TypeScript-side complement to the Zig taint_policy.zig.

import { TaintState, AuditEntry, ReasonCode, REASON_LABELS, Decision } from '../types';

/** Per-session state */
interface SessionState {
  taintState: TaintState;
  blockCount: number;
  lastTriggerTime: number;
  egressBytes: number;
  execCount: number;
  windowStart: number;
  recentBlocks: AuditEntry[];
}

/** State manager — tracks all active sessions */
export class StateManager {
  private sessions = new Map<string, SessionState>();
  private auditLog: AuditEntry[] = [];
  private windowSeconds: number;
  private quarantineThreshold: number;
  private coolDownSeconds: number;
  private maxRecentBlocks = 10;

  constructor(opts: {
    windowSeconds?: number;
    quarantineThreshold?: number;
    coolDownSeconds?: number;
  } = {}) {
    this.windowSeconds = opts.windowSeconds ?? 60;
    this.quarantineThreshold = opts.quarantineThreshold ?? 5;
    this.coolDownSeconds = opts.coolDownSeconds ?? 300;
  }

  /** Get or create session state */
  getSession(sessionId: string): SessionState {
    let session = this.sessions.get(sessionId);
    if (!session) {
      session = {
        taintState: TaintState.CLEAN,
        blockCount: 0,
        lastTriggerTime: 0,
        egressBytes: 0,
        execCount: 0,
        windowStart: Date.now(),
        recentBlocks: [],
      };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  /** Get the current taint state for a session */
  getTaintState(sessionId: string): TaintState {
    return this.getSession(sessionId).taintState;
  }

  /** Record a decision and update taint state accordingly */
  recordDecision(
    sessionId: string,
    decision: Decision,
    action: string,
    details: Record<string, unknown> = {},
  ): void {
    const session = this.getSession(sessionId);
    const now = Date.now();

    // Check if we need to reset the sliding window
    if (now - session.windowStart > this.windowSeconds * 1000) {
      session.egressBytes = 0;
      session.execCount = 0;
      session.windowStart = now;
    }

    // Create audit entry
    const entry: AuditEntry = {
      timestamp: new Date(now).toISOString(),
      sessionId,
      layer: 'L7',
      action,
      decision: decision.allow ? 'allow' : 'block',
      reasonCode: decision.reasonCode,
      details,
    };

    // If blocked, update taint
    if (!decision.allow) {
      session.blockCount++;
      session.lastTriggerTime = now;

      // Track recent blocks
      session.recentBlocks.push(entry);
      if (session.recentBlocks.length > this.maxRecentBlocks) {
        session.recentBlocks.shift();
      }

      // Escalate taint
      const oldTaint = session.taintState;
      if (decision.taintUpdate !== null) {
        if (decision.taintUpdate > session.taintState) {
          session.taintState = decision.taintUpdate;
        }
      }

      // Check quarantine threshold
      if (session.taintState === TaintState.TAINTED &&
          session.blockCount >= this.quarantineThreshold) {
        session.taintState = TaintState.QUARANTINED;
      }

      if (oldTaint !== session.taintState) {
        entry.taintTransition = { from: oldTaint, to: session.taintState };
      }
    }

    this.auditLog.push(entry);
  }

  /** Add egress bytes for rate limiting. Returns current total in window. */
  addEgressBytes(sessionId: string, bytes: number): number {
    const session = this.getSession(sessionId);
    const now = Date.now();
    if (now - session.windowStart > this.windowSeconds * 1000) {
      session.egressBytes = 0;
      session.execCount = 0;
      session.windowStart = now;
    }
    session.egressBytes += bytes;
    return session.egressBytes;
  }

  /** Increment exec count. Returns current count in window. */
  addExecCount(sessionId: string): number {
    const session = this.getSession(sessionId);
    const now = Date.now();
    if (now - session.windowStart > this.windowSeconds * 1000) {
      session.egressBytes = 0;
      session.execCount = 0;
      session.windowStart = now;
    }
    session.execCount++;
    return session.execCount;
  }

  /** Check de-escalation: TAINTED → CLEAN after cool-down */
  checkDeescalation(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.taintState !== TaintState.TAINTED) return;

    const elapsed = (Date.now() - session.lastTriggerTime) / 1000;
    if (elapsed >= this.coolDownSeconds) {
      session.taintState = TaintState.CLEAN;
      session.blockCount = 0;
    }
  }

  /** Force quarantine a session (operator command) */
  quarantineSession(sessionId: string): void {
    const session = this.getSession(sessionId);
    session.taintState = TaintState.QUARANTINED;

    this.auditLog.push({
      timestamp: new Date().toISOString(),
      sessionId,
      layer: 'operator',
      action: 'quarantine',
      decision: 'block',
      reasonCode: ReasonCode.QUARANTINED,
      details: { reason: 'Operator forced quarantine' },
    });
  }

  /** Unquarantine a session (operator command) */
  unquarantineSession(sessionId: string, reason: string): void {
    const session = this.getSession(sessionId);
    const oldState = session.taintState;
    session.taintState = TaintState.CLEAN;
    session.blockCount = 0;

    this.auditLog.push({
      timestamp: new Date().toISOString(),
      sessionId,
      layer: 'operator',
      action: 'unquarantine',
      decision: 'allow',
      reasonCode: ReasonCode.NONE,
      details: { reason },
      taintTransition: { from: oldState, to: TaintState.CLEAN },
    });
  }

  /** Get session status for operator command */
  getSessionStatus(sessionId: string): {
    taintState: string;
    blockCount: number;
    egressBytes: number;
    execCount: number;
    recentBlocks: AuditEntry[];
  } {
    const session = this.getSession(sessionId);
    return {
      taintState: TaintState[session.taintState],
      blockCount: session.blockCount,
      egressBytes: session.egressBytes,
      execCount: session.execCount,
      recentBlocks: [...session.recentBlocks],
    };
  }

  /** Export audit log as JSONL since a given duration (e.g., '1h', '30m') */
  exportAudit(since?: string): string {
    let cutoff = 0;
    if (since) {
      const match = since.match(/^(\d+)([hms])$/);
      if (match) {
        const value = parseInt(match[1]);
        const unit = match[2];
        const ms = unit === 'h' ? value * 3600000 : unit === 'm' ? value * 60000 : value * 1000;
        cutoff = Date.now() - ms;
      }
    }

    return this.auditLog
      .filter(entry => new Date(entry.timestamp).getTime() >= cutoff)
      .map(entry => JSON.stringify(entry))
      .join('\n');
  }

  /** Clear all state (for testing) */
  reset(): void {
    this.sessions.clear();
    this.auditLog = [];
  }
}
