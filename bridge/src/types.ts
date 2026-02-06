// OpenClaw Shield — Shared TypeScript types
//
// Type definitions shared across the bridge layer.

/** Taint states matching Zig TaintState enum */
export enum TaintState {
  CLEAN = 0,
  TAINTED = 1,
  QUARANTINED = 2,
}

/** Risk levels matching Zig Risk enum */
export enum Risk {
  LOW = 0,
  MEDIUM = 1,
  HIGH = 2,
}

/** Reason codes matching Zig ReasonCode enum (stable, never reordered) */
export enum ReasonCode {
  NONE = 0,
  NET_RFC1918_BLOCKED = 1001,
  NET_LOCALHOST_BLOCKED = 1002,
  NET_LINK_LOCAL_BLOCKED = 1003,
  NET_METADATA_BLOCKED = 1004,
  NET_DOMAIN_NOT_ALLOWED = 1005,
  NET_PORT_NOT_ALLOWED = 1006,
  NET_EGRESS_RATE_LIMIT = 1007,
  PROC_SPAWN_DENIED = 1101,
  PROC_SHELL_DENIED = 1102,
  PROC_BINARY_NOT_ALLOWED = 1103,
  RATE_LIMIT_EXCEEDED = 1201,
  TAINT_ESCALATED = 1301,
  QUARANTINED = 1302,
}

/** Labels for reason codes — used in error messages */
export const REASON_LABELS: Record<number, string> = {
  [ReasonCode.NONE]: 'ALLOWED',
  [ReasonCode.NET_RFC1918_BLOCKED]: 'NET_RFC1918_BLOCKED',
  [ReasonCode.NET_LOCALHOST_BLOCKED]: 'NET_LOCALHOST_BLOCKED',
  [ReasonCode.NET_LINK_LOCAL_BLOCKED]: 'NET_LINK_LOCAL_BLOCKED',
  [ReasonCode.NET_METADATA_BLOCKED]: 'NET_METADATA_BLOCKED',
  [ReasonCode.NET_DOMAIN_NOT_ALLOWED]: 'NET_DOMAIN_NOT_ALLOWED',
  [ReasonCode.NET_PORT_NOT_ALLOWED]: 'NET_PORT_NOT_ALLOWED',
  [ReasonCode.NET_EGRESS_RATE_LIMIT]: 'NET_EGRESS_RATE_LIMIT',
  [ReasonCode.PROC_SPAWN_DENIED]: 'PROC_SPAWN_DENIED',
  [ReasonCode.PROC_SHELL_DENIED]: 'PROC_SHELL_DENIED',
  [ReasonCode.PROC_BINARY_NOT_ALLOWED]: 'PROC_BINARY_NOT_ALLOWED',
  [ReasonCode.RATE_LIMIT_EXCEEDED]: 'RATE_LIMIT_EXCEEDED',
  [ReasonCode.TAINT_ESCALATED]: 'TAINT_ESCALATED',
  [ReasonCode.QUARANTINED]: 'QUARANTINED',
};

/** Decision result from the Zig engine */
export interface Decision {
  allow: boolean;
  reasonCode: ReasonCode;
  risk: Risk;
  taintUpdate: TaintState | null;
}

/** Deployment profiles */
export type Profile = 'home-lab' | 'corp-dev' | 'prod' | 'research';

/** Shield plugin configuration */
export interface ShieldConfig {
  mode: 'enforce' | 'audit';
  profile: Profile;
  network: {
    allowedHosts: string[];
    allowedPorts: number[];
    blockRFC1918: boolean;
    blockLocalhost: boolean;
    blockLinkLocal: boolean;
    blockMetadata: boolean;
    maxEgressBytesPerMin: number;
  };
  process: {
    allowSpawn: boolean;
    allowedBinaries: string[];
    denyShells: boolean;
    maxExecPerMin: number;
  };
  taint: {
    autoEscalate: boolean;
    quarantineThreshold: number;
    coolDownSeconds: number;
  };
  redaction: {
    strategy: 'mask' | 'partial' | 'hash' | 'drop';
  };
  entropy: {
    enabled: boolean;
    base64Threshold: number;
    hexThreshold: number;
  };
  layers?: {
    preventiveEnforcement?: boolean;
  };
}

/** Audit log entry */
export interface AuditEntry {
  timestamp: string;
  sessionId: string;
  agentId?: string;
  layer: string;
  action: string;
  decision: 'allow' | 'block';
  reasonCode: number;
  details: Record<string, unknown>;
  taintTransition?: {
    from: TaintState;
    to: TaintState;
  };
}

/** OpenClaw plugin API types (subset for our needs) */
export interface OpenClawPluginApi {
  registerHook(hook: string, handler: (...args: unknown[]) => unknown): void;
  registerTool(name: string, handler: (...args: unknown[]) => unknown): void;
  getConfig(): Record<string, unknown>;
}
