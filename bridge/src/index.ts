// OpenClaw Shield — Plugin Entry Point
//
// This is the main entry point loaded by OpenClaw via jiti.
// It initializes the Zig binding, resolves the deployment profile,
// installs L7 interceptors, and registers plugin hooks/tools.
//
// Usage in OpenClaw config:
//   plugins: ['@ocshield/bridge']

import { loadBindingSync, NativeBinding } from './native';
import { installNetInterceptors, uninstallNetInterceptors } from './intercept/net';
import { installProcInterceptors, uninstallProcInterceptors } from './intercept/proc';
import { installFsInterceptors, uninstallFsInterceptors } from './intercept/fs';
import { installDnsInterceptors, uninstallDnsInterceptors } from './intercept/dns';
import { freezeInterceptors, startTamperDetection, stopTamperDetection, resetFreeze } from './intercept/freeze';
import { StateManager } from './intercept/state';
import { ShieldConfig, Profile, TaintState } from './types';
import { discoverConfigFile, validateConfig } from './policy';

// ── Profile Defaults ──────────────────────────────────────────────────

const PROFILE_DEFAULTS: Record<Profile, Partial<ShieldConfig>> = {
  'home-lab': {
    mode: 'audit',
    network: {
      allowedHosts: ['*'],
      allowedPorts: [80, 443, 8080, 3000],
      blockRFC1918: false,
      blockLocalhost: false,
      blockLinkLocal: false,
      blockMetadata: true,
      maxEgressBytesPerMin: 104857600, // 100 MB
    },
    process: {
      allowSpawn: true,
      allowedBinaries: ['*'],
      denyShells: false,
      maxExecPerMin: 100,
    },
    filesystem: {
      blockSensitivePaths: true,
      blockWrites: false,
      allowedWritePaths: ['*'],
      blockPathTraversal: true,
    },
    dns: {
      blockPrivateResolution: false,
      allowedDomains: ['*'],
      blockAllDns: false,
    },
    taint: {
      autoEscalate: false,
      quarantineThreshold: 999,
      coolDownSeconds: 60,
    },
  },
  'corp-dev': {
    mode: 'enforce',
    network: {
      allowedHosts: ['*.internal.corp'],
      allowedPorts: [80, 443],
      blockRFC1918: true,
      blockLocalhost: false,
      blockLinkLocal: true,
      blockMetadata: true,
      maxEgressBytesPerMin: 52428800, // 50 MB
    },
    process: {
      allowSpawn: true,
      allowedBinaries: ['git', 'node', 'npx', 'python'],
      denyShells: true,
      maxExecPerMin: 30,
    },
    filesystem: {
      blockSensitivePaths: true,
      blockWrites: true,
      allowedWritePaths: ['/tmp/*', '/var/tmp/*'],
      blockPathTraversal: true,
    },
    dns: {
      blockPrivateResolution: true,
      allowedDomains: ['*.internal.corp'],
      blockAllDns: false,
    },
    taint: {
      autoEscalate: true,
      quarantineThreshold: 10,
      coolDownSeconds: 300,
    },
  },
  'prod': {
    mode: 'enforce',
    network: {
      allowedHosts: [],
      allowedPorts: [443],
      blockRFC1918: true,
      blockLocalhost: true,
      blockLinkLocal: true,
      blockMetadata: true,
      maxEgressBytesPerMin: 10485760, // 10 MB
    },
    process: {
      allowSpawn: false,
      allowedBinaries: [],
      denyShells: true,
      maxExecPerMin: 10,
    },
    filesystem: {
      blockSensitivePaths: true,
      blockWrites: true,
      allowedWritePaths: [],
      blockPathTraversal: true,
    },
    dns: {
      blockPrivateResolution: true,
      allowedDomains: [],
      blockAllDns: false,
    },
    taint: {
      autoEscalate: true,
      quarantineThreshold: 5,
      coolDownSeconds: 300,
    },
  },
  'research': {
    mode: 'enforce',
    network: {
      allowedHosts: ['*'],
      allowedPorts: [80, 443],
      blockRFC1918: true,
      blockLocalhost: true,
      blockLinkLocal: true,
      blockMetadata: true,
      maxEgressBytesPerMin: 52428800, // 50 MB
    },
    process: {
      allowSpawn: true,
      allowedBinaries: ['git', 'node', 'npx', 'python', 'pip'],
      denyShells: true,
      maxExecPerMin: 30,
    },
    filesystem: {
      blockSensitivePaths: true,
      blockWrites: true,
      allowedWritePaths: ['/tmp/*'],
      blockPathTraversal: true,
    },
    dns: {
      blockPrivateResolution: true,
      allowedDomains: ['*'],
      blockAllDns: false,
    },
    taint: {
      autoEscalate: true,
      quarantineThreshold: 10,
      coolDownSeconds: 300,
    },
  },
};

/** Default config matching Appendix C recommended defaults */
const DEFAULT_CONFIG: ShieldConfig = {
  mode: 'enforce',
  profile: 'prod',
  network: {
    allowedHosts: [],
    allowedPorts: [80, 443],
    blockRFC1918: true,
    blockLocalhost: true,
    blockLinkLocal: true,
    blockMetadata: true,
    maxEgressBytesPerMin: 10485760,
  },
  process: {
    allowSpawn: false,
    allowedBinaries: [],
    denyShells: true,
    maxExecPerMin: 10,
  },
  taint: {
    autoEscalate: true,
    quarantineThreshold: 5,
    coolDownSeconds: 300,
  },
  filesystem: {
    blockSensitivePaths: true,
    blockWrites: true,
    allowedWritePaths: [],
    blockPathTraversal: true,
  },
  dns: {
    blockPrivateResolution: true,
    allowedDomains: [],
    blockAllDns: false,
  },
  redaction: {
    strategy: 'mask',
  },
  entropy: {
    enabled: true,
    base64Threshold: 4.5,
    hexThreshold: 3.5,
  },
};

// ── Config Resolution ─────────────────────────────────────────────────

// Keys that must never traverse into user-supplied config objects.
// A security tool with prototype pollution is like a fire extinguisher
// filled with gasoline.
const POISONED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Deep merge user config over profile defaults */
function deepMerge(base: Record<string, unknown>, overrides: Record<string, unknown>): Record<string, unknown> {
  const result = { ...base };
  for (const key of Object.keys(overrides)) {
    if (POISONED_KEYS.has(key)) continue; // Nice try, Satan.

    const val = overrides[key];
    if (val !== undefined && typeof val === 'object' && val !== null && !Array.isArray(val)) {
      result[key] = deepMerge(
        (result[key] ?? {}) as Record<string, unknown>,
        val as Record<string, unknown>,
      );
    } else if (val !== undefined) {
      result[key] = val;
    }
  }
  return result;
}

/** Resolve config: profile defaults → user overrides */
export function resolveConfig(userConfig: Record<string, unknown> = {}): ShieldConfig {
  const profile = (userConfig.profile ?? 'prod') as Profile;
  const profileDefaults = PROFILE_DEFAULTS[profile] ?? PROFILE_DEFAULTS['prod'];

  // Start with DEFAULT_CONFIG, layer profile, then user overrides
  let config = deepMerge(
    DEFAULT_CONFIG as unknown as Record<string, unknown>,
    profileDefaults as Record<string, unknown>,
  );
  config = deepMerge(config, userConfig);
  config.profile = profile;

  return config as unknown as ShieldConfig;
}

// ── Plugin Instance ───────────────────────────────────────────────────

let binding: NativeBinding | null = null;
let stateManager: StateManager | null = null;
let currentConfig: ShieldConfig | null = null;
let initialized = false;

/**
 * Initialize the shield plugin.
 * Called by OpenClaw during plugin loading.
 */
export function init(pluginConfig: Record<string, unknown> = {}): void {
  if (initialized) return;

  // Load native binding (sync: N-API > pure-TS)
  binding = loadBindingSync();

  // Auto-discover policy file if no explicit config provided
  if (Object.keys(pluginConfig).length === 0) {
    const discovered = discoverConfigFile();
    if (discovered) {
      const validation = validateConfig(discovered.config);
      if (validation.valid) {
        pluginConfig = discovered.config as Record<string, unknown>;
        console.log(`[OC-SHIELD] Loaded policy from: ${discovered.path}`);
      } else {
        console.warn(`[OC-SHIELD] Invalid policy file ${discovered.path}, using defaults`);
      }
    }
  }

  // Resolve configuration
  currentConfig = resolveConfig(pluginConfig);

  // Create state manager
  stateManager = new StateManager({
    windowSeconds: 60,
    quarantineThreshold: currentConfig.taint.quarantineThreshold,
    coolDownSeconds: currentConfig.taint.coolDownSeconds,
  });

  // Generate session ID (in real OpenClaw, this comes from the session context)
  const sessionId = pluginConfig.sessionId as string ?? `shield-${Date.now()}`;

  // Install interceptors
  if (currentConfig.layers?.preventiveEnforcement !== false) {
    installNetInterceptors(binding, currentConfig, stateManager, sessionId);
    installProcInterceptors(binding, currentConfig, stateManager, sessionId);
    installFsInterceptors(currentConfig, stateManager, sessionId);
    installDnsInterceptors(currentConfig, stateManager, sessionId);
    freezeInterceptors();
    startTamperDetection(stateManager, sessionId);
  }

  initialized = true;

  console.log(
    `[OC-SHIELD] Initialized — profile=${currentConfig.profile}, ` +
    `mode=${currentConfig.mode}, binding=${binding.bindingType}`,
  );
}

/**
 * Shut down the shield plugin cleanly.
 */
export function shutdown(): void {
  stopTamperDetection();
  resetFreeze();
  uninstallNetInterceptors();
  uninstallProcInterceptors();
  uninstallFsInterceptors();
  uninstallDnsInterceptors();
  initialized = false;
  binding = null;
  stateManager = null;
  currentConfig = null;
}

// ── Operator Commands ─────────────────────────────────────────────────

/**
 * Shield status — returns current state for operator display.
 */
export function shieldStatus(sessionId?: string): Record<string, unknown> {
  if (!stateManager || !currentConfig || !binding) {
    return { error: 'Shield not initialized' };
  }

  const result: Record<string, unknown> = {
    profile: currentConfig.profile,
    mode: currentConfig.mode,
    binding: binding.bindingType,
    version: binding.version(),
  };

  if (sessionId) {
    result.session = stateManager.getSessionStatus(sessionId);
  }

  return result;
}

/**
 * Quarantine a session — blocks all side-effects.
 */
export function shieldQuarantine(sessionId: string): void {
  if (!stateManager) throw new Error('Shield not initialized');
  stateManager.quarantineSession(sessionId);
}

/**
 * Unquarantine a session — restores to CLEAN.
 */
export function shieldUnquarantine(sessionId: string, reason: string): void {
  if (!stateManager) throw new Error('Shield not initialized');
  stateManager.unquarantineSession(sessionId, reason);
}

/**
 * Switch deployment profile at runtime.
 */
export function shieldSetProfile(profile: Profile, userOverrides: Record<string, unknown> = {}): void {
  if (!stateManager || !binding) throw new Error('Shield not initialized');

  // Tear down current interceptors
  stopTamperDetection();
  resetFreeze();
  uninstallNetInterceptors();
  uninstallProcInterceptors();
  uninstallFsInterceptors();
  uninstallDnsInterceptors();

  // Resolve new config
  currentConfig = resolveConfig({ ...userOverrides, profile });

  // Generate a new session ID or keep the old one
  const sessionId = `shield-${Date.now()}`;

  // Re-install interceptors
  installNetInterceptors(binding, currentConfig, stateManager, sessionId);
  installProcInterceptors(binding, currentConfig, stateManager, sessionId);
  installFsInterceptors(currentConfig, stateManager, sessionId);
  installDnsInterceptors(currentConfig, stateManager, sessionId);
  freezeInterceptors();
  startTamperDetection(stateManager, sessionId);

  console.log(`[OC-SHIELD] Profile changed to: ${profile}`);
}

/**
 * Export audit log as JSONL.
 */
export function shieldExportAudit(since?: string): string {
  if (!stateManager) throw new Error('Shield not initialized');
  return stateManager.exportAudit(since);
}

// ── OpenClaw Plugin API ───────────────────────────────────────────────

/**
 * OpenClaw plugin registration function.
 * This is what OpenClaw calls when loading the plugin via jiti.
 */
export default function register(api: {
  registerHook?: (hook: string, handler: (...args: unknown[]) => unknown) => void;
  registerTool?: (name: string, handler: (...args: unknown[]) => unknown) => void;
  getConfig?: () => Record<string, unknown>;
}): void {
  const pluginConfig = api.getConfig?.() ?? {};
  init(pluginConfig);

  // Register operator tool (if tool registration is available)
  if (api.registerTool) {
    api.registerTool('oc_shield', (args: unknown) => {
      const cmd = args as Record<string, unknown>;
      const action = cmd.action as string;

      switch (action) {
        case 'status':
          return shieldStatus(cmd.sessionId as string);
        case 'quarantine':
          shieldQuarantine(cmd.sessionId as string);
          return { success: true, message: `Session ${cmd.sessionId} quarantined` };
        case 'unquarantine':
          shieldUnquarantine(cmd.sessionId as string, cmd.reason as string ?? 'operator');
          return { success: true, message: `Session ${cmd.sessionId} unquarantined` };
        case 'set-profile':
          shieldSetProfile(cmd.profile as Profile);
          return { success: true, message: `Profile changed to ${cmd.profile}` };
        case 'export-audit':
          return { audit: shieldExportAudit(cmd.since as string) };
        default:
          return { error: `Unknown action: ${action}` };
      }
    });
  }
}

// ── Exports for direct usage ──────────────────────────────────────────

export {
  ShieldConfig,
  Profile,
  TaintState,
} from './types';
export { StateManager } from './intercept/state';
export type { NativeBinding } from './native';
export { loadBinding, loadBindingSync, buildPolicyFlags } from './native';
export { installNetInterceptors, uninstallNetInterceptors, ShieldNetworkError } from './intercept/net';
export { installProcInterceptors, uninstallProcInterceptors, ShieldProcessError } from './intercept/proc';
export { installFsInterceptors, uninstallFsInterceptors, ShieldFilesystemError } from './intercept/fs';
export { installDnsInterceptors, uninstallDnsInterceptors, ShieldDnsError } from './intercept/dns';
export { freezeInterceptors, startTamperDetection, stopTamperDetection, detectTamper } from './intercept/freeze';
export { loadConfigFromFile, discoverConfigFile, validateConfig, loadAndValidateConfig } from './policy';
export type { ValidationResult, ValidationError } from './policy';
