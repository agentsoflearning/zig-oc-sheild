// OpenClaw Shield — Policy Loader (TypeScript)
//
// Loads and validates policy config from JSON files.
// Mirrors the Zig policy loader logic on the TS side.

import * as fs from 'fs';
import * as path from 'path';
import { ShieldConfig, Profile } from './types';

// ── Validation ──────────────────────────────────────────────────────

export interface ValidationError {
  field: string;
  message: string;
  severity: 'error' | 'warning';
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
}

const VALID_MODES = ['enforce', 'audit'];
const VALID_PROFILES: Profile[] = ['home-lab', 'corp-dev', 'prod', 'research'];
const VALID_STRATEGIES = ['mask', 'partial', 'hash', 'drop'];

/** Validate a ShieldConfig object. */
export function validateConfig(config: Partial<ShieldConfig>): ValidationResult {
  const errors: ValidationError[] = [];
  const warnings: ValidationError[] = [];

  // Mode
  if (config.mode && !VALID_MODES.includes(config.mode)) {
    errors.push({ field: 'mode', message: `must be "enforce" or "audit", got "${config.mode}"`, severity: 'error' });
  }

  // Profile
  if (config.profile && !VALID_PROFILES.includes(config.profile)) {
    errors.push({ field: 'profile', message: `must be one of: ${VALID_PROFILES.join(', ')}`, severity: 'error' });
  }

  // Redaction
  if (config.redaction) {
    if (config.redaction.strategy && !VALID_STRATEGIES.includes(config.redaction.strategy)) {
      errors.push({ field: 'redaction.strategy', message: `must be one of: ${VALID_STRATEGIES.join(', ')}`, severity: 'error' });
    }
  }

  // Entropy
  if (config.entropy) {
    if (config.entropy.base64Threshold !== undefined) {
      if (config.entropy.base64Threshold <= 0 || config.entropy.base64Threshold > 8) {
        errors.push({ field: 'entropy.base64Threshold', message: 'must be between 0 and 8', severity: 'error' });
      } else if (config.entropy.base64Threshold < 3) {
        warnings.push({ field: 'entropy.base64Threshold', message: 'below 3.0 may cause excessive false positives', severity: 'warning' });
      }
    }
  }

  // Network
  if (config.network) {
    if (config.network.maxEgressBytesPerMin !== undefined && config.network.maxEgressBytesPerMin <= 0) {
      errors.push({ field: 'network.maxEgressBytesPerMin', message: 'must be positive', severity: 'error' });
    }
  }

  // Process
  if (config.process) {
    if (config.process.maxExecPerMin !== undefined && config.process.maxExecPerMin <= 0) {
      errors.push({ field: 'process.maxExecPerMin', message: 'must be positive', severity: 'error' });
    }
    if (config.process.allowSpawn && config.process.denyShells === false) {
      warnings.push({ field: 'process', message: 'allowSpawn=true with denyShells=false permits shell access', severity: 'warning' });
    }
  }

  // Taint
  if (config.taint) {
    if (config.taint.quarantineThreshold !== undefined && config.taint.quarantineThreshold <= 0) {
      errors.push({ field: 'taint.quarantineThreshold', message: 'must be positive', severity: 'error' });
    }
    if (config.taint.coolDownSeconds === 0 && config.taint.autoEscalate) {
      warnings.push({ field: 'taint.coolDownSeconds', message: '0 cool-down with auto-escalate means no de-escalation path', severity: 'warning' });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ── File Loading ────────────────────────────────────────────────────

/** Default policy file search paths (relative to CWD). */
const POLICY_FILE_NAMES = [
  'ocshield.json',
  'openclaw-shield.json',
  '.ocshield.json',
];

/**
 * Load policy config from a JSON file.
 * Returns the parsed config or null if the file doesn't exist.
 */
export function loadConfigFromFile(filePath: string): Partial<ShieldConfig> | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(content) as Partial<ShieldConfig>;
  } catch {
    return null;
  }
}

/**
 * Search for a policy file in default locations and load it.
 * Searches CWD and project root.
 */
export function discoverConfigFile(baseDirs?: string[]): { path: string; config: Partial<ShieldConfig> } | null {
  const dirs = baseDirs ?? [process.cwd()];

  for (const dir of dirs) {
    for (const name of POLICY_FILE_NAMES) {
      const fullPath = path.join(dir, name);
      const config = loadConfigFromFile(fullPath);
      if (config) {
        return { path: fullPath, config };
      }
    }
  }

  return null;
}

/**
 * Load and validate a policy file. Returns the config if valid,
 * or throws with validation errors.
 */
export function loadAndValidateConfig(filePath: string): ShieldConfig {
  const config = loadConfigFromFile(filePath);
  if (!config) {
    throw new Error(`Policy file not found: ${filePath}`);
  }

  const result = validateConfig(config);
  if (!result.valid) {
    const errorMessages = result.errors.map(e => `  ${e.field}: ${e.message}`).join('\n');
    throw new Error(`Invalid policy file ${filePath}:\n${errorMessages}`);
  }

  if (result.warnings.length > 0) {
    for (const w of result.warnings) {
      console.warn(`[OC-SHIELD] Policy warning — ${w.field}: ${w.message}`);
    }
  }

  return config as ShieldConfig;
}
