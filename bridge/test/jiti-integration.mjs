/**
 * OpenClaw Shield — jiti Integration Test
 *
 * Validates that the plugin loads correctly through jiti (the same loader
 * OpenClaw uses). This is the closest simulation of real plugin loading
 * without running the full OpenClaw server.
 *
 * Usage:
 *   node test/jiti-integration.mjs
 *   npm test
 */

import { createJiti } from 'jiti';
import { fileURLToPath } from 'url';
import path from 'path';
import assert from 'assert';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bridgeRoot = path.resolve(__dirname, '..');
const srcEntry = path.join(bridgeRoot, 'src', 'index.ts');

let passed = 0;
let failed = 0;
const errors = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  \u2713 ${name}`);
  } catch (err) {
    failed++;
    errors.push({ name, err });
    console.log(`  \u2717 ${name}`);
    console.log(`    ${err.message}`);
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  \u2713 ${name}`);
  } catch (err) {
    failed++;
    errors.push({ name, err });
    console.log(`  \u2717 ${name}`);
    console.log(`    ${err.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════════
// 1. jiti Loading — simulate OpenClaw's plugin loader
// ═══════════════════════════════════════════════════════════════════

console.log('\n1. jiti Loading');
console.log('───────────────');

let mod;

await testAsync('loads plugin from TypeScript source via jiti', async () => {
  const jiti = createJiti(import.meta.url, {
    interopDefault: true,
    // Match OpenClaw's loader config
    extensions: ['.ts', '.tsx', '.mts', '.cts', '.js', '.mjs', '.cjs', '.json'],
  });

  mod = await jiti.import(srcEntry);
  assert.ok(mod, 'module should load');
});

test('module has default export (register function)', () => {
  assert.ok(mod.default, 'default export should exist');
  assert.strictEqual(typeof mod.default, 'function', 'default export should be a function');
});

test('module exports named functions', () => {
  assert.strictEqual(typeof mod.init, 'function', 'init should be a function');
  assert.strictEqual(typeof mod.shutdown, 'function', 'shutdown should be a function');
  assert.strictEqual(typeof mod.resolveConfig, 'function', 'resolveConfig should be a function');
  assert.strictEqual(typeof mod.shieldStatus, 'function', 'shieldStatus should be a function');
  assert.strictEqual(typeof mod.shieldQuarantine, 'function', 'shieldQuarantine should be a function');
  assert.strictEqual(typeof mod.shieldUnquarantine, 'function', 'shieldUnquarantine should be a function');
  assert.strictEqual(typeof mod.shieldSetProfile, 'function', 'shieldSetProfile should be a function');
  assert.strictEqual(typeof mod.shieldExportAudit, 'function', 'shieldExportAudit should be a function');
});

test('module exports interceptor functions', () => {
  assert.strictEqual(typeof mod.installNetInterceptors, 'function');
  assert.strictEqual(typeof mod.uninstallNetInterceptors, 'function');
  assert.strictEqual(typeof mod.installProcInterceptors, 'function');
  assert.strictEqual(typeof mod.uninstallProcInterceptors, 'function');
  assert.strictEqual(typeof mod.freezeInterceptors, 'function');
  assert.strictEqual(typeof mod.startTamperDetection, 'function');
  assert.strictEqual(typeof mod.stopTamperDetection, 'function');
  assert.strictEqual(typeof mod.detectTamper, 'function');
});

test('module exports policy functions', () => {
  assert.strictEqual(typeof mod.loadConfigFromFile, 'function');
  assert.strictEqual(typeof mod.discoverConfigFile, 'function');
  assert.strictEqual(typeof mod.validateConfig, 'function');
  assert.strictEqual(typeof mod.loadAndValidateConfig, 'function');
});

test('module exports binding functions', () => {
  assert.strictEqual(typeof mod.loadBindingSync, 'function');
  assert.strictEqual(typeof mod.buildPolicyFlags, 'function');
});

test('module exports type enums', () => {
  assert.ok(mod.TaintState !== undefined, 'TaintState should be exported');
  assert.strictEqual(mod.TaintState.CLEAN, 0);
  assert.strictEqual(mod.TaintState.TAINTED, 1);
  assert.strictEqual(mod.TaintState.QUARANTINED, 2);
});

test('module exports StateManager class', () => {
  assert.strictEqual(typeof mod.StateManager, 'function', 'StateManager should be a constructor');
});

test('module exports error classes', () => {
  assert.strictEqual(typeof mod.ShieldNetworkError, 'function');
  assert.strictEqual(typeof mod.ShieldProcessError, 'function');
});

// ═══════════════════════════════════════════════════════════════════
// 2. Config Resolution
// ═══════════════════════════════════════════════════════════════════

console.log('\n2. Config Resolution');
console.log('────────────────────');

test('resolveConfig returns defaults for empty input', () => {
  const cfg = mod.resolveConfig({});
  assert.strictEqual(cfg.mode, 'enforce');
  assert.strictEqual(cfg.profile, 'prod');
  assert.strictEqual(cfg.taint.quarantineThreshold, 5);
  assert.strictEqual(cfg.process.allowSpawn, false);
  assert.strictEqual(cfg.process.denyShells, true);
});

test('resolveConfig applies home-lab profile', () => {
  const cfg = mod.resolveConfig({ profile: 'home-lab' });
  assert.strictEqual(cfg.mode, 'audit');
  assert.strictEqual(cfg.profile, 'home-lab');
  assert.strictEqual(cfg.network.blockRFC1918, false);
  assert.strictEqual(cfg.process.allowSpawn, true);
  assert.strictEqual(cfg.process.denyShells, false);
  assert.strictEqual(cfg.taint.quarantineThreshold, 999);
});

test('resolveConfig applies corp-dev profile', () => {
  const cfg = mod.resolveConfig({ profile: 'corp-dev' });
  assert.strictEqual(cfg.mode, 'enforce');
  assert.strictEqual(cfg.network.blockRFC1918, true);
  assert.deepStrictEqual(cfg.process.allowedBinaries, ['git', 'node', 'npx', 'python']);
});

test('resolveConfig applies research profile', () => {
  const cfg = mod.resolveConfig({ profile: 'research' });
  assert.strictEqual(cfg.mode, 'enforce');
  assert.deepStrictEqual(cfg.network.allowedHosts, ['*']);
  assert.strictEqual(cfg.process.allowSpawn, true);
});

test('resolveConfig merges user overrides over profile', () => {
  const cfg = mod.resolveConfig({
    profile: 'prod',
    taint: { quarantineThreshold: 20 },
  });
  assert.strictEqual(cfg.taint.quarantineThreshold, 20);
  // Rest of prod defaults should still be there
  assert.strictEqual(cfg.mode, 'enforce');
});

// ═══════════════════════════════════════════════════════════════════
// 3. Policy Validation
// ═══════════════════════════════════════════════════════════════════

console.log('\n3. Policy Validation');
console.log('────────────────────');

test('validateConfig accepts valid config', () => {
  const result = mod.validateConfig({ mode: 'enforce', profile: 'prod' });
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.errors.length, 0);
});

test('validateConfig rejects invalid mode', () => {
  const result = mod.validateConfig({ mode: 'invalid' });
  assert.strictEqual(result.valid, false);
  assert.ok(result.errors.length > 0);
  assert.ok(result.errors[0].field === 'mode');
});

test('validateConfig rejects invalid profile', () => {
  const result = mod.validateConfig({ profile: 'staging' });
  assert.strictEqual(result.valid, false);
  assert.ok(result.errors.some(e => e.field === 'profile'));
});

test('validateConfig warns on permissive settings', () => {
  const result = mod.validateConfig({
    process: { allowSpawn: true, denyShells: false },
  });
  assert.strictEqual(result.valid, true); // warning, not error
  assert.ok(result.warnings.length > 0);
});

test('validateConfig rejects negative thresholds', () => {
  const result = mod.validateConfig({
    taint: { quarantineThreshold: -1 },
  });
  assert.strictEqual(result.valid, false);
});

// ═══════════════════════════════════════════════════════════════════
// 4. Native Binding
// ═══════════════════════════════════════════════════════════════════

console.log('\n4. Native Binding');
console.log('─────────────────');

test('loadBindingSync returns pure-TS fallback', () => {
  const binding = mod.loadBindingSync();
  assert.ok(binding, 'binding should load');
  assert.strictEqual(binding.bindingType, 'pure-ts', 'should fall back to pure-ts in test env');
});

test('pure-TS binding classifyIp works', () => {
  const binding = mod.loadBindingSync();
  assert.strictEqual(binding.classifyIp('10.0.0.1'), 1);      // rfc1918
  assert.strictEqual(binding.classifyIp('127.0.0.1'), 2);     // localhost
  assert.strictEqual(binding.classifyIp('169.254.169.254'), 4); // metadata
  assert.strictEqual(binding.classifyIp('8.8.8.8'), 0);        // public
  assert.strictEqual(binding.classifyIp('example.com'), 255);   // not-IP
});

test('pure-TS binding decideNetConnect blocks RFC1918', () => {
  const binding = mod.loadBindingSync();
  const flags = mod.buildPolicyFlags({
    blockRFC1918: true,
    blockLocalhost: true,
    blockLinkLocal: true,
    blockMetadata: true,
  });
  const d = binding.decideNetConnect('10.0.0.1', 443, mod.TaintState.CLEAN, flags);
  assert.strictEqual(d.allow, false);
  assert.strictEqual(d.reasonCode, 1001); // NET_RFC1918_BLOCKED
});

test('pure-TS binding decideNetConnect allows public IP', () => {
  const binding = mod.loadBindingSync();
  const flags = mod.buildPolicyFlags({
    blockRFC1918: true,
    blockLocalhost: true,
    blockLinkLocal: true,
    blockMetadata: true,
  });
  const d = binding.decideNetConnect('8.8.8.8', 443, mod.TaintState.CLEAN, flags);
  assert.strictEqual(d.allow, true);
});

test('pure-TS binding decideNetConnect blocks metadata', () => {
  const binding = mod.loadBindingSync();
  const flags = mod.buildPolicyFlags({
    blockRFC1918: false,
    blockLocalhost: false,
    blockLinkLocal: false,
    blockMetadata: true,
  });
  const d = binding.decideNetConnect('169.254.169.254', 80, mod.TaintState.CLEAN, flags);
  assert.strictEqual(d.allow, false);
  assert.strictEqual(d.reasonCode, 1004); // NET_METADATA_BLOCKED
});

test('pure-TS binding decideSpawn blocks when quarantined', () => {
  const binding = mod.loadBindingSync();
  const d = binding.decideSpawn('git', mod.TaintState.QUARANTINED, true, true);
  assert.strictEqual(d.allow, false);
  assert.strictEqual(d.reasonCode, 1302); // QUARANTINED
});

test('pure-TS binding decideSpawn blocks shells', () => {
  const binding = mod.loadBindingSync();
  const d = binding.decideSpawn('bash', mod.TaintState.CLEAN, true, true);
  assert.strictEqual(d.allow, false);
  assert.strictEqual(d.reasonCode, 1102); // PROC_SHELL_DENIED
});

test('pure-TS binding decideSpawn allows allowlisted binary', () => {
  const binding = mod.loadBindingSync();
  const d = binding.decideSpawn('git', mod.TaintState.CLEAN, true, true);
  assert.strictEqual(d.allow, true);
});

test('pure-TS binding version returns string', () => {
  const binding = mod.loadBindingSync();
  const v = binding.version();
  assert.strictEqual(typeof v, 'string');
  assert.ok(v.includes('.'), 'version should contain dots');
});

// ═══════════════════════════════════════════════════════════════════
// 5. State Manager
// ═══════════════════════════════════════════════════════════════════

console.log('\n5. State Manager');
console.log('────────────────');

test('StateManager tracks taint state', () => {
  const sm = new mod.StateManager({ windowSeconds: 60, quarantineThreshold: 3, coolDownSeconds: 300 });
  assert.strictEqual(sm.getTaintState('s1'), mod.TaintState.CLEAN);

  // Record block decisions to escalate
  sm.recordDecision('s1', { allow: false, reasonCode: 1001, risk: 1, taintUpdate: mod.TaintState.TAINTED }, 'net_connect', {});
  assert.strictEqual(sm.getTaintState('s1'), mod.TaintState.TAINTED);
});

test('StateManager quarantine and unquarantine', () => {
  const sm = new mod.StateManager({ windowSeconds: 60, quarantineThreshold: 3, coolDownSeconds: 300 });
  sm.quarantineSession('s1');
  assert.strictEqual(sm.getTaintState('s1'), mod.TaintState.QUARANTINED);

  sm.unquarantineSession('s1', 'operator');
  assert.strictEqual(sm.getTaintState('s1'), mod.TaintState.CLEAN);
});

test('StateManager session status', () => {
  const sm = new mod.StateManager({ windowSeconds: 60, quarantineThreshold: 3, coolDownSeconds: 300 });
  const status = sm.getSessionStatus('s1');
  assert.ok(status, 'status should be returned');
  assert.strictEqual(status.taintState, 'CLEAN');
  assert.strictEqual(status.blockCount, 0);
});

test('StateManager exportAudit returns JSONL', () => {
  const sm = new mod.StateManager({ windowSeconds: 60, quarantineThreshold: 3, coolDownSeconds: 300 });
  sm.recordDecision('s1', { allow: false, reasonCode: 1001, risk: 1, taintUpdate: null }, 'net_connect', { host: '10.0.0.1' });
  const audit = sm.exportAudit();
  assert.strictEqual(typeof audit, 'string');
  assert.ok(audit.length > 0, 'audit should have content');
  // Each line should be valid JSON
  const lines = audit.trim().split('\n');
  assert.ok(lines.length >= 1);
  const entry = JSON.parse(lines[0]);
  assert.strictEqual(entry.action, 'net_connect');
});

// ═══════════════════════════════════════════════════════════════════
// 6. OpenClaw register() Simulation
// ═══════════════════════════════════════════════════════════════════

console.log('\n6. OpenClaw register() Simulation');
console.log('──────────────────────────────────');

test('register() accepts mock OpenClaw API', () => {
  // First, ensure we start clean
  mod.shutdown();

  const registeredTools = {};
  const mockApi = {
    getConfig: () => ({ profile: 'home-lab', sessionId: 'test-session-1' }),
    registerHook: (_hook, _handler) => {},
    registerTool: (name, handler) => {
      registeredTools[name] = handler;
    },
  };

  // Should not throw
  mod.default(mockApi);
  assert.ok(registeredTools['oc_shield'], 'oc_shield tool should be registered');
});

test('oc_shield tool: status command', () => {
  const registeredTools = {};
  // Re-register to capture the tool handler
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({ profile: 'corp-dev', sessionId: 'test-session-2' }),
    registerTool: (name, handler) => { registeredTools[name] = handler; },
  };
  mod.default(mockApi);

  const result = registeredTools['oc_shield']({ action: 'status', sessionId: 'test-session-2' });
  assert.ok(result, 'status should return a result');
  assert.strictEqual(result.profile, 'corp-dev');
  assert.strictEqual(result.binding, 'pure-ts');
});

test('oc_shield tool: quarantine command', () => {
  const registeredTools = {};
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({ profile: 'prod', sessionId: 'test-session-3' }),
    registerTool: (name, handler) => { registeredTools[name] = handler; },
  };
  mod.default(mockApi);

  const result = registeredTools['oc_shield']({ action: 'quarantine', sessionId: 'test-session-3' });
  assert.ok(result.success);

  // Verify quarantine via status
  const status = registeredTools['oc_shield']({ action: 'status', sessionId: 'test-session-3' });
  assert.strictEqual(status.session.taintState, 'QUARANTINED');
});

test('oc_shield tool: unquarantine command', () => {
  const registeredTools = {};
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({ profile: 'prod', sessionId: 'test-session-4' }),
    registerTool: (name, handler) => { registeredTools[name] = handler; },
  };
  mod.default(mockApi);

  // Quarantine first
  registeredTools['oc_shield']({ action: 'quarantine', sessionId: 'test-session-4' });
  // Then unquarantine
  const result = registeredTools['oc_shield']({ action: 'unquarantine', sessionId: 'test-session-4', reason: 'test' });
  assert.ok(result.success);
});

test('oc_shield tool: export-audit command', () => {
  const registeredTools = {};
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({ profile: 'prod' }),
    registerTool: (name, handler) => { registeredTools[name] = handler; },
  };
  mod.default(mockApi);

  const result = registeredTools['oc_shield']({ action: 'export-audit' });
  assert.ok(result.audit !== undefined, 'audit field should exist');
  assert.strictEqual(typeof result.audit, 'string');
});

test('oc_shield tool: set-profile command', () => {
  const registeredTools = {};
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({ profile: 'prod' }),
    registerTool: (name, handler) => { registeredTools[name] = handler; },
  };
  mod.default(mockApi);

  const result = registeredTools['oc_shield']({ action: 'set-profile', profile: 'research' });
  assert.ok(result.success);
});

test('oc_shield tool: unknown action returns error', () => {
  const registeredTools = {};
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({}),
    registerTool: (name, handler) => { registeredTools[name] = handler; },
  };
  mod.default(mockApi);

  const result = registeredTools['oc_shield']({ action: 'invalid-action' });
  assert.ok(result.error, 'should return error for unknown action');
});

test('register() works without registerTool', () => {
  mod.shutdown();
  const mockApi = {
    getConfig: () => ({}),
    // No registerTool — should not throw
  };
  mod.default(mockApi);
  // Just verify no crash
  assert.ok(true);
});

// ═══════════════════════════════════════════════════════════════════
// 7. Lifecycle: Init / Shutdown Idempotency
// ═══════════════════════════════════════════════════════════════════

console.log('\n7. Lifecycle');
console.log('────────────');

test('init is idempotent', () => {
  mod.shutdown();
  mod.init({ profile: 'home-lab' });
  mod.init({ profile: 'prod' }); // Should be a no-op (already initialized)
  const status = mod.shieldStatus();
  // Should still be home-lab since second init was skipped
  assert.strictEqual(status.profile, 'home-lab');
});

test('shutdown then reinit works', () => {
  mod.shutdown();
  mod.init({ profile: 'research' });
  const status = mod.shieldStatus();
  assert.strictEqual(status.profile, 'research');
  mod.shutdown();
});

test('status returns error when not initialized', () => {
  mod.shutdown();
  const status = mod.shieldStatus();
  assert.ok(status.error, 'should return error when not initialized');
});

// ═══════════════════════════════════════════════════════════════════
// 8. buildPolicyFlags
// ═══════════════════════════════════════════════════════════════════

console.log('\n8. Policy Flags');
console.log('───────────────');

test('buildPolicyFlags encodes correctly', () => {
  const allBlocked = mod.buildPolicyFlags({
    blockRFC1918: true,
    blockLocalhost: true,
    blockLinkLocal: true,
    blockMetadata: true,
  });
  assert.strictEqual(allBlocked, 0b1111); // 15

  const noneBlocked = mod.buildPolicyFlags({
    blockRFC1918: false,
    blockLocalhost: false,
    blockLinkLocal: false,
    blockMetadata: false,
  });
  assert.strictEqual(noneBlocked, 0);

  const onlyMeta = mod.buildPolicyFlags({
    blockRFC1918: false,
    blockLocalhost: false,
    blockLinkLocal: false,
    blockMetadata: true,
  });
  assert.strictEqual(onlyMeta, 0b1000); // 8
});

// ═══════════════════════════════════════════════════════════════════
// Cleanup and Summary
// ═══════════════════════════════════════════════════════════════════

mod.shutdown();

console.log('\n═══════════════════════════════════════');
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('═══════════════════════════════════════');

if (failed > 0) {
  console.log('\nFailed tests:');
  for (const { name, err } of errors) {
    console.log(`  \u2717 ${name}`);
    console.log(`    ${err.message}`);
  }
  process.exit(1);
} else {
  console.log('\nAll jiti integration tests passed!\n');
  process.exit(0);
}
