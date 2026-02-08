/**
 * YAML Signature Loader
 * Loads fingerprint signatures from YAML files and merges with built-in TS fingerprints.
 */

import * as yaml from 'js-yaml';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ServiceFingerprint, FingerprintRule, NegativePattern, FingerprintMatchType } from './types.js';

// Raw YAML types (before conversion)
interface YamlFingerprintRule {
  type: string;
  pattern?: string;
  value?: number | string;
  header?: string;
  required?: boolean;
  weight?: number;
}

interface YamlNegativePattern {
  type: string;
  pattern?: string;
  value?: number | string;
  header?: string;
  description: string;
}

interface YamlSignature {
  service: string;
  description: string;
  cnames: string[];
  fingerprints: YamlFingerprintRule[];
  negativePatterns?: YamlNegativePattern[];
  takeoverPossible: boolean;
  minConfidence?: number;
  documentation?: string;
  poc?: string;
}

const VALID_MATCH_TYPES: Set<string> = new Set([
  'http_body', 'http_status', 'http_header',
  'dns_nxdomain', 'dns_cname',
  'ns_nxdomain', 'mx_nxdomain', 'spf_include_nxdomain',
  'srv_nxdomain', 'txt_ref_nxdomain'
]);

function convertRule(raw: YamlFingerprintRule): FingerprintRule {
  if (!VALID_MATCH_TYPES.has(raw.type)) {
    throw new Error(`Invalid fingerprint type: ${raw.type}`);
  }
  const rule: FingerprintRule = { type: raw.type as FingerprintMatchType };
  if (raw.pattern !== undefined) rule.pattern = raw.pattern;
  if (raw.value !== undefined) rule.value = raw.value;
  if (raw.header) rule.header = raw.header;
  if (raw.required) rule.required = true;
  if (raw.weight !== undefined) rule.weight = raw.weight;
  return rule;
}

function convertNegative(raw: YamlNegativePattern): NegativePattern {
  return {
    type: raw.type as 'http_body' | 'http_header' | 'http_status',
    pattern: raw.pattern,
    value: raw.value,
    header: raw.header,
    description: raw.description,
  };
}

function convertSignature(raw: YamlSignature): ServiceFingerprint {
  const fp: ServiceFingerprint = {
    service: raw.service,
    description: raw.description,
    cnames: raw.cnames,
    fingerprints: raw.fingerprints.map(convertRule),
    takeoverPossible: raw.takeoverPossible,
  };
  if (raw.negativePatterns?.length) {
    fp.negativePatterns = raw.negativePatterns.map(convertNegative);
  }
  if (raw.minConfidence !== undefined) fp.minConfidence = raw.minConfidence;
  if (raw.documentation) fp.documentation = raw.documentation;
  if (raw.poc) fp.poc = raw.poc;
  return fp;
}

/**
 * Load signatures from a directory of YAML files.
 * Returns empty array if directory doesn't exist.
 */
export function loadSignaturesFromDir(dir: string): ServiceFingerprint[] {
  const resolved = resolve(dir);
  if (!existsSync(resolved)) return [];

  const results: ServiceFingerprint[] = [];
  const files = readdirSync(resolved).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));

  for (const file of files) {
    const content = readFileSync(join(resolved, file), 'utf-8');
    const raw = yaml.load(content) as YamlSignature[];
    if (!Array.isArray(raw)) continue;
    for (const entry of raw) {
      results.push(convertSignature(entry));
    }
  }

  return results;
}

/**
 * Get the built-in signatures directory path
 */
export function getBuiltinSignaturesDir(): string {
  // Works for both ESM (dist/) and development
  const thisFile = fileURLToPath(import.meta.url);
  // From dist/signatures.js or src/signatures.ts -> project root/signatures/
  const projectRoot = join(thisFile, '..', '..');
  return join(projectRoot, 'signatures');
}

/**
 * Load all signatures: built-in YAML + optional custom directory.
 * YAML signatures take priority; TS fingerprints are used as fallback.
 */
export function loadSignatures(customDir?: string): ServiceFingerprint[] {
  const builtinDir = getBuiltinSignaturesDir();
  const yamlSigs = loadSignaturesFromDir(builtinDir);

  // If custom dir provided, load and merge
  let customSigs: ServiceFingerprint[] = [];
  if (customDir) {
    customSigs = loadSignaturesFromDir(customDir);
  }

  // Build service name set from YAML + custom
  const seen = new Set<string>();
  const merged: ServiceFingerprint[] = [];

  // Custom signatures first (highest priority)
  for (const sig of customSigs) {
    seen.add(sig.service.toLowerCase());
    merged.push(sig);
  }

  // Built-in YAML signatures
  for (const sig of yamlSigs) {
    const key = sig.service.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(sig);
    }
  }

  // Fallback: TS fingerprints for any not covered by YAML
  // Lazy import to avoid circular deps
  try {
    // Dynamic import not needed since we import statically in the caller
    // This is handled by the caller (fingerprints/index.ts)
  } catch {
    // ignore
  }

  return merged;
}
