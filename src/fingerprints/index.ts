/**
 * SubVet - Fingerprint Database
 * Organized by service category for maintainability
 * 
 * Based on: https://github.com/EdOverflow/can-i-take-over-xyz
 * 
 * Priority: Custom YAML > Built-in YAML > TypeScript hardcoded
 */

import type { ServiceFingerprint } from '../types.js';
import { loadSignatures } from '../signatures.js';

// Import fingerprints by category (fallback)
import { cloudFingerprints } from './cloud.js';
import { hostingFingerprints } from './hosting.js';
import { websiteBuilderFingerprints } from './website-builders.js';
import { ecommerceFingerprints } from './ecommerce.js';
import { supportFingerprints } from './support.js';
import { marketingFingerprints } from './marketing.js';
import { devtoolsFingerprints } from './devtools.js';
import { miscFingerprints } from './misc.js';

/**
 * All TS-hardcoded fingerprints (fallback)
 */
const tsFingerprints: ServiceFingerprint[] = [
  ...cloudFingerprints,
  ...hostingFingerprints,
  ...websiteBuilderFingerprints,
  ...ecommerceFingerprints,
  ...supportFingerprints,
  ...marketingFingerprints,
  ...devtoolsFingerprints,
  ...miscFingerprints
];

// Active fingerprints (initialized lazily)
let _fingerprints: ServiceFingerprint[] | null = null;
let _customSignaturesDir: string | undefined;

/**
 * Set custom signatures directory (call before first access)
 */
export function setCustomSignaturesDir(dir: string | undefined): void {
  _customSignaturesDir = dir;
  _fingerprints = null; // Reset cache
}

/**
 * Build merged fingerprint list: YAML (custom + builtin) + TS fallback
 */
function buildFingerprints(): ServiceFingerprint[] {
  const yamlSigs = loadSignatures(_customSignaturesDir);
  
  if (yamlSigs.length === 0) {
    // No YAML files found, use TS fingerprints as-is
    return [...tsFingerprints];
  }

  // Merge: YAML signatures + TS fallback for any not in YAML
  const seen = new Set(yamlSigs.map(s => s.service.toLowerCase()));
  const fallback = tsFingerprints.filter(fp => !seen.has(fp.service.toLowerCase()));
  
  return [...yamlSigs, ...fallback];
}

/**
 * Get active fingerprints (lazy-loaded with YAML priority)
 */
function getFingerprints(): ServiceFingerprint[] {
  if (!_fingerprints) {
    _fingerprints = buildFingerprints();
  }
  return _fingerprints;
}

// Proxy for backward compat: `fingerprints` export
// We use a getter via Object.defineProperty on module level isn't possible with const,
// so we use a function-based approach. The `fingerprints` const is kept for import compat.
export const fingerprints: ServiceFingerprint[] = new Proxy([] as ServiceFingerprint[], {
  get(_target, prop, receiver) {
    const fps = getFingerprints();
    if (prop === 'length') return fps.length;
    if (prop === Symbol.iterator) return fps[Symbol.iterator].bind(fps);
    if (typeof prop === 'string' && /^\d+$/.test(prop)) return fps[Number(prop)];
    if (typeof prop === 'string' && prop in Array.prototype) {
      const val = (fps as any)[prop];
      return typeof val === 'function' ? val.bind(fps) : val;
    }
    return Reflect.get(fps, prop, receiver);
  },
}) as unknown as ServiceFingerprint[];

/**
 * Convert glob pattern to regex
 * Handles: * (any chars), ? (single char), . (literal dot)
 */
function globToRegex(pattern: string): RegExp {
  // First escape all regex special characters
  let regexPattern = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  // Then convert glob patterns: * -> .*, ? -> .
  regexPattern = regexPattern
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${regexPattern}$`, 'i');
}

/**
 * Normalize CNAME (trim, remove trailing dot, lowercase)
 */
function normalizeCname(cname: string): string {
  let normalized = cname.trim();
  // Remove trailing dot (FQDN format from some DNS resolvers)
  if (normalized.endsWith('.')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized.toLowerCase();
}

/**
 * Find matching fingerprint for a CNAME
 */
export function findServiceByCname(cname: string): ServiceFingerprint | null {
  const normalizedCname = normalizeCname(cname);
  const fps = getFingerprints();
  
  for (const fp of fps) {
    for (const pattern of fp.cnames) {
      const regex = globToRegex(pattern);
      
      if (regex.test(normalizedCname)) {
        return fp;
      }
    }
  }
  
  return null;
}

/**
 * Get all fingerprints
 */
export function getAllFingerprints(): ServiceFingerprint[] {
  return getFingerprints();
}

/**
 * Get fingerprint by service name
 */
export function getServiceByName(name: string): ServiceFingerprint | null {
  return getFingerprints().find(fp => 
    fp.service.toLowerCase() === name.toLowerCase()
  ) || null;
}

/**
 * Get fingerprints by category
 */
export function getFingerprintsByCategory(category: string): ServiceFingerprint[] {
  switch (category.toLowerCase()) {
    case 'cloud':
      return cloudFingerprints;
    case 'hosting':
      return hostingFingerprints;
    case 'website-builders':
    case 'cms':
      return websiteBuilderFingerprints;
    case 'ecommerce':
      return ecommerceFingerprints;
    case 'support':
    case 'helpdesk':
      return supportFingerprints;
    case 'marketing':
      return marketingFingerprints;
    case 'devtools':
    case 'developer':
      return devtoolsFingerprints;
    case 'misc':
      return miscFingerprints;
    default:
      return [];
  }
}

/**
 * List all categories
 */
export function listCategories(): { name: string; count: number }[] {
  return [
    { name: 'cloud', count: cloudFingerprints.length },
    { name: 'hosting', count: hostingFingerprints.length },
    { name: 'website-builders', count: websiteBuilderFingerprints.length },
    { name: 'ecommerce', count: ecommerceFingerprints.length },
    { name: 'support', count: supportFingerprints.length },
    { name: 'marketing', count: marketingFingerprints.length },
    { name: 'devtools', count: devtoolsFingerprints.length },
    { name: 'misc', count: miscFingerprints.length }
  ];
}

// Re-export categories for direct access
export {
  cloudFingerprints,
  hostingFingerprints,
  websiteBuilderFingerprints,
  ecommerceFingerprints,
  supportFingerprints,
  marketingFingerprints,
  devtoolsFingerprints,
  miscFingerprints
};
