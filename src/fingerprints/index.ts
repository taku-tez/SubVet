/**
 * SubVet - Fingerprint Database
 * Organized by service category for maintainability
 * 
 * Based on: https://github.com/EdOverflow/can-i-take-over-xyz
 */

import type { ServiceFingerprint } from '../types.js';

// Import fingerprints by category
import { cloudFingerprints } from './cloud.js';
import { hostingFingerprints } from './hosting.js';
import { websiteBuilderFingerprints } from './website-builders.js';
import { ecommerceFingerprints } from './ecommerce.js';
import { supportFingerprints } from './support.js';
import { marketingFingerprints } from './marketing.js';
import { devtoolsFingerprints } from './devtools.js';
import { miscFingerprints } from './misc.js';

/**
 * All fingerprints combined
 */
export const fingerprints: ServiceFingerprint[] = [
  ...cloudFingerprints,
  ...hostingFingerprints,
  ...websiteBuilderFingerprints,
  ...ecommerceFingerprints,
  ...supportFingerprints,
  ...marketingFingerprints,
  ...devtoolsFingerprints,
  ...miscFingerprints
];

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
 * Find matching fingerprint for a CNAME
 */
export function findServiceByCname(cname: string): ServiceFingerprint | null {
  const lowerCname = cname.toLowerCase();
  
  for (const fp of fingerprints) {
    for (const pattern of fp.cnames) {
      const regex = globToRegex(pattern);
      
      if (regex.test(lowerCname)) {
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
  return fingerprints;
}

/**
 * Get fingerprint by service name
 */
export function getServiceByName(name: string): ServiceFingerprint | null {
  return fingerprints.find(fp => 
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
