#!/usr/bin/env npx tsx
/**
 * Convert existing TypeScript fingerprints to YAML format
 * Usage: npx tsx scripts/convert-fingerprints.ts
 */

import * as yaml from 'js-yaml';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { cloudFingerprints } from '../src/fingerprints/cloud.js';
import { hostingFingerprints } from '../src/fingerprints/hosting.js';
import { websiteBuilderFingerprints } from '../src/fingerprints/website-builders.js';
import { ecommerceFingerprints } from '../src/fingerprints/ecommerce.js';
import { supportFingerprints } from '../src/fingerprints/support.js';
import { marketingFingerprints } from '../src/fingerprints/marketing.js';
import { devtoolsFingerprints } from '../src/fingerprints/devtools.js';
import { miscFingerprints } from '../src/fingerprints/misc.js';
import type { ServiceFingerprint, FingerprintRule, NegativePattern } from '../src/types.js';

const outDir = join(import.meta.dirname, '..', 'signatures');
mkdirSync(outDir, { recursive: true });

function ruleToYaml(rule: FingerprintRule): Record<string, unknown> {
  const out: Record<string, unknown> = { type: rule.type };
  if (rule.pattern !== undefined) {
    out.pattern = rule.pattern instanceof RegExp ? rule.pattern.source : rule.pattern;
  }
  if (rule.value !== undefined) out.value = rule.value;
  if (rule.header) out.header = rule.header;
  if (rule.required) out.required = true;
  if (rule.weight !== undefined) out.weight = rule.weight;
  return out;
}

function negToYaml(neg: NegativePattern): Record<string, unknown> {
  const out: Record<string, unknown> = { type: neg.type };
  if (neg.pattern !== undefined) {
    out.pattern = neg.pattern instanceof RegExp ? neg.pattern.source : neg.pattern;
  }
  if (neg.value !== undefined) out.value = neg.value;
  if (neg.header) out.header = neg.header;
  out.description = neg.description;
  return out;
}

function convertCategory(fps: ServiceFingerprint[]): Record<string, unknown>[] {
  return fps.map(fp => {
    const entry: Record<string, unknown> = {
      service: fp.service,
      description: fp.description,
      cnames: fp.cnames,
      fingerprints: fp.fingerprints.map(ruleToYaml),
    };
    if (fp.negativePatterns?.length) {
      entry.negativePatterns = fp.negativePatterns.map(negToYaml);
    }
    entry.takeoverPossible = fp.takeoverPossible;
    if (fp.minConfidence !== undefined) entry.minConfidence = fp.minConfidence;
    if (fp.documentation) entry.documentation = fp.documentation;
    if (fp.poc) entry.poc = fp.poc;
    return entry;
  });
}

const categories: Record<string, ServiceFingerprint[]> = {
  cloud: cloudFingerprints,
  hosting: hostingFingerprints,
  'website-builders': websiteBuilderFingerprints,
  ecommerce: ecommerceFingerprints,
  support: supportFingerprints,
  marketing: marketingFingerprints,
  devtools: devtoolsFingerprints,
  misc: miscFingerprints,
};

let total = 0;
for (const [name, fps] of Object.entries(categories)) {
  const data = convertCategory(fps);
  const content = yaml.dump(data, { lineWidth: 120, noRefs: true, quotingType: '"' });
  const outPath = join(outDir, `${name}.yaml`);
  writeFileSync(outPath, content);
  console.log(`  ${name}.yaml: ${fps.length} services`);
  total += fps.length;
}
console.log(`\nTotal: ${total} services written to ${outDir}`);
