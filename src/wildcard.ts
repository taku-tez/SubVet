/**
 * SubVet - Wildcard DNS Adjustment
 * Logic for adjusting scan results when wildcard DNS is detected.
 */

import type { ScanResult } from './types.js';
import type { WildcardResult } from './dns.js';
import { WILDCARD_CONFIDENCE_PENALTY } from './constants.js';

/**
 * Check if a scan result has DNS-based dangling vulnerabilities
 * that should not be downgraded by wildcard heuristics.
 */
export function hasDnsDanglingVulnerability(result: ScanResult): boolean {
  return !!(
    (result.dns.nsDangling && result.dns.nsDangling.length > 0) ||
    (result.dns.mxDangling && result.dns.mxDangling.length > 0) ||
    (result.dns.spfDangling && result.dns.spfDangling.length > 0) ||
    (result.dns.srvDangling && result.dns.srvDangling.length > 0)
  );
}

/**
 * Apply wildcard DNS adjustments to a scan result.
 * Modifies the result in place.
 */
export function applyWildcardAdjustment(result: ScanResult, wildcardInfo: WildcardResult): void {
  if (!wildcardInfo.isWildcard) return;

  result.evidence.push('Wildcard DNS detected');

  if (hasDnsDanglingVulnerability(result)) {
    result.evidence.push('Wildcard adjustment skipped — DNS dangling vulnerability confirmed');
    return;
  }

  // If subdomain resolves to the same IP as wildcard and has no CNAME, it's likely just wildcard
  const aRecords = result.dns.records.filter(r => r.type === 'A').map(r => r.value);
  const aaaaRecords = result.dns.records.filter(r => r.type === 'AAAA').map(r => r.value);
  const allIpRecords = [...aRecords, ...aaaaRecords];
  const hasCname = result.dns.records.some(r => r.type === 'CNAME');

  const wildcardIps = wildcardInfo.wildcardIps ?? (wildcardInfo.wildcardIp ? [wildcardInfo.wildcardIp] : []);
  const matchCount = allIpRecords.filter(ip => wildcardIps.includes(ip)).length;
  const allMatch = allIpRecords.length > 0 && matchCount === allIpRecords.length;
  const partialMatch = matchCount > 0 && matchCount < allIpRecords.length;

  if (allMatch && !hasCname) {
    // All IPs match wildcard set, no CNAME → almost certainly just wildcard response
    result.status = 'not_vulnerable';
    result.risk = 'info';
    result.evidence.push(`All IPs match wildcard set [${wildcardIps.join(', ')}] — safe`);
  } else if (partialMatch && !hasCname) {
    // Partial IP match — reduce confidence but keep status
    result.evidence.push(`Partial wildcard IP match (${matchCount}/${allIpRecords.length}) — confidence reduced`);
    // Adjust confidence evidence string if present
    const confIdx = result.evidence.findIndex(e => e.startsWith('Confidence:'));
    if (confIdx >= 0) {
      const confMatch = result.evidence[confIdx].match(/Confidence: (\d+)\/10/);
      if (confMatch) {
        const reduced = Math.max(0, parseInt(confMatch[1], 10) - WILDCARD_CONFIDENCE_PENALTY);
        result.evidence[confIdx] = `Confidence: ${reduced}/10`;
      }
    }
  } else if (!hasCname && allIpRecords.length > 0) {
    // Has A record but no CNAME in wildcard domain → reduce confidence
    result.evidence.push('No CNAME in wildcard domain — confidence reduced');
    if (result.risk === 'critical') {
      result.risk = 'high';
      result.status = 'likely';
    } else if (result.risk === 'high') {
      result.risk = 'medium';
      result.status = 'potential';
    } else if (result.risk === 'medium') {
      result.risk = 'low';
    }
  }
}
