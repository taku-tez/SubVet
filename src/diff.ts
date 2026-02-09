/**
 * SubVet - Diff Module
 * Compare scan results for CI/CD pipelines
 */

import type { ScanOutput, ScanResult, TakeoverStatus } from './types.js';

export interface DiffEntry {
  subdomain: string;
  type: 'new' | 'resolved' | 'changed';
  currentStatus?: TakeoverStatus;
  previousStatus?: TakeoverStatus;
  service?: string | null;
  evidence?: string[];
  risk?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface DiffSummary {
  newVulnerable: number;
  newLikely: number;
  newPotential: number;
  resolved: number;
  unchanged: number;
  statusChanged: number;
  addedSafe: number;
  removedSafe: number;
}

export interface DiffResult {
  version: string;
  timestamp: string;
  baseline: {
    timestamp: string;
    total: number;
  };
  current: {
    timestamp: string;
    total: number;
  };
  summary: DiffSummary;
  entries: DiffEntry[];
}

const RISK_STATUSES: TakeoverStatus[] = ['vulnerable', 'likely', 'potential'];

/**
 * Compare two scan outputs and return the differences
 */
export function compareScans(baseline: ScanOutput, current: ScanOutput): DiffResult {
  const baselineMap = new Map<string, ScanResult>();
  const currentMap = new Map<string, ScanResult>();

  // Build maps for O(1) lookup
  for (const result of baseline.results) {
    baselineMap.set(result.subdomain, result);
  }
  for (const result of current.results) {
    currentMap.set(result.subdomain, result);
  }

  const entries: DiffEntry[] = [];
  const summary: DiffSummary = {
    newVulnerable: 0,
    newLikely: 0,
    newPotential: 0,
    resolved: 0,
    unchanged: 0,
    statusChanged: 0,
    addedSafe: 0,
    removedSafe: 0,
  };

  // Check current results against baseline
  for (const [subdomain, currentResult] of currentMap) {
    const baselineResult = baselineMap.get(subdomain);

    if (!baselineResult) {
      // New entry in current scan
      if (RISK_STATUSES.includes(currentResult.status)) {
        entries.push({
          subdomain,
          type: 'new',
          currentStatus: currentResult.status,
          service: currentResult.service,
          evidence: currentResult.evidence,
          risk: currentResult.risk,
        });

        if (currentResult.status === 'vulnerable') summary.newVulnerable++;
        else if (currentResult.status === 'likely') summary.newLikely++;
        else if (currentResult.status === 'potential') summary.newPotential++;
      } else {
        summary.addedSafe++;
      }
    } else if (currentResult.status !== baselineResult.status) {
      // Status changed
      const wasRisky = RISK_STATUSES.includes(baselineResult.status);
      const isRisky = RISK_STATUSES.includes(currentResult.status);

      if (wasRisky && !isRisky) {
        // Resolved
        entries.push({
          subdomain,
          type: 'resolved',
          currentStatus: currentResult.status,
          previousStatus: baselineResult.status,
          service: baselineResult.service,
        });
        summary.resolved++;
      } else if (!wasRisky && isRisky) {
        // Became risky (treat as new)
        entries.push({
          subdomain,
          type: 'new',
          currentStatus: currentResult.status,
          service: currentResult.service,
          evidence: currentResult.evidence,
          risk: currentResult.risk,
        });
        if (currentResult.status === 'vulnerable') summary.newVulnerable++;
        else if (currentResult.status === 'likely') summary.newLikely++;
        else if (currentResult.status === 'potential') summary.newPotential++;
      } else {
        // Status changed but both are risky or both are safe
        entries.push({
          subdomain,
          type: 'changed',
          currentStatus: currentResult.status,
          previousStatus: baselineResult.status,
          service: currentResult.service,
          evidence: currentResult.evidence,
          risk: currentResult.risk,
        });
        summary.statusChanged++;
      }
    } else {
      // Unchanged
      summary.unchanged++;
    }
  }

  // Check for entries that were in baseline but not in current
  for (const [subdomain, baselineResult] of baselineMap) {
    if (!currentMap.has(subdomain)) {
      // Was in baseline, not in current (might be resolved or subdomain removed)
      if (RISK_STATUSES.includes(baselineResult.status)) {
        entries.push({
          subdomain,
          type: 'resolved',
          previousStatus: baselineResult.status,
          service: baselineResult.service,
        });
        summary.resolved++;
      } else {
        summary.removedSafe++;
      }
    }
  }

  // Sort entries by severity (vulnerable > likely > potential > resolved > changed)
  const statusOrder: Record<string, number> = {
    vulnerable: 0,
    likely: 1,
    potential: 2,
  };

  entries.sort((a, b) => {
    // New items first, then resolved, then changed
    const typeOrder: Record<string, number> = { new: 0, resolved: 1, changed: 2 };
    if (a.type !== b.type) {
      return typeOrder[a.type] - typeOrder[b.type];
    }

    // Within new items, sort by severity
    if (a.type === 'new' && b.type === 'new') {
      const aOrder = statusOrder[a.currentStatus ?? 'potential'] ?? 3;
      const bOrder = statusOrder[b.currentStatus ?? 'potential'] ?? 3;
      return aOrder - bOrder;
    }

    return a.subdomain.localeCompare(b.subdomain);
  });

  return {
    version: current.version,
    timestamp: new Date().toISOString(),
    baseline: {
      timestamp: baseline.timestamp,
      total: baseline.summary.total,
    },
    current: {
      timestamp: current.timestamp,
      total: current.summary.total,
    },
    summary,
    entries,
  };
}

/**
 * Format diff result as human-readable text
 */
export function formatDiffText(diff: DiffResult): string {
  const lines: string[] = [];
  
  lines.push('═══════════════════════════════════════════════════════');
  lines.push('                  SubVet Diff Report                    ');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push('');
  lines.push(`Baseline: ${diff.baseline.timestamp} (${diff.baseline.total} targets)`);
  lines.push(`Current:  ${diff.current.timestamp} (${diff.current.total} targets)`);
  lines.push('');

  // Summary
  lines.push('─── Summary ───────────────────────────────────────────');
  
  const hasNewIssues = diff.summary.newVulnerable > 0 || 
                       diff.summary.newLikely > 0 || 
                       diff.summary.newPotential > 0;

  if (hasNewIssues) {
    lines.push(`🔴 New vulnerable:  ${diff.summary.newVulnerable}`);
    lines.push(`🟠 New likely:      ${diff.summary.newLikely}`);
    lines.push(`🟡 New potential:   ${diff.summary.newPotential}`);
  }
  
  if (diff.summary.resolved > 0) {
    lines.push(`✅ Resolved:        ${diff.summary.resolved}`);
  }
  
  if (diff.summary.statusChanged > 0) {
    lines.push(`🔄 Status changed:  ${diff.summary.statusChanged}`);
  }

  if (diff.summary.addedSafe > 0) {
    lines.push(`➕ Added (safe):    ${diff.summary.addedSafe}`);
  }

  if (diff.summary.removedSafe > 0) {
    lines.push(`➖ Removed (safe):  ${diff.summary.removedSafe}`);
  }
  
  lines.push(`   Unchanged:       ${diff.summary.unchanged}`);
  lines.push('');

  // Entries
  if (diff.entries.length > 0) {
    lines.push('─── Details ───────────────────────────────────────────');
    
    for (const entry of diff.entries) {
      if (entry.type === 'new') {
        const emoji = entry.currentStatus === 'vulnerable' ? '🔴' :
                      entry.currentStatus === 'likely' ? '🟠' : '🟡';
        lines.push(`${emoji} NEW: ${entry.subdomain}`);
        lines.push(`      Status: ${entry.currentStatus?.toUpperCase()}`);
        if (entry.service) {
          lines.push(`      Service: ${entry.service}`);
        }
        if (entry.evidence && entry.evidence.length > 0) {
          lines.push(`      Evidence: ${entry.evidence[0]}`);
        }
        lines.push('');
      } else if (entry.type === 'resolved') {
        lines.push(`✅ RESOLVED: ${entry.subdomain}`);
        lines.push(`      Was: ${entry.previousStatus?.toUpperCase()}`);
        if (entry.service) {
          lines.push(`      Service: ${entry.service}`);
        }
        lines.push('');
      } else if (entry.type === 'changed') {
        lines.push(`🔄 CHANGED: ${entry.subdomain}`);
        lines.push(`      ${entry.previousStatus?.toUpperCase()} → ${entry.currentStatus?.toUpperCase()}`);
        lines.push('');
      }
    }
  } else {
    lines.push('─── No Changes ────────────────────────────────────────');
    lines.push('No new vulnerabilities or status changes detected.');
    lines.push('');
  }

  lines.push('═══════════════════════════════════════════════════════');

  return lines.join('\n');
}

/**
 * Determine exit code based on diff result
 * 0: No new vulnerabilities
 * 1: New likely vulnerabilities
 * 2: New vulnerable (confirmed) findings
 */
export function getDiffExitCode(diff: DiffResult): number {
  if (diff.summary.newVulnerable > 0) return 2;
  if (diff.summary.newLikely > 0) return 1;
  return 0;
}
