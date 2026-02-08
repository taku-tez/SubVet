/**
 * SubVet - Report Generation Module
 */

import type { ScanOutput } from './types.js';

export type ReportFormat = 'html' | 'md' | 'json' | 'sarif';

/** Canonical repository URL — keep in sync with package.json */
export const REPO_URL = 'https://github.com/taku-tez/SubVet';

/**
 * Generate HTML report
 */
export function generateHtmlReport(output: ScanOutput): string {
  const { summary, results } = output;
  
  const vulnerableResults = results.filter(r => r.status === 'vulnerable');
  const likelyResults = results.filter(r => r.status === 'likely');
  const potentialResults = results.filter(r => r.status === 'potential');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SubVet Scan Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; }
    .summary { display: flex; gap: 20px; margin: 20px 0; }
    .stat { padding: 20px; border-radius: 8px; text-align: center; min-width: 120px; }
    .stat-value { font-size: 36px; font-weight: bold; }
    .stat-label { font-size: 14px; color: #666; }
    .vulnerable { background: #ffebee; color: #c62828; }
    .likely { background: #fff3e0; color: #e65100; }
    .potential { background: #fff8e1; color: #f57f17; }
    .safe { background: #e8f5e9; color: #2e7d32; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #f5f5f5; font-weight: 600; }
    .status-vulnerable { color: #c62828; font-weight: bold; }
    .status-likely { color: #e65100; font-weight: bold; }
    .status-potential { color: #f57f17; }
    .evidence { font-size: 12px; color: #666; }
    .timestamp { color: #999; font-size: 12px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔍 SubVet Scan Report</h1>
    
    <div class="summary">
      <div class="stat vulnerable">
        <div class="stat-value">${summary.vulnerable}</div>
        <div class="stat-label">Vulnerable</div>
      </div>
      <div class="stat likely">
        <div class="stat-value">${summary.likely}</div>
        <div class="stat-label">Likely</div>
      </div>
      <div class="stat potential">
        <div class="stat-value">${summary.potential}</div>
        <div class="stat-label">Potential</div>
      </div>
      <div class="stat safe">
        <div class="stat-value">${summary.safe}</div>
        <div class="stat-label">Safe</div>
      </div>
    </div>

    ${vulnerableResults.length > 0 ? `
    <h2>🔴 Vulnerable (${vulnerableResults.length})</h2>
    <table>
      <tr><th>Subdomain</th><th>Service</th><th>Evidence</th><th>PoC</th></tr>
      ${vulnerableResults.map(r => `
      <tr>
        <td><strong>${escapeHtml(r.subdomain)}</strong></td>
        <td>${escapeHtml(r.service || 'Unknown')}</td>
        <td class="evidence">${r.evidence.map(e => escapeHtml(e)).join('<br>')}</td>
        <td>${escapeHtml(r.poc || '-')}</td>
      </tr>
      `).join('')}
    </table>
    ` : ''}

    ${likelyResults.length > 0 ? `
    <h2>🟠 Likely (${likelyResults.length})</h2>
    <table>
      <tr><th>Subdomain</th><th>Service</th><th>Evidence</th></tr>
      ${likelyResults.map(r => `
      <tr>
        <td><strong>${escapeHtml(r.subdomain)}</strong></td>
        <td>${escapeHtml(r.service || 'Unknown')}</td>
        <td class="evidence">${r.evidence.map(e => escapeHtml(e)).join('<br>')}</td>
      </tr>
      `).join('')}
    </table>
    ` : ''}

    ${potentialResults.length > 0 ? `
    <h2>🟡 Potential (${potentialResults.length})</h2>
    <table>
      <tr><th>Subdomain</th><th>Evidence</th></tr>
      ${potentialResults.map(r => `
      <tr>
        <td>${escapeHtml(r.subdomain)}</td>
        <td class="evidence">${r.evidence.map(e => escapeHtml(e)).join('<br>')}</td>
      </tr>
      `).join('')}
    </table>
    ` : ''}

    <p class="timestamp">Generated: ${output.timestamp} | SubVet v${output.version}</p>
  </div>
</body>
</html>`;
}

/**
 * Generate Markdown report
 */
export function generateMarkdownReport(output: ScanOutput): string {
  const { summary, results } = output;
  
  const vulnerableResults = results.filter(r => r.status === 'vulnerable');
  const likelyResults = results.filter(r => r.status === 'likely');
  const potentialResults = results.filter(r => r.status === 'potential');

  let md = `# 🔍 SubVet Scan Report

## Summary

| Status | Count |
|--------|-------|
| 🔴 Vulnerable | ${summary.vulnerable} |
| 🟠 Likely | ${summary.likely} |
| 🟡 Potential | ${summary.potential} |
| 🟢 Safe | ${summary.safe} |
| ⚪ Errors | ${summary.errors} |
| **Total** | **${summary.total}** |

`;

  if (vulnerableResults.length > 0) {
    md += `## 🔴 Vulnerable (${vulnerableResults.length})

| Subdomain | Service | Evidence | PoC |
|-----------|---------|----------|-----|
`;
    for (const r of vulnerableResults) {
      const subdomain = escapeMarkdownCell(r.subdomain);
      const service = escapeMarkdownCell(r.service || '-');
      const evidence = escapeMarkdownCell(r.evidence.join('; '));
      const poc = escapeMarkdownCell(r.poc || '-');
      md += `| \`${subdomain}\` | ${service} | ${evidence} | ${poc} |\n`;
    }
    md += '\n';
  }

  if (likelyResults.length > 0) {
    md += `## 🟠 Likely (${likelyResults.length})

| Subdomain | Service | Evidence |
|-----------|---------|----------|
`;
    for (const r of likelyResults) {
      const subdomain = escapeMarkdownCell(r.subdomain);
      const service = escapeMarkdownCell(r.service || '-');
      const evidence = escapeMarkdownCell(r.evidence.join('; '));
      md += `| \`${subdomain}\` | ${service} | ${evidence} |\n`;
    }
    md += '\n';
  }

  if (potentialResults.length > 0) {
    md += `## 🟡 Potential (${potentialResults.length})

| Subdomain | Evidence |
|-----------|----------|
`;
    for (const r of potentialResults) {
      const subdomain = escapeMarkdownCell(r.subdomain);
      const evidence = escapeMarkdownCell(r.evidence.join('; '));
      md += `| \`${subdomain}\` | ${evidence} |\n`;
    }
    md += '\n';
  }

  md += `---
*Generated: ${output.timestamp} | SubVet v${output.version}*
`;

  return md;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Escape Markdown table cell special characters
 * Handles: | (pipe), newlines, and other problematic chars
 */
function escapeMarkdownCell(text: string): string {
  return text
    .replace(/\|/g, '\\|')           // Escape pipe
    .replace(/\r?\n/g, '<br>')       // Convert newlines to <br>
    .replace(/\s+/g, ' ')            // Collapse multiple whitespace
    .trim();
}

/**
 * SARIF 2.1.0 types (subset)
 */
interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties?: { tags?: string[] };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: SarifLocation[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
  };
}

/**
 * Map takeover status to SARIF level
 */
function statusToSarifLevel(status: string): 'error' | 'warning' | 'note' | 'none' {
  switch (status) {
    case 'vulnerable': return 'error';
    case 'likely': return 'error';
    case 'potential': return 'warning';
    case 'not_vulnerable': return 'note';
    default: return 'none';
  }
}

/**
 * Generate SARIF 2.1.0 report for GitHub Code Scanning integration
 */
export function generateSarifReport(output: ScanOutput): string {
  const rulesMap = new Map<string, SarifRule>();
  const sarifResults: SarifResult[] = [];

  for (const result of output.results) {
    // Skip safe/unknown results
    if (result.status === 'not_vulnerable' || result.status === 'unknown') continue;

    const serviceName = result.service || 'unknown';
    const ruleId = `subvet/${serviceName.toLowerCase().replace(/\s+/g, '-')}`;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: `${serviceName} Subdomain Takeover`,
        shortDescription: { text: `Potential subdomain takeover via ${serviceName}` },
        properties: { tags: ['security', 'subdomain-takeover'] },
      });
    }

    const evidenceText = result.evidence.length > 0
      ? `\nEvidence: ${result.evidence.join('; ')}`
      : '';
    const cnameText = result.cname ? ` (CNAME: ${result.cname})` : '';

    sarifResults.push({
      ruleId,
      level: statusToSarifLevel(result.status),
      message: {
        text: `${result.subdomain} is ${result.status} to subdomain takeover via ${serviceName}${cnameText}${evidenceText}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: result.subdomain },
        },
      }],
    });
  }

  const sarif: SarifReport = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'SubVet',
          version: output.version,
          informationUri: REPO_URL,
          rules: Array.from(rulesMap.values()),
        },
      },
      results: sarifResults,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Generate report in specified format
 */
export function generateReport(output: ScanOutput, format: ReportFormat): string {
  switch (format) {
    case 'html':
      return generateHtmlReport(output);
    case 'md':
      return generateMarkdownReport(output);
    case 'sarif':
      return generateSarifReport(output);
    case 'json':
    default:
      return JSON.stringify(output, null, 2);
  }
}
