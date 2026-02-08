/**
 * SubVet - Slack Webhook Integration
 * Send scan results and alerts to Slack
 */

import type { ScanOutput, ScanSummary } from './types.js';
import type { DiffResult } from './diff.js';

export interface SlackBlock {
  type: string;
  text?: {
    type: string;
    text: string;
    emoji?: boolean;
  };
  elements?: Array<{
    type: string;
    text: string;
    emoji?: boolean;
  }>;
  fields?: Array<{
    type: string;
    text: string;
  }>;
}

export interface SlackMessage {
  text: string;
  blocks?: SlackBlock[];
}

/**
 * Send a message to Slack via webhook
 */
export async function sendSlackWebhook(
  webhookUrl: string,
  message: SlackMessage
): Promise<{ ok: boolean; error?: string }> {
  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(message),
    });

    if (!response.ok) {
      const text = await response.text();
      return { ok: false, error: `HTTP ${response.status}: ${text}` };
    }

    return { ok: true };
  } catch (error) {
    return { ok: false, error: (error as Error).message };
  }
}

/**
 * Format scan results as a Slack message
 */
export function formatScanMessage(output: ScanOutput): SlackMessage {
  const { summary } = output;
  const hasIssues = summary.vulnerable > 0 || summary.likely > 0;
  
  const emoji = summary.vulnerable > 0 ? '🚨' : 
                summary.likely > 0 ? '⚠️' : '✅';
  
  const statusText = summary.vulnerable > 0 ? 'VULNERABILITIES FOUND' :
                     summary.likely > 0 ? 'Likely Issues Found' :
                     'All Clear';

  const text = `${emoji} SubVet Scan: ${statusText}`;

  const blocks: SlackBlock[] = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: `${emoji} SubVet Scan Results`,
        emoji: true,
      },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Total Scanned:*\n${summary.total}` },
        { type: 'mrkdwn', text: `*Timestamp:*\n${output.timestamp.split('T')[0]}` },
        { type: 'mrkdwn', text: `*🔴 Vulnerable:*\n${summary.vulnerable}` },
        { type: 'mrkdwn', text: `*🟠 Likely:*\n${summary.likely}` },
        { type: 'mrkdwn', text: `*🟡 Potential:*\n${summary.potential}` },
        { type: 'mrkdwn', text: `*✅ Safe:*\n${summary.safe}` },
      ],
    },
  ];

  // Add details for vulnerable/likely findings
  if (hasIssues) {
    const issues = output.results.filter(
      r => r.status === 'vulnerable' || r.status === 'likely'
    );

    const issueLines = issues.slice(0, 10).map(r => {
      const icon = r.status === 'vulnerable' ? '🔴' : '🟠';
      const service = r.service ? ` (${r.service})` : '';
      return `${icon} \`${r.subdomain}\`${service}`;
    });

    if (issues.length > 10) {
      issueLines.push(`_...and ${issues.length - 10} more_`);
    }

    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Findings:*\n${issueLines.join('\n')}`,
      },
    });
  }

  // Footer
  blocks.push({
    type: 'context',
    elements: [
      {
        type: 'mrkdwn',
        text: `SubVet v${output.version} • Exit code: ${getExitCode(summary)}`,
      },
    ],
  });

  return { text, blocks };
}

/**
 * Format diff results as a Slack message
 */
export function formatDiffMessage(diff: DiffResult): SlackMessage {
  const hasNewIssues = diff.summary.newVulnerable > 0 || diff.summary.newLikely > 0 || diff.summary.newPotential > 0;
  
  const emoji = diff.summary.newVulnerable > 0 ? '🚨' :
                diff.summary.newLikely > 0 ? '⚠️' :
                diff.summary.newPotential > 0 ? '🟡' :
                diff.summary.resolved > 0 ? '✅' : '📊';

  const statusText = diff.summary.newVulnerable > 0 ? 'NEW VULNERABILITIES' :
                     diff.summary.newLikely > 0 ? 'New Likely Issues' :
                     diff.summary.newPotential > 0 ? 'New Potential Issues' :
                     diff.summary.resolved > 0 ? 'Issues Resolved' :
                     'No Changes';

  const text = `${emoji} SubVet Diff: ${statusText}`;

  const blocks: SlackBlock[] = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: `${emoji} SubVet Diff Report`,
        emoji: true,
      },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Baseline:*\n${diff.baseline.total} targets` },
        { type: 'mrkdwn', text: `*Current:*\n${diff.current.total} targets` },
        { type: 'mrkdwn', text: `*🔴 New Vulnerable:*\n${diff.summary.newVulnerable}` },
        { type: 'mrkdwn', text: `*🟠 New Likely:*\n${diff.summary.newLikely}` },
        { type: 'mrkdwn', text: `*🟡 New Potential:*\n${diff.summary.newPotential}` },
        { type: 'mrkdwn', text: `*✅ Resolved:*\n${diff.summary.resolved}` },
        { type: 'mrkdwn', text: `*Unchanged:*\n${diff.summary.unchanged}` },
      ],
    },
  ];

  // Add new issues
  if (hasNewIssues) {
    const newIssues = diff.entries.filter(
      e => e.type === 'new' && (e.currentStatus === 'vulnerable' || e.currentStatus === 'likely' || e.currentStatus === 'potential')
    );

    const issueLines = newIssues.slice(0, 10).map(e => {
      const icon = e.currentStatus === 'vulnerable' ? '🔴' : e.currentStatus === 'likely' ? '🟠' : '🟡';
      const service = e.service ? ` (${e.service})` : '';
      return `${icon} \`${e.subdomain}\`${service}`;
    });

    if (newIssues.length > 10) {
      issueLines.push(`_...and ${newIssues.length - 10} more_`);
    }

    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*New Issues:*\n${issueLines.join('\n')}`,
      },
    });
  }

  // Add resolved issues
  if (diff.summary.resolved > 0) {
    const resolved = diff.entries.filter(e => e.type === 'resolved');

    const resolvedLines = resolved.slice(0, 5).map(e => {
      return `✅ \`${e.subdomain}\` (was ${e.previousStatus})`;
    });

    if (resolved.length > 5) {
      resolvedLines.push(`_...and ${resolved.length - 5} more_`);
    }

    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Resolved:*\n${resolvedLines.join('\n')}`,
      },
    });
  }

  // Footer
  blocks.push({
    type: 'context',
    elements: [
      {
        type: 'mrkdwn',
        text: `SubVet v${diff.version} • Compared at ${diff.timestamp.split('T')[0]}`,
      },
    ],
  });

  return { text, blocks };
}

function getExitCode(summary: ScanSummary): number {
  if (summary.vulnerable > 0) return 2;
  if (summary.likely > 0) return 1;
  return 0;
}
