/**
 * SubVet - CLI Option Definitions
 * Commander.js command and option setup.
 */

import { Command } from 'commander';
import { VERSION } from './version.js';

/**
 * Create and configure the CLI program with all commands and options.
 */
export function createProgram(): Command {
  const program = new Command();

  program
    .name('subvet')
    .description('Subdomain takeover vulnerability scanner')
    .version(VERSION);

  // Global option for custom signatures
  program
    .option('--custom-signatures <dir>', 'Load additional signatures from a custom directory');

  // === scan command ===
  program
    .command('scan')
    .description('Scan subdomains for takeover vulnerabilities')
    .argument('[target]', 'Domain or subdomain to scan')
    .option('-f, --file <path>', 'Read subdomains from file (one per line)')
    .option('--stdin', 'Read subdomains from stdin')
    .option('-t, --timeout <ms>', 'Timeout for DNS/HTTP requests', '10000')
    .option('-c, --concurrency <n>', 'Number of concurrent requests', '10')
    .option('--no-http', 'Skip HTTP probing')
    .option('--check-ns', 'Check for dangling NS delegation')
    .option('--check-mx', 'Check for dangling MX records')
    .option('--check-spf', 'Check for dangling SPF includes')
    .option('--check-srv', 'Check for dangling SRV records')
    .option('--check-txt', 'Check for dangling TXT domain references')
    .option('-v, --verbose', 'Show progress')
    .option('-o, --output <file>', 'Write JSON output to file')
    .option('--pretty', 'Pretty print JSON output')
    .option('--summary', 'Show summary only (no full results)')
    .option('--report <format>', 'Generate report (html, md, json, sarif)')
    .option('--diff <baseline>', 'Compare against baseline JSON file (CI mode)')
    .option('--diff-json', 'Output diff as JSON (with --diff)')
    .option('--slack-webhook <url>', 'Send results to Slack webhook')
    .option('--slack-on <condition>', 'When to notify: always, issues, new (new = diff-mode only; falls back to issues in regular scan)', 'issues');

  // === check command (single subdomain, human readable) ===
  program
    .command('check')
    .description('Check a single subdomain (human-readable output)')
    .argument('<subdomain>', 'Subdomain to check')
    .option('-t, --timeout <ms>', 'Timeout for DNS/HTTP requests', '10000')
    .option('--check-ns', 'Check for dangling NS delegation')
    .option('--check-mx', 'Check for dangling MX records')
    .option('--check-spf', 'Check for dangling SPF includes')
    .option('--check-srv', 'Check for dangling SRV records')
    .option('--check-txt', 'Check for dangling TXT domain references')
    .option('--json', 'Output as JSON');

  // === services command ===
  program
    .command('services')
    .description('List all supported services')
    .option('--json', 'Output as JSON');

  // === fingerprint command ===
  program
    .command('fingerprint <service>')
    .description('Show fingerprint details for a service');

  // === signatures command ===
  const sigCmd = program
    .command('signatures')
    .description('Manage signature files');

  sigCmd
    .command('list')
    .description('List all loaded signatures')
    .option('--json', 'Output as JSON');

  return program;
}
