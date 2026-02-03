#!/usr/bin/env node

/**
 * SubVet - CLI Entry Point
 */

import { Command } from 'commander';
import { readFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import chalk from 'chalk';
import { Scanner } from './scanner.js';
import { getAllFingerprints } from './fingerprints/index.js';
import type { ScanResult } from './types.js';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('subvet')
  .description('Subdomain takeover vulnerability scanner')
  .version(VERSION);

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
  .option('-v, --verbose', 'Show progress')
  .option('-o, --output <file>', 'Write JSON output to file')
  .option('--pretty', 'Pretty print JSON output')
  .action(async (target, options) => {
    try {
      let subdomains: string[] = [];

      // Collect subdomains from various sources
      if (options.stdin) {
        subdomains = await readFromStdin();
      } else if (options.file) {
        subdomains = await readFromFile(options.file);
      } else if (target) {
        subdomains = [target];
      } else {
        console.error(chalk.red('Error: Please provide a target, file, or use --stdin'));
        process.exit(1);
      }

      if (subdomains.length === 0) {
        console.error(chalk.red('Error: No subdomains to scan'));
        process.exit(1);
      }

      // Create scanner
      const scanner = new Scanner({
        timeout: parseInt(options.timeout),
        concurrency: parseInt(options.concurrency),
        httpProbe: options.http !== false,
        verbose: options.verbose
      });

      if (options.verbose) {
        console.error(chalk.cyan(`SubVet v${VERSION}`));
        console.error(chalk.gray(`Scanning ${subdomains.length} subdomain(s)...`));
      }

      // Run scan
      const output = await scanner.scan(subdomains);

      // Output results
      if (options.output) {
        const fs = await import('node:fs/promises');
        const json = options.pretty 
          ? JSON.stringify(output, null, 2)
          : JSON.stringify(output);
        await fs.writeFile(options.output, json);
        console.error(chalk.green(`Results written to ${options.output}`));
      }

      // Always output JSON to stdout
      const json = options.pretty 
        ? JSON.stringify(output, null, 2)
        : JSON.stringify(output);
      console.log(json);

      // Exit with error code if vulnerabilities found
      if (output.summary.vulnerable > 0) {
        process.exit(2);
      } else if (output.summary.likely > 0) {
        process.exit(1);
      }

    } catch (error) {
      console.error(chalk.red(`Error: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// === check command (single subdomain, human readable) ===
program
  .command('check')
  .description('Check a single subdomain (human-readable output)')
  .argument('<subdomain>', 'Subdomain to check')
  .option('-t, --timeout <ms>', 'Timeout for DNS/HTTP requests', '10000')
  .option('--json', 'Output as JSON')
  .action(async (subdomain, options) => {
    try {
      const scanner = new Scanner({
        timeout: parseInt(options.timeout),
        httpProbe: true
      });

      const output = await scanner.scan([subdomain]);
      const result = output.results[0];

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      // Human-readable output
      printResult(result);

      // Exit codes
      if (result.status === 'vulnerable') process.exit(2);
      if (result.status === 'likely') process.exit(1);

    } catch (error) {
      console.error(chalk.red(`Error: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// === services command ===
program
  .command('services')
  .description('List all supported services')
  .option('--json', 'Output as JSON')
  .action((options) => {
    const services = getAllFingerprints();

    if (options.json) {
      console.log(JSON.stringify(services, null, 2));
      return;
    }

    console.log(chalk.cyan(`\nSupported Services (${services.length}):\n`));
    
    const vulnerable = services.filter(s => s.takeoverPossible);
    const notVulnerable = services.filter(s => !s.takeoverPossible);

    console.log(chalk.red('Takeover Possible:'));
    for (const s of vulnerable) {
      console.log(`  ${chalk.yellow('●')} ${s.service}`);
      console.log(chalk.gray(`    CNAME: ${s.cnames.join(', ')}`));
    }

    console.log(chalk.green('\nTakeover Not Possible (requires verification):'));
    for (const s of notVulnerable) {
      console.log(`  ${chalk.green('●')} ${s.service}`);
    }

    console.log();
  });

// === fingerprint command ===
program
  .command('fingerprint <service>')
  .description('Show fingerprint details for a service')
  .action((service) => {
    const fps = getAllFingerprints();
    const fp = fps.find(f => 
      f.service.toLowerCase() === service.toLowerCase()
    );

    if (!fp) {
      console.error(chalk.red(`Service not found: ${service}`));
      console.error(chalk.gray('Use "subvet services" to list available services'));
      process.exit(1);
    }

    console.log(chalk.cyan(`\n${fp.service}\n`));
    console.log(chalk.gray(`Description: ${fp.description}`));
    console.log(chalk.gray(`Takeover: ${fp.takeoverPossible ? chalk.red('Possible') : chalk.green('Not Possible')}`));
    console.log(chalk.gray(`CNAME patterns:`));
    for (const cname of fp.cnames) {
      console.log(chalk.yellow(`  - ${cname}`));
    }
    console.log(chalk.gray(`Fingerprints:`));
    for (const rule of fp.fingerprints) {
      console.log(chalk.gray(`  - ${rule.type}: ${rule.pattern ?? rule.value ?? ''}`));
    }
    if (fp.poc) {
      console.log(chalk.gray(`PoC: ${fp.poc}`));
    }
    if (fp.documentation) {
      console.log(chalk.gray(`Docs: ${fp.documentation}`));
    }
    console.log();
  });

// === Helper functions ===

async function readFromFile(path: string): Promise<string[]> {
  const content = await readFile(path, 'utf-8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
}

async function readFromStdin(): Promise<string[]> {
  return new Promise((resolve) => {
    const lines: string[] = [];
    const rl = createInterface({
      input: process.stdin,
      crlfDelay: Infinity
    });

    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        lines.push(trimmed);
      }
    });

    rl.on('close', () => {
      resolve(lines);
    });
  });
}

function printResult(result: ScanResult): void {
  const statusColors: Record<string, (s: string) => string> = {
    vulnerable: chalk.red,
    likely: chalk.yellow,
    potential: chalk.magenta,
    edge_case: chalk.cyan,
    not_vulnerable: chalk.green,
    unknown: chalk.gray
  };

  const riskEmoji: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    info: '⚪'
  };

  const colorFn = statusColors[result.status] ?? chalk.gray;
  
  console.log();
  console.log(`${riskEmoji[result.risk]} ${chalk.bold(result.subdomain)}`);
  console.log(`   Status: ${colorFn(result.status.toUpperCase())}`);
  
  if (result.service) {
    console.log(`   Service: ${chalk.cyan(result.service)}`);
  }
  
  if (result.cname) {
    console.log(`   CNAME: ${chalk.gray(result.cname)}`);
  }

  if (result.dns.records.length > 0) {
    console.log(`   DNS Records:`);
    for (const record of result.dns.records.slice(0, 5)) {
      console.log(chalk.gray(`     ${record.type}: ${record.value}`));
    }
    if (result.dns.records.length > 5) {
      console.log(chalk.gray(`     ... and ${result.dns.records.length - 5} more`));
    }
  }

  if (result.http) {
    console.log(`   HTTP: ${result.http.status ?? 'N/A'} (${result.http.responseTime ?? 0}ms)`);
    if (result.http.error) {
      console.log(chalk.red(`     Error: ${result.http.error}`));
    }
  }

  if (result.evidence.length > 0) {
    console.log(`   Evidence:`);
    for (const e of result.evidence) {
      console.log(chalk.yellow(`     - ${e}`));
    }
  }

  if (result.poc) {
    console.log(`   PoC: ${chalk.magenta(result.poc)}`);
  }

  console.log();
}

// Run CLI
program.parse();
