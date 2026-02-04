/**
 * SubVet - Version (single source of truth)
 * Reads from package.json at build time
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Read package.json - works for both src (dev) and dist (prod)
let packageJsonPath = join(__dirname, '..', 'package.json');

// Fallback: try one level up (for dist/version.js)
try {
  readFileSync(packageJsonPath, 'utf-8');
} catch {
  packageJsonPath = join(__dirname, '..', '..', 'package.json');
}

const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

export const VERSION = packageJson.version as string;
export const NAME = packageJson.name as string;
