/**
 * Version Module Tests
 */

import { describe, it, expect } from 'vitest';
import { VERSION, NAME } from '../version.js';

describe('version module', () => {
  it('should export VERSION string', () => {
    expect(typeof VERSION).toBe('string');
    expect(VERSION).toBeTruthy();
  });

  it('should match semver format', () => {
    // Semver: major.minor.patch (optionally with prerelease)
    const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$/;
    expect(VERSION).toMatch(semverRegex);
  });

  it('should export NAME string', () => {
    expect(typeof NAME).toBe('string');
    expect(NAME).toBe('subvet');
  });
});
