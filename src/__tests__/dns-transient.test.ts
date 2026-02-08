/**
 * DNS transient error handling tests
 * Verifies that SERVFAIL/timeout errors are NOT treated as dangling
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
  resolveCname: vi.fn(),
  resolveNs: vi.fn(),
  resolveMx: vi.fn(),
  resolveSrv: vi.fn(),
  resolveTxt: vi.fn(),
}));

vi.mock('node:dns', () => ({
  default: mocks,
  ...mocks,
}));

import { DnsResolver } from '../dns.js';

function mockReject(mockFn: ReturnType<typeof vi.fn>, code: string) {
  mockFn.mockImplementation((_target: string, cb: Function) => {
    cb(Object.assign(new Error(code), { code }), null);
  });
}

function mockRejectMsg(mockFn: ReturnType<typeof vi.fn>, message: string) {
  mockFn.mockImplementation((_target: string, cb: Function) => {
    cb(new Error(message), null);
  });
}

function mockResolveWith(mockFn: ReturnType<typeof vi.fn>, value: any) {
  mockFn.mockImplementation((_target: string, cb: Function) => {
    cb(null, value);
  });
}

describe('DNS transient error handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: permanent failure
    mockReject(mocks.resolve4, 'ENOTFOUND');
    mockReject(mocks.resolve6, 'ENOTFOUND');
    mockReject(mocks.resolveCname, 'ENOTFOUND');
    mockReject(mocks.resolveNs, 'ENOTFOUND');
    mockReject(mocks.resolveMx, 'ENOTFOUND');
    mockReject(mocks.resolveSrv, 'ENOTFOUND');
    mockReject(mocks.resolveTxt, 'ENOTFOUND');
  });

  it('should not mark NS as dangling on SERVFAIL (transient)', async () => {
    mockReject(mocks.resolve4, 'SERVFAIL');
    mockReject(mocks.resolve6, 'SERVFAIL');

    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isNsDangling('ns1.transient.example');
    expect(result).toBe(false);
  });

  it('should mark NS as dangling on ENOTFOUND (permanent)', async () => {
    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isNsDangling('ns1.dead.example');
    expect(result).toBe(true);
  });

  it('should mark NS as dangling on ENODATA (permanent)', async () => {
    mockReject(mocks.resolve4, 'ENODATA');
    mockReject(mocks.resolve6, 'ENODATA');

    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isNsDangling('ns1.nodata.example');
    expect(result).toBe(true);
  });

  it('should not mark MX as dangling on DNS timeout (transient)', async () => {
    mockRejectMsg(mocks.resolve4, 'DNS timeout');
    mockRejectMsg(mocks.resolve6, 'DNS timeout');

    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isMxDangling('mx.transient.example');
    expect(result).toBe(false);
  });

  it('should not mark SRV target as dangling on ESERVFAIL (transient)', async () => {
    mockReject(mocks.resolve4, 'ESERVFAIL');
    mockReject(mocks.resolve6, 'ESERVFAIL');

    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isSrvTargetDangling('srv.transient.example');
    expect(result).toBe(false);
  });

  it('should resolve when A record exists', async () => {
    mockResolveWith(mocks.resolve4, ['1.2.3.4']);
    mockReject(mocks.resolve6, 'ENODATA');

    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isNsDangling('ns1.good.example');
    expect(result).toBe(false);
  });

  it('should not mark CNAME as dangling on transient error', async () => {
    mockReject(mocks.resolve4, 'SERVFAIL');
    mockReject(mocks.resolve6, 'SERVFAIL');

    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.isCnameDangling('target.transient.example');
    expect(result).toBe(false);
  });
});
