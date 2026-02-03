/**
 * Miscellaneous Service Fingerprints
 * Surveys, job boards, regional services, etc.
 */

import type { ServiceFingerprint } from '../types.js';

export const miscFingerprints: ServiceFingerprint[] = [
  {
    service: 'SurveySparrow',
    description: 'SurveySparrow survey platform',
    cnames: ['*.surveysparrow.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Account not found.', weight: 10, required: true }
    ],
    takeoverPossible: true,
    documentation: 'https://help.surveysparrow.com/custom-domain',
    poc: 'Create SurveySparrow account and configure custom domain'
  },
  {
    service: 'SmartJobBoard',
    description: 'SmartJobBoard job board platform',
    cnames: ['*.smartjobboard.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'This job board website is either expired or its domain name is invalid', weight: 10, required: true }
    ],
    takeoverPossible: true,
    documentation: 'https://help.smartjobboard.com/en/articles/1269655',
    poc: 'Create SmartJobBoard site and configure custom domain'
  },
  {
    service: 'HatenaBlog',
    description: 'Hatena Blog platform (Japan)',
    cnames: ['*.hatenablog.com', '*.hatenablog.jp', '*.hateblo.jp'],
    fingerprints: [
      { type: 'http_body', pattern: '404 Blog is not found', weight: 10, required: true },
      { type: 'http_body', pattern: 'ブログが見つかりません', weight: 10 }
    ],
    takeoverPossible: true,
    poc: 'Create Hatena Blog and configure custom domain'
  },
  {
    service: 'Airee',
    description: 'Airee.ru CDN',
    cnames: ['*.airee.ru'],
    fingerprints: [
      { type: 'http_body', pattern: 'Ошибка 402. Оплата не manufacturers', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Register with Airee'
  }
];
