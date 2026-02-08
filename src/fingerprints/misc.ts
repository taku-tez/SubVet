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
  },
  {
    service: 'Short.io',
    description: 'Short.io URL shortener',
    cnames: ['*.short.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Link does not exist', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Create Short.io account and configure custom domain'
  },
  {
    service: 'Smugmug',
    description: 'SmugMug photo hosting',
    cnames: ['*.smugmug.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Page Not Found', weight: 5 },
      { type: 'http_body', pattern: 'SmugMug', weight: 5 }
    ],
    takeoverPossible: true,
    poc: 'Create SmugMug account and configure custom domain'
  },
  {
    service: 'Acquia',
    description: 'Acquia Cloud (Drupal hosting)',
    cnames: ['*.acquia-sites.com', '*.acquia.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Web Site Not Found', weight: 8 },
      { type: 'http_body', pattern: 'If you are an Acquia Cloud customer', weight: 8 }
    ],
    takeoverPossible: false,
    documentation: 'https://github.com/EdOverflow/can-i-take-over-xyz/issues/103'
  },
  {
    service: 'Frontify',
    description: 'Frontify brand management',
    cnames: ['*.frontify.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Oops… looks like you got lost', weight: 7 },
      { type: 'http_body', pattern: '404 - Page Not Found', weight: 5 }
    ],
    takeoverPossible: false,
    documentation: 'https://github.com/EdOverflow/can-i-take-over-xyz/issues/170'
  },
  {
    service: 'Mashery',
    description: 'TIBCO Mashery API management',
    cnames: ['*.mashery.com', '*.api.mashery.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Unrecognized domain', weight: 10, required: true }
    ],
    takeoverPossible: false,
    documentation: 'https://github.com/EdOverflow/can-i-take-over-xyz/issues/14'
  },
  {
    service: 'Instapage',
    description: 'Instapage landing page platform',
    cnames: ['*.instapage.com', '*.pagedemo.co'],
    fingerprints: [
      { type: 'http_body', pattern: 'You\'ve Discovered A Missing Link', weight: 7 },
      { type: 'http_body', pattern: 'Instapage', weight: 5 }
    ],
    takeoverPossible: false,
    documentation: 'https://github.com/EdOverflow/can-i-take-over-xyz/issues/73'
  },
  {
    service: 'Dreamhost',
    description: 'DreamHost web hosting',
    cnames: ['*.dreamhost.com', '*.dreamhosters.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Site Not Found', weight: 5 },
      { type: 'http_body', pattern: 'The site you\'re looking for is not here', weight: 7 }
    ],
    takeoverPossible: false,
    documentation: 'https://github.com/EdOverflow/can-i-take-over-xyz/issues/153'
  }
];
