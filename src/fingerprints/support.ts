/**
 * Support & Helpdesk Platform Fingerprints
 */

import type { ServiceFingerprint } from '../types.js';

export const supportFingerprints: ServiceFingerprint[] = [
  {
    service: 'Zendesk',
    description: 'Zendesk support',
    cnames: ['*.zendesk.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Help Center Closed', weight: 10, required: true },
      { type: 'http_body', pattern: 'this help center no longer exists', weight: 10 }
    ],
    takeoverPossible: true,
    poc: 'Create Zendesk account and claim subdomain'
  },
  {
    service: 'Freshdesk',
    description: 'Freshdesk support',
    cnames: ['*.freshdesk.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'There is no helpdesk here!', weight: 10, required: true },
      { type: 'http_body', pattern: 'May be this is still fresh!', weight: 8 }
    ],
    takeoverPossible: false,
    documentation: 'Requires account verification'
  },
  {
    service: 'Intercom',
    description: 'Intercom help center',
    cnames: ['*.intercom.help', 'custom.intercom.help'],
    fingerprints: [
      { type: 'http_body', pattern: 'This page is reserved for', weight: 10, required: true },
      { type: 'http_body', pattern: 'Uh oh. That page doesn\'t exist', weight: 8 }
    ],
    takeoverPossible: true,
    poc: 'Add domain in Intercom settings'
  },
  {
    service: 'Kayako',
    description: 'Kayako helpdesk',
    cnames: ['*.kayako.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Support Center', weight: 5 },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    takeoverPossible: false,
    documentation: 'Requires account verification'
  },
  {
    service: 'Desk.com',
    description: 'Salesforce Desk.com',
    cnames: ['*.desk.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, We Couldn\'t Find That Page', weight: 8 },
      { type: 'http_body', pattern: 'Please try again or visit our Help Center', weight: 8 }
    ],
    takeoverPossible: false,
    documentation: 'Service deprecated, check with Salesforce'
  },
  {
    service: 'Help Juice',
    description: 'Help Juice knowledge base',
    cnames: ['*.helpjuice.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'We could not find what you\'re looking for', weight: 10, required: true }
    ],
    takeoverPossible: true,
    documentation: 'https://help.helpjuice.com/en_US/using-your-custom-domain/how-to-set-up-a-custom-domain',
    poc: 'Create Help Juice account and add custom domain'
  },
  {
    service: 'Help Scout Docs',
    description: 'Help Scout documentation',
    cnames: ['*.helpscoutdocs.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'No settings were found for this company:', weight: 10, required: true }
    ],
    takeoverPossible: true,
    documentation: 'https://docs.helpscout.net/article/42-setup-custom-domain',
    poc: 'Create Help Scout Docs site and add custom domain'
  },
  {
    service: 'Helprace',
    description: 'Helprace helpdesk',
    cnames: ['*.helprace.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Helprace', weight: 6 },
      { type: 'http_body', pattern: 'This community no longer exists', weight: 10, required: true },
      { type: 'http_body', pattern: 'community.*not.*found', weight: 8 },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    minConfidence: 5,
    takeoverPossible: true,
    poc: 'Create Helprace helpdesk with custom domain'
  },
  {
    service: 'UserVoice',
    description: 'UserVoice feedback',
    cnames: ['*.uservoice.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'This UserVoice subdomain is currently available!', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Create UserVoice account with subdomain'
  },
  {
    service: 'Canny',
    description: 'Canny feedback',
    cnames: ['*.canny.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Company Not Found', weight: 10, required: true },
      { type: 'http_body', pattern: 'There is no such company', weight: 10 }
    ],
    takeoverPossible: true,
    poc: 'Create Canny board with matching subdomain'
  }
];
