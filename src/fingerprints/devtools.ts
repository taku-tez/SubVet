/**
 * Developer Tools & Services Fingerprints
 * Version control, CI/CD, documentation, monitoring
 */

import type { ServiceFingerprint } from '../types.js';

export const devtoolsFingerprints: ServiceFingerprint[] = [
  {
    service: 'Bitbucket',
    description: 'Bitbucket cloud pages',
    cnames: ['*.bitbucket.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Repository not found', weight: 10, required: true },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    takeoverPossible: true,
    poc: 'Create repository and enable pages'
  },
  {
    service: 'Statuspage',
    description: 'Atlassian Statuspage',
    cnames: ['*.statuspage.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Status page pushed a b', weight: 8 },
      { type: 'http_body', pattern: 'You are being redirected', weight: 6 },
      { type: 'http_status', value: 302, weight: 3 }
    ],
    minConfidence: 5,
    takeoverPossible: true,
    poc: 'Create statuspage and add custom domain'
  },
  {
    service: 'Pingdom',
    description: 'Pingdom status pages',
    cnames: ['*.pingdom.com', '*.status.pingdom.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, couldn\'t find the status page', weight: 10, required: true },
      { type: 'http_body', pattern: 'Public report not activated', weight: 8 }
    ],
    takeoverPossible: true,
    documentation: 'https://help.pingdom.com/hc/en-us/articles/205386171-Public-Status-Page',
    poc: 'Create Pingdom status page and add custom domain'
  },
  {
    service: 'UptimeRobot',
    description: 'UptimeRobot status pages',
    cnames: ['*.stats.uptimerobot.com', '*.uptimerobot.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'page not found', weight: 8 }
    ],
    minConfidence: 5,
    takeoverPossible: true,
    poc: 'Create UptimeRobot status page and add custom domain'
  },
  {
    service: 'JetBrains YouTrack',
    description: 'JetBrains YouTrack InCloud',
    cnames: ['*.youtrack.cloud', '*.myjetbrains.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'is not a registered InCloud YouTrack', weight: 10, required: true }
    ],
    takeoverPossible: true,
    documentation: 'https://www.jetbrains.com/help/youtrack/incloud/Domain-Settings.html',
    poc: 'Create YouTrack InCloud instance and add custom domain'
  },
  {
    service: 'Readme.io',
    description: 'Readme.io documentation platform',
    cnames: ['*.readme.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'The creators of this project are still working on making everything perfect!', weight: 10, required: true },
      { type: 'http_body', pattern: 'Project not found', weight: 10 }
    ],
    takeoverPossible: true,
    poc: 'Create Readme.io project and configure custom domain'
  },
  {
    service: 'Discourse',
    description: 'Discourse forum hosting',
    cnames: ['*.trydiscourse.com'],
    fingerprints: [
      { type: 'dns_nxdomain', weight: 10 }
    ],
    takeoverPossible: true,
    documentation: 'https://meta.discourse.org/',
    poc: 'Create Discourse instance and configure custom domain'
  },
  {
    service: 'Ngrok',
    description: 'Ngrok tunnel service',
    cnames: ['*.ngrok.io', '*.ngrok-free.app'],
    fingerprints: [
      { type: 'http_body', pattern: 'Tunnel .*.ngrok.io not found', weight: 10, required: true },
      { type: 'http_body', pattern: 'ngrok gateway error', weight: 8 },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    takeoverPossible: true,
    documentation: 'https://ngrok.com/docs#http-custom-domains',
    poc: 'Register ngrok tunnel with the custom domain'
  },
  {
    service: 'Gemfury',
    description: 'Gemfury package hosting',
    cnames: ['*.furyns.com', '*.fury.io'],
    fingerprints: [
      { type: 'http_body', pattern: '404: This page could not be found', weight: 8 }
    ],
    minConfidence: 5,
    takeoverPossible: true,
    poc: 'Create Gemfury repository and configure domain'
  },
  {
    service: 'Feedpress',
    description: 'Feedpress podcast hosting',
    cnames: ['*.redirect.feedpress.me'],
    fingerprints: [
      { type: 'http_body', pattern: 'The feed has not been found', weight: 10, required: true },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    takeoverPossible: true,
    poc: 'Create feed with custom domain'
  }
];
