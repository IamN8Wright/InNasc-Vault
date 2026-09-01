import fs from 'node:fs/promises';
import path from 'node:path';

import { createOffboardingPdf } from '../dist/local-server/offboarding-pdf.js';

const outputPath = path.resolve(process.argv[2] ?? 'tmp/pdfs/InNasc_Offboarding_Sample.pdf');
const pdf = await createOffboardingPdf({
  exportedAt: '2026-09-01T12:00:00.000Z',
  exportedBy: 'Synthetic Test Owner <owner@example.invalid>',
  clients: [{
    name: 'Synthetic Client - Café Technology Group',
    code: 'SAMPLE',
    notes: 'Demonstration data only. No real client or credential information is included.',
    locations: [{
      name: 'Main Office',
      address: '100 Example Avenue\nAnchorage, Alaska 99501',
      notes: 'Sample location used only to verify PDF pagination and typography.',
      systems: [
        { name: 'Sample Firewall', collection: 'network', manufacturer: 'Example Networks', model: 'FW-100', network_address: '192.0.2.10', notes: 'Synthetic documentation record.' },
        { name: 'Sample Conference Room', collection: 'av_systems', manufacturer: 'Example AV', model: 'ROOM-20', network_address: '192.0.2.20', notes: 'Synthetic AV system record.' },
      ],
      assets: [
        { asset_type: 'device', name: 'Sample Switch', system_name: 'Sample Firewall', vendor: 'Example Networks', version_or_model: 'SW-48', identifier: 'SYNTHETIC-0001', url: 'https://example.invalid/switch', notes: 'No real serial number.' },
        { asset_type: 'software', name: 'Sample Management Portal', system_name: '', vendor: 'Example Software', version_or_model: '1.0', identifier: 'DEMO-LICENSE', url: 'https://example.invalid/portal', notes: 'No real account.' },
      ],
      credentials: [
        { name: 'Sample Firewall Administrator', collection: 'network', systemName: 'Sample Firewall', url: 'https://192.0.2.10', lastVerifiedAt: '2026-09-01T11:30:00.000Z', expiresAt: '', secret: { username: 'synthetic-admin', password: 'SYNTHETIC-NOT-A-REAL-PASSWORD-9!xQ', pin: '', apiToken: '', licenseKey: '', notes: 'Demonstration credential only.' } },
        { name: 'Sample Vendor Portal', collection: 'websites_accounts', systemName: '', url: 'https://example.invalid/login', lastVerifiedAt: '2026-09-01T11:35:00.000Z', expiresAt: '2027-09-01T00:00:00.000Z', secret: { username: 'sample-user@example.invalid', password: 'SYNTHETIC-NOT-A-REAL-PASSWORD-4@wR', pin: '000000', apiToken: 'SYNTHETIC-TOKEN-NOT-VALID', licenseKey: 'SYNTHETIC-LICENSE-NOT-VALID', notes: 'All values in this document are intentionally unusable.' } },
      ],
    }],
  }],
});

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.writeFile(outputPath, pdf);
console.log(outputPath);
