import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { db, type DatabaseSchema } from '../server/db.js';
import { disconnectMongo } from '../server/models.js';

async function main() {
  try {
    await db.initialize();
    const sourcePath = path.resolve(process.cwd(), 'data', 'sentinel_db.json');
    const schema = JSON.parse(await readFile(sourcePath, 'utf8')) as DatabaseSchema;
    if (schema.findings?.length !== 24) {
      throw new Error(`Expected 24 demo detections in ${sourcePath}; found ${schema.findings?.length || 0}.`);
    }
    const reset = process.argv.includes('--reset');
    await db.seedDatabase(schema, reset);
    const [findings, alerts, users, brand] = await Promise.all([
      db.getFindings(),
      db.getAlerts(),
      db.getUsers(),
      db.getBrand(),
    ]);
    console.log(
      `MongoDB seed complete${reset ? ' (reset)' : ''}: ${findings.length} detections, ${alerts.length} alerts, ${users.length} users, ${brand.officialApps.length + brand.officialSocialAccounts.length + brand.officialDomains.length} official allowlist entries.`,
    );
  } finally {
    await disconnectMongo();
  }
}

main().catch((error: unknown) => {
  console.error('MongoDB seed failed:', error);
  process.exitCode = 1;
});
