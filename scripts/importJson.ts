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
    if (!schema.brand || !Array.isArray(schema.findings)) {
      throw new Error(`${sourcePath} is not a supported SentinelShield JSON database.`);
    }
    await db.importLegacyJson(schema);
    console.log(`Imported ${schema.findings.length} legacy detections from ${sourcePath}; duplicate IDs were skipped.`);
  } finally {
    await disconnectMongo();
  }
}

main().catch((error: unknown) => {
  console.error('Legacy JSON import failed:', error);
  process.exitCode = 1;
});
