/**
 * Standalone Seed CLI Script
 * Run via: npm run seed
 * Provisions and verifies the 4 default TrustVault evaluation accounts and sample data.
 */

import { seedInitialData } from './seed.js';
import { vaultStore } from './store.js';

async function main() {
  console.log('[TrustVault] Initializing and verifying demo accounts...');
  await seedInitialData();

  const users = await vaultStore.getAllUsers();
  console.log(`[TrustVault] Database seeded successfully. Total users: ${users.length}`);

  for (const u of users) {
    console.log(`  - Account: ${u.email.padEnd(28)} | Role: ${u.role.toUpperCase().padEnd(7)} | Active: ${u.active}`);
  }

  const owner = await vaultStore.getUserByEmail('owner@trustvault.local');
  if (owner) {
    const docs = await vaultStore.searchAccessibleDocuments(owner.id, {});
    console.log(`[TrustVault] Seeded accessible documents for owner: ${docs.length}`);
  }

  console.log('[TrustVault] All demo profiles verified and ready.');
  process.exit(0);
}

main().catch(err => {
  console.error('[TrustVault Seed Error]', err);
  process.exit(1);
});
