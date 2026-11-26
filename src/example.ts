import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSigningKey, signBytes } from 'sovereign-attest';
import { DAY_MS } from './policy.js';
import { Succession } from './succession.js';
import { claimPayload } from './claim.js';

/**
 * A full succession run on a scratch directory:
 * owner heartbeats → goes silent → 2 of 3 heirs open the window and claim.
 *
 * Run with `npm run example`.
 */
async function main(): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'succession-example-'));
  const owner = createSigningKey('owner-primary', Date.UTC(2026, 0, 1));
  const heirs = ['ann', 'bob', 'cy'].map((id) => ({
    ...createSigningKey(id, Date.UTC(2026, 0, 1)),
  }));

  let clock = Date.UTC(2026, 0, 1);
  const now = (): number => clock;

  const succession = await Succession.open({
    dir,
    ownerKey: owner,
    now,
    policy: {
      heirs: heirs.map((heir) => ({
        id: heir.keyId,
        publicKey: heir.publicKey,
        label: heir.keyId,
      })),
      threshold: 2,
      dormantAfterDays: 90,
      createdAt: clock,
    },
  });

  console.log(`store:       ${dir}`);
  console.log(`policy:      ${succession.policyId}`);
  console.log(`2 of ${succession.policy.heirs.length} heirs, dormant after 90 days`);

  clock += 30 * DAY_MS;
  await succession.heartbeat();
  console.log(`heartbeat:   owner seen at ${new Date(clock).toISOString()}`);

  clock += 10 * DAY_MS;
  console.log(`day 10:      ${(await succession.status()).phase}`);

  clock += 80 * DAY_MS;
  console.log(`day 90:      ${(await succession.status()).phase}`);

  const requestId = 'estate-2027-01';
  const at = clock;
  const payload = claimPayload(succession.policyId, requestId, at);
  const shares = [heirs[0], heirs[2]].map((heir) => ({
    heirId: heir.keyId,
    sig: signBytes(heir.privateKey, payload),
  }));

  const grant = await succession.claim({ requestId, at, shares, purpose: 'open the books' });
  console.log(`grant:       ${grant.receipt.id}`);
  console.log(`holders:     ${grant.holders.join(', ')}`);
  console.log(`custody:     ${grant.custodyToken}`);

  const report = await succession.verify();
  console.log(`receipts:    ${report.receipts.length} verified, head ${report.head}`);
  console.log(`owner key:   ${report.ownerKeyFingerprint}`);
  console.log(`system key:  ${report.systemKeyFingerprint}`);

  try {
    await succession.claim({ requestId, at: at + DAY_MS, shares });
  } catch (error) {
    console.log(`replay:      refused with ${(error as { code?: string }).code}`);
  }
}

await main();
