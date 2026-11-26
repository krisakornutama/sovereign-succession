import { mkdir, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { signBytes } from 'sovereign-attest';
import { ACTION_DENIED, ACTION_GRANTED, ACTION_HEARTBEAT } from '../src/clock.js';
import { claimPayload } from '../src/claim.js';
import { sealPolicy } from '../src/policy.js';
import { Succession } from '../src/succession.js';
import { DAY_MS, T0, heirKeys, key, manualClock, tempDir } from './helpers.js';

const owner = key('owner-primary');
const heirs = heirKeys(['ann', 'bob', 'cy']);

interface Store {
  readonly dir: string;
  readonly clock: ReturnType<typeof manualClock>;
  readonly succession: Succession;
}

async function makeStore(
  options: { dir?: string; notBefore?: number | null; threshold?: number } = {}
): Promise<Store> {
  const dir = options.dir ?? (await tempDir());
  const clock = manualClock(T0);
  const succession = await Succession.open({
    dir,
    ownerKey: owner,
    now: clock.now,
    policy: {
      heirs: heirs.map((heir) => ({ id: heir.keyId, publicKey: heir.publicKey })),
      threshold: options.threshold ?? 2,
      dormantAfterDays: 90,
      notBefore: options.notBefore ?? null,
      createdAt: T0,
    },
  });
  return { dir, clock, succession };
}

function sharesFor(
  succession: Succession,
  requestId: string,
  at: number,
  signers: readonly { keyId: string; privateKey: string }[] = [heirs[0], heirs[1]]
) {
  const payload = claimPayload(succession.policyId, requestId, at);
  return signers.map((heir) => ({
    heirId: heir.keyId,
    sig: signBytes(heir.privateKey, payload),
  }));
}

describe('opening a store', () => {
  it('writes policy, state, system key and a genesis receipt', async () => {
    const { dir, succession } = await makeStore();
    const files = await readdir(dir);
    expect(files).toEqual(expect.arrayContaining(['policy.json', 'state.json', 'system-key.json']));
    const report = await succession.verify();
    expect(report.receipts).toHaveLength(1);
    expect(report.receipts[0].body.action).toBe('succession.policy.sealed');
    expect(report.head).toBe(report.receipts[0].id);
    expect(report.ownerKeyFingerprint).toHaveLength(32);
    expect(report.systemKeyFingerprint).toHaveLength(32);
  });

  it('reopens the same store and re-verifies the chain', async () => {
    const { dir, succession } = await makeStore();
    const again = await Succession.open({ dir, now: () => T0 });
    expect(again.policyId).toBe(succession.policyId);
    expect((await again.verify()).head).toBe((await succession.verify()).head);
  });

  it('refuses to create a store with no policy and no owner key', async () => {
    const dir = await tempDir();
    await expect(Succession.open({ dir })).rejects.toMatchObject({ code: 'invalid-policy' });
  });

  it('refuses to seal an unsigned draft without the owner key', async () => {
    const dir = await tempDir();
    await expect(
      Succession.open({
        dir,
        policy: {
          heirs: [{ id: 'ann', publicKey: heirs[0].publicKey }],
          threshold: 1,
          dormantAfterDays: 30,
        },
      })
    ).rejects.toMatchObject({ code: 'unauthorised' });
  });

  it('refuses an owner key that is not the policy owner', async () => {
    const { dir } = await makeStore();
    const stranger = key('stranger');
    await expect(Succession.open({ dir, ownerKey: stranger, now: () => T0 })).rejects.toMatchObject(
      { code: 'unauthorised' }
    );
  });
});

describe('owner heartbeats', () => {
  it('moves the last-seen time and records a receipt', async () => {
    const { clock, succession } = await makeStore();
    clock.add(10 * DAY_MS);
    const receipt = await succession.heartbeat();
    expect(receipt.body.action).toBe(ACTION_HEARTBEAT);
    const status = await succession.status();
    expect(status.lastSeenAt).toBe(clock.now());
    expect(status.phase).toBe('active');
    expect(
      (await succession.history()).some((entry) => entry.body.action === ACTION_HEARTBEAT)
    ).toBe(true);
  });

  it('refuses a heartbeat that goes backwards in time', async () => {
    const { clock, succession } = await makeStore();
    clock.add(10 * DAY_MS);
    await succession.heartbeat();
    await expect(succession.heartbeat({ at: T0 + DAY_MS })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses heartbeats on a read-only reopen', async () => {
    const { dir } = await makeStore();
    const readonly = await Succession.open({ dir, now: () => T0 });
    await expect(readonly.heartbeat()).rejects.toMatchObject({ code: 'unauthorised' });
  });
});

describe('heir claims', () => {
  it('refuses while the owner is active, and still writes the denial', async () => {
    const { clock, succession } = await makeStore();
    clock.add(10 * DAY_MS);
    const at = clock.now();
    await expect(
      succession.claim({
        requestId: 'estate-open-1',
        at,
        shares: sharesFor(succession, 'estate-open-1', at),
      })
    ).rejects.toMatchObject({ code: 'not-dormant' });

    const history = await succession.history();
    const denial = history.find((entry) => entry.body.action === ACTION_DENIED);
    expect(denial?.body.meta?.code).toBe('not-dormant');
  });

  it('refuses during dormancy when an absolute time-lock has not passed', async () => {
    const { clock, succession } = await makeStore({ notBefore: T0 + 400 * DAY_MS });
    clock.add(200 * DAY_MS);
    const at = clock.now();
    await expect(
      succession.claim({
        requestId: 'estate-open-1',
        at,
        shares: sharesFor(succession, 'estate-open-1', at),
      })
    ).rejects.toMatchObject({ code: 'too-early' });
  });

  it('grants once the window is open and consumes the request id', async () => {
    const { clock, succession } = await makeStore();
    clock.add(91 * DAY_MS);
    const at = clock.now();
    const grant = await succession.claim({
      requestId: 'estate-open-1',
      at,
      shares: sharesFor(succession, 'estate-open-1', at),
      purpose: 'estate handover',
    });

    expect(grant.holders).toEqual(['ann', 'bob']);
    expect(grant.receipt.body.action).toBe(ACTION_GRANTED);
    expect(grant.receipt.body.meta?.custodyToken).toBe(grant.custodyToken);
    expect(grant.status.phase).toBe('window-open');

    await expect(
      succession.claim({
        requestId: 'estate-open-1',
        at: at + DAY_MS,
        shares: sharesFor(succession, 'estate-open-1', at + DAY_MS),
      })
    ).rejects.toMatchObject({ code: 'replay' });
  });

  it('refuses an under-threshold claim', async () => {
    const { clock, succession } = await makeStore();
    clock.add(91 * DAY_MS);
    const at = clock.now();
    await expect(
      succession.claim({
        requestId: 'estate-open-1',
        at,
        shares: sharesFor(succession, 'estate-open-1', at, [heirs[0]]),
      })
    ).rejects.toMatchObject({ code: 'insufficient-shares' });
  });

  it('keeps working when only a quorum of heirs still holds a key', async () => {
    const { clock, succession } = await makeStore({ threshold: 3 });
    clock.add(91 * DAY_MS);
    const at = clock.now();
    await expect(
      succession.claim({
        requestId: 'estate-open-1',
        at,
        shares: sharesFor(succession, 'estate-open-1', at, [heirs[0], heirs[2]]),
      })
    ).rejects.toMatchObject({ code: 'insufficient-shares' });

    const grant = await succession.claim({
      requestId: 'estate-open-2',
      at,
      shares: sharesFor(succession, 'estate-open-2', at, heirs),
    });
    expect(grant.holders).toEqual(['ann', 'bob', 'cy']);
  });
});

describe('tamper detection', () => {
  it('refuses to open when a receipt was edited', async () => {
    const { dir, succession } = await makeStore();
    const head = (await succession.verify()).head!;
    const path = join(dir, 'receipts', `${head}.json`);
    const receipt = JSON.parse(await readFile(path, 'utf8')) as {
      body: { at: number };
    };
    receipt.body.at += 1;
    await writeFile(path, JSON.stringify(receipt), 'utf8');

    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'bad-signature',
    });
  });

  it('refuses a head that points at a receipt that is not stored', async () => {
    const { dir } = await makeStore();
    const statePath = join(dir, 'state.json');
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>;
    state.head = 'a'.repeat(64);
    await writeFile(statePath, JSON.stringify(state), 'utf8');

    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'rollback',
    });
  });

  it('refuses a policy whose state file was deleted', async () => {
    const { dir } = await makeStore();
    await unlink(join(dir, 'state.json'));
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses state that belongs to another policy', async () => {
    const { dir } = await makeStore();
    const statePath = join(dir, 'state.json');
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>;
    state.policyId = 'f'.repeat(64);
    await writeFile(statePath, JSON.stringify(state), 'utf8');

    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses state that is not valid JSON', async () => {
    const { dir } = await makeStore();
    await writeFile(join(dir, 'state.json'), 'not json', 'utf8');
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses to answer when the decision cannot be recorded', async () => {
    const { clock, succession, dir } = await makeStore();
    clock.add(10 * DAY_MS);
    // Replace the state file with a directory so the write-rename has nowhere to land.
    await rm(join(dir, 'state.json'));
    await mkdir(join(dir, 'state.json'));

    await expect(succession.heartbeat()).rejects.toMatchObject({ code: 'receipt-required' });
  });

  it('refuses a system key that is missing from an existing store', async () => {
    const { dir } = await makeStore();
    await unlink(join(dir, 'system-key.json'));
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('reports one verification handle for the whole store', async () => {
    const { clock, succession } = await makeStore();
    clock.add(5 * DAY_MS);
    await succession.heartbeat();
    const report = await succession.verify();
    expect(report.receipts).toHaveLength(2);
    expect(report.heartbeats).toBe(1);
    expect(report.head).toBe(report.receipts[1].id);
    expect(report.status.elapsedDays).toBe(0);
  });

  it('refuses a claim time that is not an instant', async () => {
    const { clock, succession } = await makeStore();
    clock.add(91 * DAY_MS);
    await expect(
      succession.claim({ requestId: 'estate-open-1', at: -1, shares: [] })
    ).rejects.toMatchObject({ code: 'invalid-state' });
  });

  it('creates a store from an already sealed policy without the owner key', async () => {
    const dir = await tempDir();
    const sealed = sealPolicy(owner, {
      heirs: heirs.map((heir) => ({ id: heir.keyId, publicKey: heir.publicKey })),
      threshold: 2,
      dormantAfterDays: 90,
      createdAt: T0,
    });
    const succession = await Succession.open({ dir, policy: sealed, now: () => T0 });
    expect(succession.policyId).toBe(sealed.policyId);
    // Read-only: without the owner key the clock cannot be moved.
    await expect(succession.heartbeat()).rejects.toMatchObject({ code: 'unauthorised' });
  });

  it('accepts a sealed policy together with its owner key', async () => {
    const dir = await tempDir();
    const sealed = sealPolicy(owner, {
      heirs: heirs.map((heir) => ({ id: heir.keyId, publicKey: heir.publicKey })),
      threshold: 2,
      dormantAfterDays: 30,
      createdAt: T0,
    });
    const succession = await Succession.open({
      dir,
      policy: sealed,
      ownerKey: owner,
      now: () => T0,
    });
    await expect(succession.heartbeat({ at: T0 + DAY_MS })).resolves.toBeDefined();
  });

  it('refuses a policy path that cannot be read', async () => {
    const dir = await tempDir();
    await mkdir(join(dir, 'policy.json'));
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-policy',
    });
  });

  it('grants a claim that carries no purpose', async () => {
    const { clock, succession } = await makeStore();
    clock.add(91 * DAY_MS);
    const at = clock.now();
    const grant = await succession.claim({
      requestId: 'estate-open-7',
      at,
      shares: sharesFor(succession, 'estate-open-7', at),
    });
    expect(grant.receipt.body.meta?.purpose).toBeUndefined();
  });

  it('exposes the system public key for offline trust', async () => {
    const { succession } = await makeStore();
    expect(succession.systemPublicKey).toContain('BEGIN PUBLIC KEY');
    expect(succession.policy.heirs).toHaveLength(3);
    expect(succession.policyId).toHaveLength(64);
  });

  it('refuses state files that are the wrong shape', async () => {
    const cases: unknown[] = [
      5,
      { v: 2, policyId: 'x', head: null, used: [] },
      { v: 1, head: null, used: [] },
      { v: 1, policyId: 'x', head: 5, used: [] },
      { v: 1, policyId: 'x', head: null, used: 'x' },
    ];
    for (const value of cases) {
      const { dir } = await makeStore();
      await writeFile(join(dir, 'state.json'), JSON.stringify(value), 'utf8');
      await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
        code: 'invalid-state',
      });
    }
  });

  it('refuses a head that is not a receipt id', async () => {
    const { dir } = await makeStore();
    const statePath = join(dir, 'state.json');
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>;
    state.head = 'not-a-digest';
    await writeFile(statePath, JSON.stringify(state), 'utf8');
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses a stored receipt that is not a receipt', async () => {
    const { dir, succession } = await makeStore();
    const head = (await succession.verify()).head!;
    await writeFile(join(dir, 'receipts', `${head}.json`), JSON.stringify({ x: 1 }), 'utf8');
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses a malformed system key', async () => {
    const { dir } = await makeStore();
    await writeFile(join(dir, 'system-key.json'), JSON.stringify({ keyId: 'x' }), 'utf8');
    await expect(Succession.open({ dir, now: () => T0 })).rejects.toMatchObject({
      code: 'invalid-state',
    });
  });

  it('refuses to deny a claim it cannot record', async () => {
    const { clock, succession, dir } = await makeStore();
    clock.add(1 * DAY_MS);
    await rm(join(dir, 'state.json'));
    await mkdir(join(dir, 'state.json'));
    const at = clock.now();
    await expect(
      succession.claim({
        requestId: 'estate-open-9',
        at,
        shares: sharesFor(succession, 'estate-open-9', at),
      })
    ).rejects.toMatchObject({ code: 'receipt-required' });
  });
});
