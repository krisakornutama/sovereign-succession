import {
  AttestError,
  createSigningKey,
  openReceipt,
  publicKeyFingerprint,
  publicKeyMatches,
  sealReceipt,
  type Receipt,
  type SigningKey,
} from 'sovereign-attest';
import { custodyToken, evaluateClaim, refusalError, type ClaimInput } from './claim.js';
import {
  ACTION_DENIED,
  ACTION_GRANTED,
  ACTION_HEARTBEAT,
  ACTION_POLICY_SEALED,
  DormancyClock,
  type SuccessionStatus,
} from './clock.js';
import { SuccessionError } from './errors.js';
import {
  openPolicy,
  policyIdOf,
  sealPolicy,
  type SuccessionPolicy,
  type SuccessionPolicyBody,
  type SuccessionPolicyInput,
} from './policy.js';
import * as store from './store.js';

export interface SuccessionOpenOptions {
  /** Directory that holds policy.json, state.json, the system key and receipts/. */
  readonly dir: string;
  /** Supplied only when creating; a stored policy always wins and is re-verified. */
  readonly policy?: SuccessionPolicy | SuccessionPolicyInput;
  /** The owner's signing key: needed to create a policy and to heartbeat, never to claim. */
  readonly ownerKey?: SigningKey;
  /** Injectable clock so tests and offline audits are deterministic. */
  readonly now?: () => number;
}

export interface HeartbeatInput {
  readonly at?: number;
}

export interface ClaimGrant {
  readonly policyId: string;
  readonly requestId: string;
  readonly holders: readonly string[];
  /** Opaque handle for later follow-up; not a data key (M1 does not unwrap anything). */
  readonly custodyToken: string;
  readonly receipt: Receipt;
  readonly status: SuccessionStatus;
}

export interface SuccessionVerifyReport {
  readonly policyId: string;
  readonly head: string | null;
  readonly receipts: readonly Receipt[];
  readonly heartbeats: number;
  readonly status: SuccessionStatus;
  readonly ownerKeyFingerprint: string;
  readonly systemKeyFingerprint: string;
}

function isSealedPolicy(value: unknown): value is SuccessionPolicy {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<SuccessionPolicy>;
  const body: unknown = candidate.body;
  return (
    typeof candidate.policyId === 'string' &&
    typeof candidate.sig === 'string' &&
    typeof body === 'object' &&
    body !== null
  );
}

/**
 * Walks the receipt chain from the head back to genesis, verifying every signature,
 * every link and the policy it claims to be about. Any deviation is `rollback`:
 * a rewritten head, a swapped receipt, a missing link or a receipt from another policy.
 */
async function verifyChain(
  dir: string,
  policyId: string,
  body: SuccessionPolicyBody,
  systemKey: SigningKey,
  head: string | null
): Promise<Receipt[]> {
  const trust = {
    trustedKeys: {
      [body.owner.keyId]: body.owner.publicKey,
      [systemKey.keyId]: systemKey.publicKey,
    },
  };
  const chain: Receipt[] = [];
  const seen = new Set<string>();
  let next = head;

  while (next !== null) {
    if (seen.has(next)) {
      throw new SuccessionError('rollback', `chain repeats receipt ${next}`);
    }
    seen.add(next);
    const receipt = await store.loadReceiptFile(dir, next);
    if (!receipt) {
      throw new SuccessionError('rollback', `chain points at receipt ${next}, which is not stored`);
    }
    try {
      openReceipt(receipt, trust);
    } catch (error) {
      if (error instanceof AttestError) {
        throw new SuccessionError('bad-signature', error.message, { cause: error });
      }
      throw error;
    }
    if (receipt.body.artifact.sha256 !== policyId) {
      throw new SuccessionError('rollback', `receipt ${next} belongs to another policy`);
    }
    chain.push(receipt);
    next = receipt.body.prev;
  }

  chain.reverse();
  for (let index = 1; index < chain.length; index += 1) {
    if (chain[index].body.at < chain[index - 1].body.at) {
      throw new SuccessionError('rollback', 'chain timestamps move backwards');
    }
  }
  return chain;
}

/**
 * Heir access by policy, entirely offline.
 *
 * - The owner proves presence with signed heartbeats; silence for `dormantAfterDays`
 *   (and passing `notBefore`) opens the successor window.
 * - An open window still needs `threshold` distinct, non-revoked heir signatures over
 *   one exact claim, so a single stolen heir key is not enough.
 * - Every grant and every refusal is a signed receipt in the same chain, written before
 *   the decision is returned: no receipt means no answer.
 */
export class Succession {
  private readonly dir: string;
  private readonly body: SuccessionPolicyBody;
  private readonly ownerKey: SigningKey | null;
  private readonly systemKey: SigningKey;
  private readonly clockNow: () => number;
  private state: store.SuccessionState;

  private constructor(options: {
    dir: string;
    body: SuccessionPolicyBody;
    ownerKey: SigningKey | null;
    systemKey: SigningKey;
    state: store.SuccessionState;
    clockNow: () => number;
  }) {
    this.dir = options.dir;
    this.body = options.body;
    this.ownerKey = options.ownerKey;
    this.systemKey = options.systemKey;
    this.state = options.state;
    this.clockNow = options.clockNow;
  }

  /**
   * Opens (or creates) a succession store. A stored policy and state are re-verified
   * before anything else runs, so a tampered directory fails here rather than later.
   */
  static async open(options: SuccessionOpenOptions): Promise<Succession> {
    if (typeof options.dir !== 'string' || options.dir.trim().length === 0) {
      throw new SuccessionError('invalid-state', 'dir is required');
    }
    const dir = options.dir;
    const now = options.now ?? Date.now;
    await store.ensureStore(dir);

    const stored = await store.loadPolicyFile(dir);
    let body: SuccessionPolicyBody;

    if (stored !== null) {
      body = openPolicy(stored, options.ownerKey?.publicKey);
    } else {
      const input = options.policy;
      if (input === undefined) {
        throw new SuccessionError(
          'invalid-policy',
          'no policy stored; pass one to create the store'
        );
      }
      let sealed: SuccessionPolicy;
      if (isSealedPolicy(input)) {
        body = openPolicy(input, options.ownerKey?.publicKey);
        sealed = input;
      } else {
        if (!options.ownerKey) {
          throw new SuccessionError(
            'unauthorised',
            'creating a policy from an unsigned draft needs the owner signing key'
          );
        }
        sealed = sealPolicy(options.ownerKey, {
          ...input,
          createdAt: input.createdAt ?? now(),
        });
        body = sealed.body;
      }
      await store.savePolicyFile(dir, sealed);
    }

    if (options.ownerKey && !publicKeyMatches(options.ownerKey.publicKey, body.owner.publicKey)) {
      throw new SuccessionError('unauthorised', 'owner key does not match the policy owner');
    }

    const policyId = policyIdOf(body);
    let state = await store.loadStateFile(dir);
    if (state === null && stored !== null) {
      // A policy without its pointer file is not a new store: it is a deleted state.
      throw new SuccessionError('invalid-state', 'policy exists but state.json is missing');
    }
    const systemKey =
      state === null
        ? createSigningKey('succession-system', now())
        : await store.loadSystemKey(dir);

    if (state !== null && state.policyId !== policyId) {
      throw new SuccessionError('invalid-state', 'state belongs to a different policy');
    }

    if (state === null) {
      await store.saveSystemKey(dir, systemKey);
      const genesis = sealReceipt(systemKey, {
        action: ACTION_POLICY_SEALED,
        actor: 'system',
        artifact: { name: 'succession/policy', sha256: policyId },
        at: now(),
        prev: null,
        meta: {
          owner: body.owner.keyId,
          heirs: body.heirs.length,
          threshold: body.threshold,
          dormantAfterDays: body.dormantAfterDays,
        },
      });
      try {
        await store.saveReceiptFile(dir, genesis);
      } catch (error) {
        throw new SuccessionError(
          'receipt-required',
          'genesis receipt could not be written; refusing to open a store without it',
          { cause: error }
        );
      }
      state = { v: 1, policyId, head: genesis.id, used: [] };
      await store.saveStateFile(dir, state);
    }

    const instance = new Succession({
      dir,
      body,
      ownerKey: options.ownerKey ?? null,
      systemKey,
      state,
      clockNow: now,
    });
    // Fail closed on a tampered directory before returning a usable instance.
    await instance.chain();
    return instance;
  }

  get policy(): SuccessionPolicyBody {
    return this.body;
  }

  get policyId(): string {
    return policyIdOf(this.body);
  }

  get systemPublicKey(): string {
    return this.systemKey.publicKey;
  }

  private async chain(): Promise<Receipt[]> {
    return verifyChain(this.dir, this.policyId, this.body, this.systemKey, this.state.head);
  }

  private clockFor(chain: readonly Receipt[]): DormancyClock {
    return new DormancyClock({ policy: this.body, receipts: chain, head: this.state.head });
  }

  /** Writes the receipt first, then moves the head: a crash never produces a head that points nowhere. */
  private async persist(receipt: Receipt, consume: string | null): Promise<void> {
    try {
      await store.saveReceiptFile(this.dir, receipt);
      this.state = {
        v: 1,
        policyId: this.state.policyId,
        head: receipt.id,
        used: consume === null ? this.state.used : [...this.state.used, consume],
      };
      await store.saveStateFile(this.dir, this.state);
    } catch (error) {
      throw new SuccessionError(
        'receipt-required',
        'receipt or state could not be written; refusing to answer without a record',
        { cause: error }
      );
    }
  }

  /** The owner proving they are still here. Only the newest heartbeat can move the clock. */
  async heartbeat(input: HeartbeatInput = {}): Promise<Receipt> {
    if (!this.ownerKey) {
      throw new SuccessionError('unauthorised', 'heartbeats need the owner signing key');
    }
    const at = input.at ?? this.clockNow();
    const chain = await this.chain();
    const lastSeenAt = this.clockFor(chain).lastSeenAt;
    if (at < lastSeenAt) {
      throw new SuccessionError(
        'invalid-state',
        `heartbeat at ${at} predates the newest heartbeat (${lastSeenAt})`
      );
    }
    const receipt = sealReceipt(this.ownerKey, {
      action: ACTION_HEARTBEAT,
      actor: this.body.owner.keyId,
      artifact: { name: 'succession/policy', sha256: this.policyId },
      at,
      prev: this.state.head,
      meta: { owner: this.body.owner.keyId },
    });
    await this.persist(receipt, null);
    return receipt;
  }

  /** Where the succession stands at `now` (defaults to the injected clock). */
  async status(now?: number): Promise<SuccessionStatus> {
    const chain = await this.chain();
    return this.clockFor(chain).status(now ?? this.clockNow());
  }

  /**
   * Decides a claim. Success and refusal both leave a signed receipt, and the refusal
   * is thrown only after that receipt exists — so an unrecorded decision cannot happen.
   */
  async claim(input: ClaimInput): Promise<ClaimGrant> {
    const chain = await this.chain();
    const clock = this.clockFor(chain);
    const status = clock.status(input.at);
    const evaluation = evaluateClaim({
      policy: this.body,
      status,
      used: this.state.used,
      claim: input,
    });

    const recordAt = Number.isInteger(input.at) && input.at >= 0 ? input.at : undefined;

    if (!evaluation.ok) {
      const denial = sealReceipt(this.systemKey, {
        action: ACTION_DENIED,
        actor: 'system',
        artifact: { name: 'succession/policy', sha256: this.policyId },
        at: this.denialTime(input.at, chain),
        prev: this.state.head,
        meta: {
          requestId: typeof input.requestId === 'string' ? input.requestId.slice(0, 64) : 'invalid',
          code: evaluation.code ?? 'invalid-claim',
          holders: evaluation.holders.join(','),
          ...(recordAt === undefined ? {} : { claimAt: recordAt }),
        },
      });
      try {
        await this.persist(denial, null);
      } catch (error) {
        throw new SuccessionError(
          'receipt-required',
          'denial receipt could not be written; refusing silently is not allowed',
          { cause: error }
        );
      }
      throw refusalError(evaluation);
    }

    const token = custodyToken(this.policyId, input.requestId, evaluation.holders);
    const grant = sealReceipt(this.systemKey, {
      action: ACTION_GRANTED,
      actor: 'system',
      artifact: { name: 'succession/policy', sha256: this.policyId },
      at: this.denialTime(input.at, chain),
      prev: this.state.head,
      meta: {
        requestId: input.requestId,
        holders: evaluation.holders.join(','),
        custodyToken: token,
        ...(recordAt === undefined ? {} : { claimAt: recordAt }),
        ...(input.purpose === undefined ? {} : { purpose: input.purpose.slice(0, 200) }),
      },
    });
    await this.persist(grant, input.requestId);

    return {
      policyId: this.policyId,
      requestId: input.requestId,
      holders: evaluation.holders,
      custodyToken: token,
      receipt: grant,
      status,
    };
  }

  /** Receipt time for a decision: never before the newest link, so the chain stays monotonic. */
  private denialTime(claimAt: number, chain: readonly Receipt[]): number {
    const newest = chain.length === 0 ? 0 : chain[chain.length - 1].body.at;
    const now = this.clockNow();
    const sane = Number.isInteger(claimAt) && claimAt >= 0 ? claimAt : now;
    return Math.max(newest, sane, 0);
  }

  async history(): Promise<readonly Receipt[]> {
    return this.chain();
  }

  /** One call an auditor can make offline: chain verified, clock derived, both keys named. */
  async verify(): Promise<SuccessionVerifyReport> {
    const chain = await this.chain();
    const clock = this.clockFor(chain);
    return {
      policyId: this.policyId,
      head: this.state.head,
      receipts: chain,
      heartbeats: clock.heartbeats().length,
      status: clock.status(this.clockNow()),
      ownerKeyFingerprint: publicKeyFingerprint(this.body.owner.publicKey),
      systemKeyFingerprint: publicKeyFingerprint(this.systemKey.publicKey),
    };
  }
}
