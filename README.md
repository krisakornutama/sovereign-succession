# sovereign-succession

Heir access by policy for Sovereign OS — the part that answers one question offline:
**when the owner is gone, who may open the system, and how is that proven?**

- **The owner proves presence, not absence.** A signed heartbeat moves the clock forward. Silence
  for `dormantAfterDays` — and past any absolute `notBefore` time-lock — is the only thing that
  opens the successor window.
- **One heir is never enough.** A claim needs `threshold` distinct, non-revoked heir signatures over
  one exact payload (policy id, request id, instant), so a single stolen heir key cannot open anything.
- **Every decision is a receipt.** Grants _and_ refusals are Ed25519 receipts in one hash chain,
  written before the answer is returned. No receipt, no answer — the library has no path that decides
  without leaving a record.
- **Nothing to call home.** No server, no network, no clock service: the state is a directory of JSON
  files, and two machines with the same chain and the same `now` reach the same verdict.

## Quick start

```bash
npm ci
npm run build
npm run example     # owner heartbeats → 90 days of silence → 2-of-3 heirs claim
npm test
```

```ts
import { createSigningKey, signBytes } from 'sovereign-attest';
import { Succession, claimPayload } from 'sovereign-succession';

const succession = await Succession.open({
  dir: './estate',
  ownerKey,
  policy: {
    heirs: heirs.map((h) => ({ id: h.keyId, publicKey: h.publicKey })),
    threshold: 2,
    dormantAfterDays: 90,
  },
});

await succession.heartbeat(); // owner is alive today
const status = await succession.status(); // 'active' | 'dormant' | 'window-open'

const payload = claimPayload(succession.policyId, 'estate-2027', at);
const grant = await succession.claim({
  requestId: 'estate-2027',
  at,
  shares: heirs
    .slice(0, 2)
    .map((h) => ({ heirId: h.keyId, sig: signBytes(h.privateKey, payload) })),
});
```

## Refusal codes

| code                  | meaning                                                                               |
| --------------------- | ------------------------------------------------------------------------------------- |
| `invalid-policy`      | policy shape, id, signature or a pinned owner key does not hold up                    |
| `invalid-claim`       | request id, instant or shares are malformed                                           |
| `invalid-state`       | state file, system key or a receipt is missing or unreadable                          |
| `rollback`            | chain head points nowhere, repeats, moves backwards in time, or covers another policy |
| `bad-signature`       | a receipt or share does not verify                                                    |
| `unauthorised`        | the owner key supplied is not the policy owner, or a write needs it and it is absent  |
| `not-dormant`         | the owner's heartbeats are still current                                              |
| `too-early`           | dormancy reached, but the policy time-lock has not passed                             |
| `insufficient-shares` | fewer valid shares than the threshold                                                 |
| `unknown-heir`        | a share names an heir the policy does not contain                                     |
| `heir-revoked`        | a share names a revoked heir                                                          |
| `duplicate-share`     | the same heir signed twice                                                            |
| `bad-share`           | a share's signature is not for this claim                                             |
| `replay`              | the request id was already decided                                                    |
| `receipt-required`    | the receipt or state could not be written; the decision is withheld                   |

## What M1 does not do

- It decides **access** and proves it; it does **not** unwrap a data key. The `custodyToken` in a
  grant is a stable handle, not a key. Shipping the wrapped-key release is M2.
- No multi-channel delivery (4G / LoRa / satellite). The chain travels as a directory; moving it
  across transports is out of scope here.

## Design notes

- `policy.json` is signed by the owner key; its `policyId` is the SHA-256 of the canonical body, so a
  stored policy cannot be edited without breaking both the id and the signature.
- `state.json` holds only the head pointer and the consumed request ids. Deleting it is tampering,
  not a reset: a store with a policy but no state refuses to open.
- `system-key.json` (mode 600 where the OS allows) signs grants and refusals, so a claim never needs
  the owner to be online.
- Receipts are written before the head moves; a crash leaves an unreferenced receipt, never a head
  that points at nothing.

## License

MIT.
