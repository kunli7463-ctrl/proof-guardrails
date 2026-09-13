# proof-guardrails

**A verified proof is not a verified transaction.** This is the small layer in
between: pinned verification keys, public signals bound by name to the context
your application authorized, and Merkle roots you recompute instead of trust.

Zero dependencies. Node 20+. Apache-2.0.

## The failures it is built to prevent

| What the verifier tells you | What it does not tell you | What this library does |
|---|---|---|
| "This proof is valid for these 13 numbers" | That the third number is the recipient and not the fee | Names every signal position once, compares by name |
| "Valid" | That those numbers describe the transaction you authorized | Refuses to call the verifier unless every signal equals the authorized context |
| "Valid" | Which key it used | Refuses to start unless the key hashes to the value you pinned |
| Nothing at all | Whether `"05"`, `"0x5"` and `"5 "` are the same signal | Canonicalizes every field element and rejects the rest |
| Nothing at all | Whether the new Merkle root is the real one | Recomputes the root from a frontier and the appended leaves |

Each row is a real bug class, not a hypothetical: a proof accepted for the
wrong context, a swapped key, a root taken on trust. The library's own test
suite attacks each one — reordered signals, non-canonical encodings,
out-of-field values, swapped keys and manifests, a verifier that throws or
returns something truthy but not `true`, a tampered frontier.

## Install

Not on npm yet. Clone it, or vendor `src/` — it is five files and no dependencies.

```sh
git clone https://github.com/kunli7463-ctrl/proof-guardrails.git
cd proof-guardrails && node --test
```

## Bind a proof to its context

```js
import { Groth16Guardrail, PublicSignalSchema, verificationKeyHash } from "./proof-guardrails/index.js";
import * as snarkjs from "snarkjs";

const schema = new PublicSignalSchema(["merkleRoot", "recipient", "fee"]);

const guard = new Groth16Guardrail({
  verifier: { verify: snarkjs.groth16.verify },
  verificationKey,                                   // parsed verification_key.json
  expectedVerificationKeyHash: "…",                  // pinned at review time
  schema,
  manifest,                                          // optional: protocol, curve, circuit id/version, signal order
});

// `expectedSignals` is what your application decided, before it saw any proof.
const receipt = await guard.verify({
  proof,
  publicSignals,                                     // positional, straight from the prover
  expectedSignals: { merkleRoot: "…", recipient: "…", fee: "…" },
});

// receipt: { verified, signals, proofHash, publicSignalsHash, verificationKeyHash, … }
```

If a signal disagrees with the authorized context, `verify` throws
`PUBLIC_SIGNAL_MISMATCH` naming the signal — before the pairing check runs.
The returned hashes are what you store next to the transaction so an auditor
can tell later exactly what was verified.

## Keep an append-only Merkle root honest

```js
import { createMerkleFrontier } from "./proof-guardrails/index.js";

const merkle = createMerkleFrontier({
  leafDomain: 0x4c454146n,   // match your circuit's domain tags
  nodeDomain: 0x4e4f4445n,
  depth: 32,
});

let state = merkle.empty();                                   // { treeSize, frontier, root }
state = merkle.append({ ...state, expectedRoot: state.root }, [
  merkle.leaf(commitmentX, commitmentY).toString(),
]);
```

The state is `depth + 1` field elements, not the tree: for every set bit `i` of
the size, `frontier[i]` is the root of the complete left subtree at that level.
That is enough to recompute the root, verify a published one, and replay an
append — without storing or re-reading the leaves. Passing `expectedRoot` makes
the append refuse a state whose frontier does not reproduce the root you have
on record.

`poseidon3` is a dependency-free implementation of circomlib's `Poseidon(3)`
over BN254, pinned by known-answer vectors to `circomlibjs`, so a server can
recompute what the circuit computed without pulling a proving toolchain.

## Scope, and what it is not

- It does **not** implement pairing checks or any cryptography beyond Poseidon.
  You bring the verifier; the library decides when calling it is meaningful.
- It does **not** make an unaudited circuit safe. Binding signals correctly is
  worth nothing if the circuit does not constrain what you think it does.
- Domain tags, depth and signal order must match your circuit. The library
  enforces internal consistency, not agreement with a circuit it cannot see.
- BN254 only.

## Provenance

Extracted from the settlement path of a confidential-transfer control plane,
where these checks were introduced in response to an independent security
review: a published Merkle root that nothing recomputed, and public signals
that were not bound to the authorized recipient. Both were reproduced as
failing tests before the fix. This package is that hardening, generalized and
separated from the business system.

## Development

```sh
node --test          # 21 tests, no dependencies, no network
```

Security reports: see [SECURITY.md](SECURITY.md).
