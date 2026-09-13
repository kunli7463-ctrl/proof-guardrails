# Security policy

## Reporting

Please report vulnerabilities privately through the repository's Security tab
("Report a vulnerability") rather than as a public issue. Include what an
attacker gains, the affected version or commit, and a reproduction if you have
one.

## What this library claims

A report is most useful when it breaks one of these:

- A `verify` call cannot reach the verifier unless every public signal is a
  canonical BN254 field element and equals the authorized context by name.
- A `Groth16Guardrail` cannot be constructed with a verification key that does
  not hash to the pinned value, or a manifest whose signal order disagrees with
  the schema.
- Only a verifier result of exactly `true` is a pass; a throw, a timeout or any
  other value is a rejection.
- `append` refuses a state whose frontier does not reproduce the supplied
  `expectedRoot`, and the returned root equals a full recomputation of the tree.
- `poseidon3` agrees with circomlib `Poseidon(3)` over BN254.

## What it does not claim

It performs no pairing checks and does not validate proof-point membership —
that is your verifier's job. It cannot know whether your circuit constrains
what you believe it constrains, and it does not audit circuits. Domain tags,
tree depth and signal order are your responsibility to match to the circuit.
