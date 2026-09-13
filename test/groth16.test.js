import assert from "node:assert/strict";
import test from "node:test";
import { Groth16Guardrail, verificationKeyHash } from "../src/groth16.js";
import { PublicSignalSchema } from "../src/signals.js";

const schema = new PublicSignalSchema(["merkleRoot", "recipient", "fee"]);
const verificationKey = { protocol: "groth16", curve: "bn128", nPublic: 3, id: "test-key" };
const manifest = {
  protocol: "groth16", curve: "bn128", circuitId: "demo", circuitVersion: "1.0.0",
  publicSignalOrder: ["merkleRoot", "recipient", "fee"],
};
const context = { merkleRoot: "101", recipient: "202", fee: "3" };
const proof = { pi_a: ["1", "2", "1"], pi_b: [["1", "2"], ["3", "4"], ["1", "0"]], pi_c: ["5", "6", "1"] };

function guardrail(overrides = {}) {
  const calls = [];
  const verifier = { verify: async (...args) => { calls.push(args); return overrides.result ?? true; } };
  return {
    calls,
    guard: new Groth16Guardrail({
      verifier: overrides.verifier ?? verifier,
      verificationKey,
      expectedVerificationKeyHash: verificationKeyHash(verificationKey),
      schema,
      manifest,
      ...overrides.construct,
    }),
  };
}

test("an honest proof verifies and reports what was verified", async () => {
  const { guard, calls } = guardrail();
  const result = await guard.verify({ proof, publicSignals: ["101", "202", "3"], expectedSignals: context });
  assert.equal(result.verified, true);
  assert.equal(result.circuitId, "demo");
  assert.match(result.proofHash, /^[0-9a-f]{64}$/);
  assert.deepEqual(result.signals, context);
  // The verifier sees the canonical signals in schema order, never the raw input.
  assert.deepEqual(calls[0][1], ["101", "202", "3"]);
});

test("signals that do not match the authorized context are rejected by name", async () => {
  const { guard } = guardrail();
  await assert.rejects(guard.verify({ proof, publicSignals: ["101", "999", "3"], expectedSignals: context }),
    (error) => error.code === "PUBLIC_SIGNAL_MISMATCH" && /recipient/.test(error.message));
});

test("reordered signals are rejected even though the multiset is identical", async () => {
  const { guard } = guardrail();
  await assert.rejects(guard.verify({ proof, publicSignals: ["202", "101", "3"], expectedSignals: context }),
    { code: "PUBLIC_SIGNAL_MISMATCH" });
});

test("non-canonical or out-of-field signals never reach the verifier", async () => {
  const { guard, calls } = guardrail();
  for (const bad of [["0101", "202", "3"], ["101", "0x202", "3"], ["101", "202", " 3"], ["101", "202", ""]]) {
    await assert.rejects(guard.verify({ proof, publicSignals: bad, expectedSignals: context }),
      { code: "INVALID_FIELD_ELEMENT" });
  }
  const field = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
  await assert.rejects(guard.verify({ proof, publicSignals: [field, "202", "3"], expectedSignals: context }),
    { code: "INVALID_FIELD_ELEMENT" });
  assert.equal(calls.length, 0);
});

test("the wrong number of signals is rejected", async () => {
  const { guard } = guardrail();
  await assert.rejects(guard.verify({ proof, publicSignals: ["101", "202"], expectedSignals: context }),
    { code: "INVALID_PUBLIC_SIGNALS" });
  await assert.rejects(guard.verify({ proof, publicSignals: ["101", "202", "3", "4"], expectedSignals: context }),
    { code: "INVALID_PUBLIC_SIGNALS" });
});

test("a verifier that fails, throws or answers anything but true is a rejection", async () => {
  const falsy = guardrail({ result: false });
  await assert.rejects(falsy.guard.verify({ proof, publicSignals: ["101", "202", "3"], expectedSignals: context }),
    { code: "INVALID_PROOF" });
  const truthy = guardrail({ result: "true" });
  await assert.rejects(truthy.guard.verify({ proof, publicSignals: ["101", "202", "3"], expectedSignals: context }),
    { code: "INVALID_PROOF" });
  const throwing = guardrail({ verifier: { verify: async () => { throw new Error("worker died"); } } });
  await assert.rejects(throwing.guard.verify({ proof, publicSignals: ["101", "202", "3"], expectedSignals: context }),
    { code: "VERIFIER_UNAVAILABLE" });
});

test("a swapped verification key or manifest is refused at construction", () => {
  assert.throws(() => new Groth16Guardrail({
    verifier: { verify: async () => true }, verificationKey: { ...verificationKey, id: "other" },
    expectedVerificationKeyHash: verificationKeyHash(verificationKey), schema, manifest,
  }), { code: "VERIFICATION_KEY_HASH_MISMATCH" });

  assert.throws(() => new Groth16Guardrail({
    verifier: { verify: async () => true }, verificationKey,
    expectedVerificationKeyHash: verificationKeyHash(verificationKey), schema,
    manifest: { ...manifest, publicSignalOrder: ["recipient", "merkleRoot", "fee"] },
  }), { code: "SIGNAL_ORDER_MISMATCH" });

  assert.throws(() => new Groth16Guardrail({
    verifier: { verify: async () => true }, verificationKey,
    expectedVerificationKeyHash: verificationKeyHash(verificationKey), schema,
    manifest, expectedManifestHash: "0".repeat(64),
  }), { code: "MANIFEST_HASH_MISMATCH" });

  assert.throws(() => new Groth16Guardrail({
    verifier: { verify: async () => true }, verificationKey,
    expectedVerificationKeyHash: verificationKeyHash(verificationKey), schema,
    manifest: { ...manifest, curve: "bls12-381" },
  }), { code: "INVALID_MANIFEST" });
});

test("a proof package that is not an object is refused", async () => {
  const { guard } = guardrail();
  for (const bad of [null, "proof", ["a"]]) {
    await assert.rejects(guard.verify({ proof: bad, publicSignals: ["101", "202", "3"], expectedSignals: context }),
      { code: "INVALID_PROOF_PACKAGE" });
  }
});

test("the guardrail holds its own copies of the key and manifest", async () => {
  const key = { ...verificationKey };
  const guard = new Groth16Guardrail({
    verifier: { verify: async (vk) => vk.id === "test-key" }, verificationKey: key,
    expectedVerificationKeyHash: verificationKeyHash(key), schema, manifest,
  });
  key.id = "mutated-after-construction";
  const result = await guard.verify({ proof, publicSignals: ["101", "202", "3"], expectedSignals: context });
  assert.equal(result.verified, true);
});
