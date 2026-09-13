// A Groth16 verification wrapper that fails closed.
//
// It does not implement pairing checks — you bring a verifier (snarkjs, a
// native binding, a remote service). What it does is refuse every call that
// would produce a meaningless "valid" answer:
//
//   * the verification key must hash to the value you pinned, so a swapped or
//     re-generated key is rejected rather than silently trusted;
//   * the artifact manifest must declare the same protocol, curve, circuit and
//     signal order that the application expects;
//   * the public signals must have the schema's exact length, be canonical
//     field elements, and match the context the application authorized;
//   * a verifier that throws, times out, or returns anything other than `true`
//     is a failure, never a pass.
//
// Every successful verification returns hashes of the proof and signals so the
// caller can record what was verified.

import { guardrailError } from "./field.js";
import { PublicSignalSchema, canonicalize, hashOf } from "./signals.js";

export function verificationKeyHash(verificationKey) {
  return hashOf(verificationKey);
}

export class Groth16Guardrail {
  /**
   * @param {object} options
   * @param {{verify: Function}} options.verifier  e.g. { verify: snarkjs.groth16.verify }
   * @param {object} options.verificationKey       the parsed verification key
   * @param {string} options.expectedVerificationKeyHash  sha256 you pinned at review time
   * @param {PublicSignalSchema} options.schema
   * @param {object} [options.manifest]            { protocol, curve, circuitId, circuitVersion, publicSignalOrder }
   * @param {string} [options.expectedManifestHash]
   */
  constructor({ verifier, verificationKey, expectedVerificationKeyHash, schema, manifest = null, expectedManifestHash = null }) {
    if (!verifier || typeof verifier.verify !== "function") {
      throw guardrailError("VERIFIER_REQUIRED", "a verifier with a verify(vk, signals, proof) function is required");
    }
    if (!(schema instanceof PublicSignalSchema)) {
      throw guardrailError("SCHEMA_REQUIRED", "a PublicSignalSchema is required");
    }
    const actualKeyHash = verificationKeyHash(verificationKey);
    if (!/^[0-9a-f]{64}$/.test(expectedVerificationKeyHash ?? "") || actualKeyHash !== expectedVerificationKeyHash) {
      throw guardrailError("VERIFICATION_KEY_HASH_MISMATCH", "verification key is not the pinned artifact");
    }
    if (manifest !== null) {
      if (manifest.protocol !== "groth16" || manifest.curve !== "bn128" || !manifest.circuitId || !manifest.circuitVersion) {
        throw guardrailError("INVALID_MANIFEST", "manifest must declare groth16/bn128, a circuit id and a version");
      }
      if (canonicalize(manifest.publicSignalOrder) !== canonicalize(schema.names)) {
        throw guardrailError("SIGNAL_ORDER_MISMATCH", "manifest public signal order does not match the schema");
      }
      const actualManifestHash = hashOf(manifest);
      if (expectedManifestHash !== null && actualManifestHash !== expectedManifestHash) {
        throw guardrailError("MANIFEST_HASH_MISMATCH", "artifact manifest is not the pinned manifest");
      }
      this.manifestHash = actualManifestHash;
      this.manifest = structuredClone(manifest);
    } else {
      this.manifestHash = null;
      this.manifest = null;
    }
    this.verifier = verifier;
    this.verificationKey = structuredClone(verificationKey);
    this.verificationKeyHash = actualKeyHash;
    this.schema = schema;
  }

  /**
   * @param {object} options
   * @param {object} options.proof            the proof as produced by the prover
   * @param {string[]} options.publicSignals  positional signals from the prover
   * @param {object} options.expectedSignals  the context the application authorized, by name
   */
  async verify({ proof, publicSignals, expectedSignals }) {
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
      throw guardrailError("INVALID_PROOF_PACKAGE", "a proof object is required");
    }
    const bound = this.schema.assertBinds(publicSignals, expectedSignals);
    const ordered = this.schema.names.map((name) => bound[name]);
    let verified;
    try {
      verified = await this.verifier.verify(this.verificationKey, ordered, proof);
    } catch (cause) {
      throw guardrailError("VERIFIER_UNAVAILABLE", `verifier failed: ${cause.message}`);
    }
    if (verified !== true) {
      throw guardrailError("INVALID_PROOF", "proof verification failed");
    }
    return {
      verified: true,
      schemaId: this.schema.id,
      verificationKeyHash: this.verificationKeyHash,
      manifestHash: this.manifestHash,
      circuitId: this.manifest?.circuitId ?? null,
      circuitVersion: this.manifest?.circuitVersion ?? null,
      proofHash: hashOf(proof),
      publicSignalsHash: this.schema.hash(ordered),
      signals: bound,
    };
  }
}
