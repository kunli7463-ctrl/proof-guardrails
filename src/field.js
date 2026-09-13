// Canonical field-element handling for BN254 public signals.
//
// Proof systems accept field elements, but applications pass them around as
// strings. "5", "05", "0x5" and "5 " are the same number to a verifier and
// different strings to your database, so a system that compares signals as
// strings can be made to accept a proof whose context does not match. Every
// value entering this library is therefore reduced to one canonical decimal
// spelling and checked against the field modulus before anything else happens.

export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function guardrailError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

/** Returns the canonical decimal string, or throws INVALID_FIELD_ELEMENT. */
export function normalizeFieldElement(value, label = "value") {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw guardrailError("INVALID_FIELD_ELEMENT", `${label} must be a canonical decimal field element`);
  }
  if (BigInt(value) >= BN254_SCALAR_FIELD) {
    throw guardrailError("INVALID_FIELD_ELEMENT", `${label} exceeds the BN254 scalar field`);
  }
  return value;
}

export function toFieldBigInt(value, label = "value") {
  return BigInt(normalizeFieldElement(String(value), label));
}
