// A named, ordered schema for a circuit's public signals.
//
// A Groth16 verifier tells you "this proof is valid for this list of numbers".
// It cannot tell you that the third number was meant to be the recipient and
// not the fee, nor that those numbers describe the transaction your application
// authorized. That binding is the application's job, and it is where real
// systems go wrong: a proof is verified, the signals are read positionally,
// and a caller who reorders or relabels them gets an accepted proof for a
// different transaction.
//
// A schema names each position once, so signals can be compared by name, the
// count is enforced, and the whole list hashes to a single value you can store
// alongside the receipt.

import { createHash } from "node:crypto";
import { guardrailError, normalizeFieldElement } from "./field.js";

const NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

export function hashOf(value) {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalize(value)).digest("hex");
}

export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export class PublicSignalSchema {
  /** @param {string[]} names signal names, in the circuit's output order */
  constructor(names) {
    if (!Array.isArray(names) || names.length === 0 || names.length > 256) {
      throw guardrailError("INVALID_SIGNAL_SCHEMA", "a schema needs between 1 and 256 signal names");
    }
    if (!names.every((name) => typeof name === "string" && NAME.test(name))) {
      throw guardrailError("INVALID_SIGNAL_SCHEMA", "signal names must be identifiers");
    }
    if (new Set(names).size !== names.length) {
      throw guardrailError("INVALID_SIGNAL_SCHEMA", "signal names must be unique");
    }
    this.names = Object.freeze([...names]);
    this.length = names.length;
    this.id = hashOf(this.names);
    Object.freeze(this);
  }

  /** Named object -> canonical named object. Missing or malformed values throw. */
  normalizeNamed(values, labelPrefix = "") {
    return Object.fromEntries(this.names.map((name) => [
      name, normalizeFieldElement(String(values?.[name] ?? ""), `${labelPrefix}${name}`),
    ]));
  }

  /** Positional array (as returned by a prover) -> canonical named object. */
  normalizeList(signals) {
    if (!Array.isArray(signals) || signals.length !== this.length) {
      throw guardrailError("INVALID_PUBLIC_SIGNALS", `exactly ${this.length} public signals are required`);
    }
    return Object.fromEntries(this.names.map((name, index) => [
      name, normalizeFieldElement(String(signals[index]), name),
    ]));
  }

  toList(named) {
    const normalized = this.normalizeNamed(named);
    return this.names.map((name) => normalized[name]);
  }

  /**
   * Checks a prover's signals against the context the application authorized.
   * Throws PUBLIC_SIGNAL_MISMATCH naming the first signal that differs.
   */
  assertBinds(signals, expected) {
    const actual = this.normalizeList(signals);
    const wanted = this.normalizeNamed(expected, "expected ");
    for (const name of this.names) {
      if (actual[name] !== wanted[name]) {
        throw guardrailError("PUBLIC_SIGNAL_MISMATCH", `public signal ${name} does not match the authorized context`);
      }
    }
    return actual;
  }

  /** One hash over the ordered signals, safe to store next to a receipt. */
  hash(signalsOrNamed) {
    const list = Array.isArray(signalsOrNamed)
      ? this.names.map((name, index) => normalizeFieldElement(String(signalsOrNamed[index]), name))
      : this.toList(signalsOrNamed);
    return hashOf([this.id, ...list]);
  }
}
