// Poseidon over BN254 with three inputs, with no dependencies.
//
// The round constants and MDS matrix are the circomlib t=4 parameters, so this
// produces the same digests as `circomlibjs`' Poseidon(3) and as a circom
// `Poseidon(3)` template. It exists because a server that has to recompute what
// a circuit computed should not have to pull a multi-megabyte toolchain — and
// because a second, independent implementation is what lets you test the first
// one.

import { createRequire } from "node:module";
import { BN254_SCALAR_FIELD } from "./field.js";

const require = createRequire(import.meta.url);
const CONSTANTS = require("./poseidon-bn254-t4-constants.json");

const P = BN254_SCALAR_FIELD;
const T = CONSTANTS.t;
const ROUNDS_F = CONSTANTS.nRoundsF;
const ROUNDS_P = CONSTANTS.nRoundsP;
const C = CONSTANTS.C.map((value) => BigInt(value));
const M = CONSTANTS.M.map((row) => row.map((value) => BigInt(value)));

if (T !== 4 || C.length !== T * (ROUNDS_F + ROUNDS_P) || M.length !== T) {
  throw new Error("Poseidon t=4 constants are malformed");
}

function mod(value) {
  const reduced = value % P;
  return reduced < 0n ? reduced + P : reduced;
}

function pow5(value) {
  const square = (value * value) % P;
  return (((square * square) % P) * value) % P;
}

/** circomlib Poseidon(3): three field elements in, one out. */
export function poseidon3(a, b, c) {
  let state = [0n, mod(BigInt(a)), mod(BigInt(b)), mod(BigInt(c))];
  for (let round = 0; round < ROUNDS_F + ROUNDS_P; round += 1) {
    for (let i = 0; i < T; i += 1) state[i] = mod(state[i] + C[round * T + i]);
    if (round < ROUNDS_F / 2 || round >= ROUNDS_F / 2 + ROUNDS_P) {
      for (let i = 0; i < T; i += 1) state[i] = pow5(state[i]);
    } else {
      state[0] = pow5(state[0]);
    }
    const mixed = new Array(T);
    for (let i = 0; i < T; i += 1) {
      let accumulator = 0n;
      for (let j = 0; j < T; j += 1) accumulator += M[i][j] * state[j];
      mixed[i] = accumulator % P;
    }
    state = mixed;
  }
  return state[0];
}
