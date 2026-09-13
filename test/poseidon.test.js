import assert from "node:assert/strict";
import test from "node:test";
import { poseidon3 } from "../src/poseidon.js";

// Known answers produced by circomlibjs@0.1.7 buildPoseidon() with three
// inputs. They pin this implementation to the reference one without making
// circomlibjs a dependency of the library or of its test suite.
const VECTORS = [
  [["0", "0", "0"], "5317387130258456662214331362918410991734007599705406860481038345552731150762"],
  [["1", "2", "3"], "6542985608222806190361240322586112750744169038454362455181422643027100751666"],
  [["4849306210689893633", "123456789", "987654321"],
    "15777687274477077374854117890245313112687029852930544623930007610968752585447"],
  [["14474011154664524427946373126085988481658748083205070504932198000989141205009",
    "1606938044258990275541962092341162602522202993782792835301381",
    "21888242871839275222246405745257275088548364400416034343698204186575808495616"],
  "7962547421592302865804198945500273255144160729698420648666685462458961944391"],
];

test("poseidon3 reproduces circomlib Poseidon(3) known answers", () => {
  for (const [inputs, expected] of VECTORS) {
    assert.equal(poseidon3(...inputs.map(BigInt)).toString(), expected, inputs.join(","));
  }
});

test("poseidon3 reduces its inputs modulo the field", () => {
  const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  assert.equal(poseidon3(1n, 2n, 3n), poseidon3(1n + field, 2n, 3n));
  assert.notEqual(poseidon3(1n, 2n, 3n), poseidon3(3n, 2n, 1n));
});
