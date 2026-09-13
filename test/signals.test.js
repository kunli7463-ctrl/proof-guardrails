import assert from "node:assert/strict";
import test from "node:test";
import { PublicSignalSchema } from "../src/signals.js";

const schema = new PublicSignalSchema(["root", "recipient", "amountCommitment"]);

test("a schema rejects malformed definitions", () => {
  assert.throws(() => new PublicSignalSchema([]), { code: "INVALID_SIGNAL_SCHEMA" });
  assert.throws(() => new PublicSignalSchema(["a", "a"]), { code: "INVALID_SIGNAL_SCHEMA" });
  assert.throws(() => new PublicSignalSchema(["1bad"]), { code: "INVALID_SIGNAL_SCHEMA" });
  assert.throws(() => new PublicSignalSchema("root"), { code: "INVALID_SIGNAL_SCHEMA" });
});

test("named and positional forms round-trip", () => {
  const named = { root: "1", recipient: "2", amountCommitment: "3" };
  assert.deepEqual(schema.toList(named), ["1", "2", "3"]);
  assert.deepEqual(schema.normalizeList(["1", "2", "3"]), named);
});

test("the signal hash depends on order, values and the schema itself", () => {
  const base = schema.hash(["1", "2", "3"]);
  assert.equal(base, schema.hash({ root: "1", recipient: "2", amountCommitment: "3" }));
  assert.notEqual(base, schema.hash(["2", "1", "3"]));
  const renamed = new PublicSignalSchema(["root", "payee", "amountCommitment"]);
  assert.notEqual(base, renamed.hash(["1", "2", "3"]));
});

test("assertBinds returns the canonical signals and names the first mismatch", () => {
  const expected = { root: "1", recipient: "2", amountCommitment: "3" };
  assert.deepEqual(schema.assertBinds(["1", "2", "3"], expected), expected);
  assert.throws(() => schema.assertBinds(["1", "2", "4"], expected),
    (error) => error.code === "PUBLIC_SIGNAL_MISMATCH" && /amountCommitment/.test(error.message));
  assert.throws(() => schema.assertBinds(["1", "2", "3"], { root: "1", recipient: "2" }),
    { code: "INVALID_FIELD_ELEMENT" });
});
