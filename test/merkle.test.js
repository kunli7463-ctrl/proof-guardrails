import assert from "node:assert/strict";
import test from "node:test";
import { createMerkleFrontier } from "../src/merkle.js";

const LEAF_DOMAIN = 0x434c324c45414601n;
const NODE_DOMAIN = 0x434c324e4f444501n;
const tree = (depth = 8) => createMerkleFrontier({ leafDomain: LEAF_DOMAIN, nodeDomain: NODE_DOMAIN, depth });

/** Independent reference: build the whole tree level by level. */
function referenceRoot(merkle, leaves) {
  let level = [...leaves.map(BigInt)];
  const zeros = merkle.zeros();
  for (let height = 0; height < merkle.depth; height += 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const right = index + 1 < level.length ? level[index + 1] : zeros[height];
      next.push(merkle.node(level[index], right));
    }
    level = next.length === 0 ? [zeros[height + 1]] : next;
  }
  return level[0];
}

test("the frontier root matches a full-tree recomputation for every prefix", () => {
  const merkle = tree();
  const leaves = Array.from({ length: 9 }, (_, index) => merkle.leaf(BigInt(index + 1), BigInt(index * 7 + 3)).toString());
  let state = merkle.empty();
  assert.equal(state.root, referenceRoot(merkle, []).toString());
  for (let count = 1; count <= leaves.length; count += 1) {
    state = merkle.append(state, [leaves[count - 1]]);
    assert.equal(state.treeSize, count);
    assert.equal(state.root, referenceRoot(merkle, leaves.slice(0, count)).toString());
  }
});

test("appending in one batch equals appending one at a time", () => {
  const merkle = tree();
  const leaves = ["11", "22", "33", "44", "55"];
  let stepwise = merkle.empty();
  for (const leaf of leaves) stepwise = merkle.append(stepwise, [leaf]);
  const batched = merkle.append(merkle.empty(), leaves);
  assert.deepEqual(batched, stepwise);
});

test("a frontier that does not reproduce its stored root is refused", () => {
  const merkle = tree();
  const state = merkle.append(merkle.empty(), ["7", "8", "9"]);
  assert.equal(merkle.rootFrom(state.treeSize, state.frontier).toString(), state.root);
  assert.throws(() => merkle.append({ ...state, expectedRoot: "12345" }, ["10"]), { code: "MERKLE_ROOT_MISMATCH" });
  // A tampered level is caught even when the caller supplies the matching root.
  const tampered = [...state.frontier];
  tampered[0] = "424242";
  assert.throws(() => merkle.append({ treeSize: state.treeSize, frontier: tampered, expectedRoot: state.root }, ["10"]),
    { code: "MERKLE_ROOT_MISMATCH" });
});

test("malformed states are rejected before any hashing", () => {
  const merkle = tree();
  const empty = merkle.empty();
  assert.throws(() => merkle.rootFrom(-1, empty.frontier), { code: "INVALID_MERKLE_STATE" });
  assert.throws(() => merkle.rootFrom(1, empty.frontier), { code: "INVALID_MERKLE_STATE" });
  assert.throws(() => merkle.rootFrom(0, empty.frontier.slice(1)), { code: "INVALID_MERKLE_STATE" });
  assert.throws(() => merkle.append(merkle.empty(), []), { code: "INVALID_MERKLE_APPEND" });
  assert.throws(() => merkle.append(merkle.empty(), ["007"]), { code: "INVALID_FIELD_ELEMENT" });
  assert.throws(() => merkle.append(merkle.empty(), ["0x10"]), { code: "INVALID_FIELD_ELEMENT" });
});

test("a tree filled to capacity still has a verifiable root, and takes no more leaves", () => {
  const merkle = tree(2);
  const state = merkle.append(merkle.empty(), ["1", "2", "3", "4"]);
  assert.equal(state.treeSize, 4);
  assert.equal(state.root, referenceRoot(merkle, ["1", "2", "3", "4"]).toString());
  assert.equal(merkle.rootFrom(state.treeSize, state.frontier).toString(), state.root);
  assert.throws(() => merkle.append(state, ["5"]), { code: "MERKLE_TREE_FULL" });
});

test("leaf and node domains must differ, and leaves are not subtrees", () => {
  assert.throws(() => createMerkleFrontier({ leafDomain: 1n, nodeDomain: 1n }), { code: "INVALID_MERKLE_DOMAINS" });
  const merkle = tree();
  assert.notEqual(merkle.leaf(5n, 6n), merkle.node(5n, 6n));
});
