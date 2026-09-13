// An append-only Poseidon Merkle tree stored as a frontier.
//
// A service that accepts "here is the new root after these insertions" and
// writes it down has no way to notice a wrong root — including one that
// silently mints or drops leaves. Recomputing the root needs the tree, and
// keeping every leaf in memory or re-reading them per append does not scale.
//
// A frontier is the small state that makes recomputation cheap: for every set
// bit i of the tree size, `frontier[i]` is the root of the complete left
// subtree of 2^i leaves at that level; unset bits are null. Size plus frontier
// determine the root, so a published root can be verified and an append can be
// replayed from `depth + 1` field elements instead of the whole tree. (The
// extra level holds the root of a tree filled to capacity, where every lower
// bit of the size is zero.)
//
//   leaf(x, y)        = Poseidon([leafDomain, x, y])
//   node(left, right) = Poseidon([nodeDomain, left, right])
//   zeros[0] = 0, zeros[k+1] = node(zeros[k], zeros[k])
//
// Domain tags separate leaf hashes from internal nodes, so a leaf can never be
// presented as a subtree. Match them to your circuit's constants.

import { guardrailError, normalizeFieldElement } from "./field.js";
import { poseidon3 } from "./poseidon.js";

/**
 * @param {object} options
 * @param {bigint|string|number} options.leafDomain  domain tag hashed into every leaf
 * @param {bigint|string|number} options.nodeDomain  domain tag hashed into every internal node
 * @param {number} [options.depth=32]
 */
export function createMerkleFrontier({ leafDomain, nodeDomain, depth = 32 }) {
  if (!Number.isInteger(depth) || depth < 1 || depth > 64) {
    throw guardrailError("INVALID_MERKLE_DEPTH", "depth must be an integer in [1, 64]");
  }
  const leafTag = BigInt(leafDomain);
  const nodeTag = BigInt(nodeDomain);
  if (leafTag === nodeTag) {
    throw guardrailError("INVALID_MERKLE_DOMAINS", "leaf and node domain tags must differ");
  }
  const maxSize = 2n ** BigInt(depth);
  const levelCount = depth + 1;

  const leaf = (x, y) => poseidon3(leafTag, BigInt(x), BigInt(y));
  const node = (left, right) => poseidon3(nodeTag, BigInt(left), BigInt(right));

  let zeroCache = null;
  const zeros = () => {
    if (!zeroCache) {
      zeroCache = [0n];
      for (let level = 1; level <= depth; level += 1) zeroCache.push(node(zeroCache[level - 1], zeroCache[level - 1]));
      Object.freeze(zeroCache);
    }
    return zeroCache;
  };

  const parseTreeSize = (value) => {
    let size;
    try { size = BigInt(value); } catch { size = -1n; }
    if (size < 0n || size > maxSize) {
      throw guardrailError("INVALID_MERKLE_STATE", `tree size must be an integer in [0, 2^${depth}]`);
    }
    return size;
  };

  /** Validates a stored frontier against its size; returns bigint-or-null levels. */
  const parseFrontier = (treeSize, frontier) => {
    const size = parseTreeSize(treeSize);
    if (!Array.isArray(frontier) || frontier.length !== levelCount) {
      throw guardrailError("INVALID_MERKLE_STATE", `frontier must contain exactly ${levelCount} levels`);
    }
    return frontier.map((entry, level) => {
      const occupied = ((size >> BigInt(level)) & 1n) === 1n;
      if (!occupied) {
        if (entry !== null) throw guardrailError("INVALID_MERKLE_STATE", `frontier level ${level} must be empty for this tree size`);
        return null;
      }
      try { return BigInt(normalizeFieldElement(String(entry ?? ""), `frontier[${level}]`)); }
      catch (cause) { throw guardrailError("INVALID_MERKLE_STATE", cause.message); }
    });
  };

  const rootFrom = (treeSize, frontier) => {
    const size = parseTreeSize(treeSize);
    const levels = parseFrontier(size, frontier);
    if (levels[depth] !== null) return levels[depth];
    const zero = zeros();
    let hash = zero[0];
    for (let level = 0; level < depth; level += 1) {
      hash = levels[level] === null ? node(hash, zero[level]) : node(levels[level], hash);
    }
    return hash;
  };

  const empty = () => ({
    treeSize: 0,
    frontier: new Array(levelCount).fill(null),
    root: zeros()[depth].toString(),
  });

  /**
   * Appends leaves in order and returns the new {treeSize, frontier, root}.
   * Pass `expectedRoot` to refuse a state whose frontier does not reproduce the
   * root you have stored — that check is the point of the exercise.
   */
  const append = ({ treeSize, frontier, expectedRoot = null }, leaves) => {
    let size = parseTreeSize(treeSize);
    const levels = parseFrontier(size, frontier);
    if (expectedRoot !== null && rootFrom(size, frontier).toString() !== String(expectedRoot)) {
      throw guardrailError("MERKLE_ROOT_MISMATCH", "stored frontier does not reproduce its Merkle root");
    }
    if (!Array.isArray(leaves) || leaves.length === 0) {
      throw guardrailError("INVALID_MERKLE_APPEND", "at least one leaf is required");
    }
    if (size + BigInt(leaves.length) > maxSize) {
      throw guardrailError("MERKLE_TREE_FULL", "the tree has no remaining capacity");
    }
    for (const value of leaves) {
      let carry = BigInt(normalizeFieldElement(String(value), "leaf"));
      let level = 0;
      while (((size >> BigInt(level)) & 1n) === 1n) {
        carry = node(levels[level], carry);
        levels[level] = null;
        level += 1;
      }
      levels[level] = carry;
      size += 1n;
    }
    const serialized = levels.map((entry) => (entry === null ? null : entry.toString()));
    return { treeSize: Number(size), frontier: serialized, root: rootFrom(size, serialized).toString() };
  };

  return { depth, leafDomain: leafTag, nodeDomain: nodeTag, leaf, node, zeros, parseFrontier, rootFrom, empty, append };
}
