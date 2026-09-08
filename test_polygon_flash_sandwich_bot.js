"use strict";

const assert = require("assert");
const { ethers } = require("ethers");
const {
  compileSandwichContract,
  getAmountOut,
  parseAssetUnits,
  clampBorrow,
  generateBorrowCandidates,
  simulateOpportunity,
  serializeVictimTransaction
} = require("./polygon_flash_sandwich_bot");

function run(name, test) {
  try {
    test();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    throw error;
  }
}

run("imports without a private key and defaults to scan mode", () => {
  const bot = require("./polygon_flash_sandwich_bot");
  assert.strictEqual(bot.CONFIG.mode, "scan");
});

run("calculates Uniswap V2 output with integer arithmetic", () => {
  assert.strictEqual(getAmountOut(1_000n, 100_000n, 100_000n), 987n);
  assert.strictEqual(getAmountOut(0n, 100_000n, 100_000n), 0n);
  assert.strictEqual(getAmountOut(1_000n, 0n, 100_000n), 0n);
});

run("parses asset units without accepting negative values", () => {
  assert.strictEqual(parseAssetUnits("1.25", 6), 1_250_000n);
  assert.throws(() => parseAssetUnits("-1", 6), /cannot be negative/);
  assert.throws(() => parseAssetUnits("1.0000001", 6), /Failed to parse/);
});

run("clamps candidate size to the configured reserve share", () => {
  assert.strictEqual(clampBorrow(50n, 100n), 42n);
  assert.strictEqual(clampBorrow(0n, 100n), 0n);
  const candidates = generateBorrowCandidates(10n, 20n, 1_000n);
  assert.ok(candidates.length > 0);
  assert.ok(candidates.every(value => value <= 420n));
});

run("rejects an unprofitable or invalid simulation", () => {
  assert.strictEqual(simulateOpportunity(0n, 100n, 1_000n, 1_000n), null);
  assert.strictEqual(simulateOpportunity(100n, 1n, 1_000n, 1_000n), null);
  assert.strictEqual(
    simulateOpportunity(100n, 100n, 1_000n, 1_000n, { estimatedGasCostAsset: 10_000n }),
    null
  );
});

run("returns a protected profitable simulation", () => {
  const result = simulateOpportunity(10_000n, 100_000n, 1_000_000n, 1_000_000n, {
    estimatedGasCostAsset: 1n,
    slippageBps: 35n
  });
  assert.ok(result, "expected a profitable simulation");
  assert.ok(result.grossProfit > result.netProfit);
  assert.ok(result.minFrontOut <= result.frontOut);
  assert.ok(result.minBackOut >= result.tradeAmount + result.estimatedGasCostAsset);
});

run("preserves the victim signature when serializing a bundle transaction", () => {
  const raw = "0x02f86b8189808405f5e100843b9aca0082520894109ed65fc8dd2451481e31b3ebc7ee223189476e0180c080a096c10d714ef9c03643222cb8bbf511e5540d3c99c03975ed9798596c3a3ce905a0641a0615ed9f444347b6c55d21e735142141f937e30176d1785cb95c08f589bc";
  const tx = ethers.Transaction.from(raw);
  const serialized = serializeVictimTransaction({
    type: tx.type,
    to: tx.to,
    nonce: tx.nonce,
    gasLimit: tx.gasLimit,
    maxFeePerGas: tx.maxFeePerGas,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
    value: tx.value,
    data: tx.data,
    chainId: tx.chainId,
    accessList: tx.accessList,
    signature: tx.signature
  });
  assert.strictEqual(serialized, raw);
});

run("compiles the owner-funded executor with bundle-safe methods", () => {
  const artifact = compileSandwichContract();
  const names = artifact.abi.filter(item => item.type === "function").map(item => item.name);
  assert.ok(names.includes("startSandwich"));
  assert.ok(names.includes("finishSandwich"));
  assert.ok(names.includes("version"));
  assert.ok(!names.includes("receiveFlashLoan"));
  assert.ok(artifact.bytecode.length > 100);
});

console.log("Polygon bot tests passed");
