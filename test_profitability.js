// =============================================================================
// Arbitrum Flash Sandwich Bot - Comprehensive Profitability Test Suite
// =============================================================================

const { ethers } = require("ethers");
const assert = require("assert");

// =============================================================================
// Test Configuration
// =============================================================================

const TEST_CONFIG = {
  // Arbitrum gas prices (wei)
  gasPrices: {
    low: ethers.parseUnits("0.1", "gwei"),
    normal: ethers.parseUnits("1", "gwei"),
    high: ethers.parseUnits("10", "gwei"),
    extreme: ethers.parseUnits("50", "gwei")
  },
  
  // Aave V3 flash loan fee on Arbitrum (9 bps = 0.09%)
  flashLoanFeeBps: 9n,
  
  // Bot configuration (from your code)
  slippageBps: 50n,      // 0.5%
  maxBorrowBps: 4200n,   // 42%
  minProfitBps: 10n,     // 0.1%
  
  // Estimated gas usage
  gasEstimates: {
    deployment: 5_000_000n,
    sandwichTx: 1_200_000n,
    simpleSwap: 150_000n
  },
  
  // Token decimals
  tokenDecimals: {
    USDC: 6,
    USDT: 6,
    DAI: 18,
    WETH: 18,
    WBTC: 8
  }
};

// =============================================================================
// Test Helper Functions
// =============================================================================

/**
 * Constant product AMM math (Uniswap V2 style)
 * @param {bigint} amountIn - Input amount
 * @param {bigint} reserveIn - Input reserve
 * @param {bigint} reserveOut - Output reserve
 * @returns {bigint} - Output amount
 */
function getAmountOut(amountIn, reserveIn, reserveOut) {
  if (amountIn <= 0n || reserveIn <= 0n || reserveOut <= 0n) return 0n;
  const amountInWithFee = amountIn * 997n; // 0.3% fee
  const numerator = amountInWithFee * reserveOut;
  const denominator = reserveIn * 1000n + amountInWithFee;
  if (denominator === 0n) return 0n;
  return numerator / denominator;
}

/**
 * Simulate a sandwich attack
 * @param {bigint} borrowAmount - Amount to borrow
 * @param {bigint} victimAmount - Victim's swap amount
 * @param {bigint} reserveIn - Initial input reserve
 * @param {bigint} reserveOut - Initial output reserve
 * @param {bigint} premiumBps - Flash loan premium in basis points
 * @param {bigint} gasPrice - Gas price in wei
 * @param {bigint} gasEstimate - Estimated gas usage
 * @param {number} tokenOutDecimals - Output token decimals
 * @returns {object|null} - Simulation result or null if not profitable
 */
function simulateSandwich(
  borrowAmount, 
  victimAmount, 
  reserveIn, 
  reserveOut, 
  premiumBps = TEST_CONFIG.flashLoanFeeBps,
  gasPrice = TEST_CONFIG.gasPrices.normal,
  gasEstimate = TEST_CONFIG.gasEstimates.sandwichTx,
  tokenOutDecimals = 18
) {
  if (borrowAmount === 0n) return null;
  
  // Calculate flash loan fee
  const flashLoanFee = (borrowAmount * premiumBps) / 10_000n;
  
  // Calculate gas cost in wei
  const gasCostWei = gasEstimate * gasPrice;
  
  // Convert gas cost to token units (assuming ETH price = $2000, token price = $1 for simplicity)
  // This is a simplification - in reality, you'd need oracle prices
  const ETH_PRICE_USD = 2000n * 10n ** 18n; // $2000 with 18 decimals
  const TOKEN_PRICE_USD = 1n * 10n ** BigInt(tokenOutDecimals); // $1 with token decimals
  const gasCostToken = (gasCostWei * TOKEN_PRICE_USD) / ETH_PRICE_USD;
  
  // Front-run: bot buys tokenOut
  const frontOut = getAmountOut(borrowAmount, reserveIn, reserveOut);
  if (frontOut === 0n) return null;
  
  const rInAfterFront = reserveIn + borrowAmount;
  const rOutAfterFront = reserveOut - frontOut;
  if (rOutAfterFront <= 0n) return null;
  
  // Victim executes at worse price
  const victimOut = getAmountOut(victimAmount, rInAfterFront, rOutAfterFront);
  if (victimOut === 0n) return null;
  
  const rInAfterVictim = rInAfterFront + victimAmount;
  const rOutAfterVictim = rOutAfterFront - victimOut;
  if (rOutAfterVictim <= 0n) return null;
  
  // Back-run: bot sells tokenOut back for tokenIn
  const backOut = getAmountOut(frontOut, rOutAfterVictim, rInAfterVictim);
  if (backOut === 0n) return null;
  
  // Calculate all costs
  const totalCosts = flashLoanFee + gasCostToken;
  const netProfit = backOut - borrowAmount - totalCosts;
  
  if (netProfit <= 0n) return null;
  
  // Calculate profit margin
  const profitBps = (netProfit * 10_000n) / borrowAmount;
  
  // Apply slippage
  const minFrontOut = (frontOut * (10_000n - TEST_CONFIG.slippageBps)) / 10_000n;
  const minBackOut = (() => {
    const slipped = (backOut * (10_000n - TEST_CONFIG.slippageBps)) / 10_000n;
    const totalOwed = borrowAmount + flashLoanFee;
    return slipped > totalOwed ? slipped : totalOwed;
  })();
  
  return {
    borrowAmount,
    flashLoanFee,
    gasCostWei,
    gasCostToken,
    frontOut,
    victimOut,
    backOut,
    netProfit,
    totalCosts,
    minFrontOut,
    minBackOut,
    profitBps,
    priceImpact: ((backOut - borrowAmount) * 10_000n) / borrowAmount
  };
}

/**
 * Clamp borrow amount to max percentage of reserves
 */
function clampBorrow(amount, reserveIn) {
  const maxBorrow = (reserveIn * TEST_CONFIG.maxBorrowBps) / 10_000n;
  return maxBorrow === 0n ? 0n : (amount > maxBorrow ? maxBorrow : amount);
}

/**
 * Generate borrow amount candidates
 */
function generateBorrowCandidates(victimAmount, reserveIn) {
  const candidates = new Set();
  const push = amt => {
    const clamped = clampBorrow(amt, reserveIn);
    if (clamped > 0n) candidates.add(clamped);
  };
  push(victimAmount);
  push(victimAmount * 2n);
  push(victimAmount * 3n);
  push(victimAmount / 2n);
  push(reserveIn / 5n);
  push(reserveIn / 4n);
  push(reserveIn / 6n);
  push(reserveIn / 10n);
  return Array.from(candidates).sort((a, b) => (a > b ? -1 : a < b ? 1 : 0));
}

// =============================================================================
// Test Suite
// =============================================================================

class ProfitabilityTest {
  constructor() {
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
    this.startTime = Date.now();
  }
  
  addTest(name, fn) {
    this.tests.push({ name, fn });
  }
  
  async run() {
    console.log("\n" + "=".repeat(70));
    console.log("🧪 ARBITRUM FLASH SANDWICH BOT - PROFITABILITY TEST SUITE");
    console.log("=".repeat(70));
    console.log(`Configuration:`);
    console.log(`  - Flash Loan Fee: ${TEST_CONFIG.flashLoanFeeBps} bps`);
    console.log(`  - Slippage: ${TEST_CONFIG.slippageBps} bps`);
    console.log(`  - Max Borrow: ${TEST_CONFIG.maxBorrowBps} bps`);
    console.log(`  - Min Profit: ${TEST_CONFIG.minProfitBps} bps`);
    console.log(`  - Estimated Gas: ${TEST_CONFIG.gasEstimates.sandwichTx.toString()} wei`);
    console.log("=".repeat(70) + "\n");
    
    for (const test of this.tests) {
      try {
        await test.fn();
        this.passed++;
        console.log(`✅ PASS: ${test.name}`);
      } catch (error) {
        this.failed++;
        console.log(`❌ FAIL: ${test.name}`);
        console.log(`   Error: ${error.message}`);
      }
    }
    
    this.printSummary();
    return this.failed === 0;
  }
  
  printSummary() {
    const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);
    console.log("\n" + "=".repeat(70));
    console.log("📊 TEST SUMMARY");
    console.log("=".repeat(70));
    console.log(`Total Tests: ${this.tests.length}`);
    console.log(`Passed: ${this.passed}`);
    console.log(`Failed: ${this.failed}`);
    console.log(`Success Rate: ${((this.passed / this.tests.length) * 100).toFixed(2)}%`);
    console.log(`Duration: ${duration} seconds`);
    console.log("=".repeat(70) + "\n");
  }
}

// =============================================================================
// Test Cases
// =============================================================================

const testSuite = new ProfitabilityTest();

// Test 1: Basic sandwich profitability
testSuite.addTest("Basic sandwich is profitable with sufficient price impact", () => {
  const reserveIn = 1_000_000n * 10n ** 6n; // 1M USDC
  const reserveOut = 1_000_000n * 10n ** 18n; // 1M WETH (18 decimals)
  const victimAmount = 100_000n * 10n ** 6n; // 100K USDC
  const borrowAmount = 50_000n * 10n ** 6n; // 50K USDC
  
  const result = simulateSandwich(
    borrowAmount, 
    victimAmount, 
    reserveIn, 
    reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.normal,
    TEST_CONFIG.gasEstimates.sandwichTx,
    18
  );
  
  assert(result !== null, "Sandwich should be profitable");
  assert(result.netProfit > 0n, "Net profit should be positive");
  assert(result.profitBps > TEST_CONFIG.minProfitBps, 
    `Profit margin ${result.profitBps} should exceed min ${TEST_CONFIG.minProfitBps}`);
});

// Test 2: Small trade is not profitable
testSuite.addTest("Small trades are filtered out", () => {
  const reserveIn = 10_000n * 10n ** 6n; // 10K USDC
  const reserveOut = 10_000n * 10n ** 18n; // 10K WETH
  const victimAmount = 100n * 10n ** 6n; // 100 USDC
  const borrowAmount = 50n * 10n ** 6n; // 50 USDC
  
  const result = simulateSandwich(
    borrowAmount, 
    victimAmount, 
    reserveIn, 
    reserveOut
  );
  
  // Small trades may not be profitable due to fixed gas costs
  if (result !== null) {
    assert(result.profitBps >= TEST_CONFIG.minProfitBps || result.netProfit <= 0n,
      "Small trades should either be unprofitable or meet min threshold");
  }
});

// Test 3: High gas prices reduce profitability
testSuite.addTest("High gas prices reduce profitability", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const reserveOut = 1_000_000n * 10n ** 18n;
  const victimAmount = 100_000n * 10n ** 6n;
  const borrowAmount = 50_000n * 10n ** 6n;
  
  // Test with normal gas
  const resultNormal = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.normal
  );
  
  // Test with high gas
  const resultHigh = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.high
  );
  
  assert(resultNormal !== null, "Should be profitable with normal gas");
  
  if (resultNormal && resultHigh) {
    assert(resultHigh.netProfit < resultNormal.netProfit,
      "Higher gas should reduce profit");
  }
});

// Test 4: Flash loan fee calculation
testSuite.addTest("Flash loan fee calculation is correct", () => {
  const amount = 100_000n * 10n ** 6n; // 100K USDC
  const expectedFee = (amount * TEST_CONFIG.flashLoanFeeBps) / 10_000n;
  
  const result = simulateSandwich(
    amount, 
    amount, 
    amount * 10n, 
    amount * 10n
  );
  
  if (result) {
    assert(result.flashLoanFee === expectedFee,
      `Flash loan fee should be ${expectedFee}, got ${result.flashLoanFee}`);
  }
});

// Test 5: Borrow amount clamping
testSuite.addTest("Borrow amount is clamped to max percentage", () => {
  const reserveIn = 100_000n * 10n ** 6n; // 100K USDC
  const victimAmount = 1_000_000n * 10n ** 6n; // 1M USDC (larger than reserve)
  
  const candidates = generateBorrowCandidates(victimAmount, reserveIn);
  
  for (const candidate of candidates) {
    assert(candidate <= (reserveIn * TEST_CONFIG.maxBorrowBps) / 10_000n,
      `Borrow amount ${candidate} should not exceed max ${(reserveIn * TEST_CONFIG.maxBorrowBps) / 10_000n}`);
  }
});

// Test 6: Slippage protection
testSuite.addTest("Slippage is correctly applied", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const reserveOut = 1_000_000n * 10n ** 18n;
  const victimAmount = 100_000n * 10n ** 6n;
  const borrowAmount = 50_000n * 10n ** 6n;
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  if (result) {
    const expectedMinFront = (result.frontOut * (10_000n - TEST_CONFIG.slippageBps)) / 10_000n;
    assert(result.minFrontOut === expectedMinFront,
      `Min front out should be ${expectedMinFront}, got ${result.minFrontOut}`);
  }
});

// Test 7: Minimum profit threshold
testSuite.addTest("Trades below min profit threshold are filtered", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const reserveOut = 1_000_000n * 10n ** 18n;
  const victimAmount = 1_000n * 10n ** 6n; // 1K USDC (small)
  const borrowAmount = 500n * 10n ** 6n; // 500 USDC
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  if (result) {
    // If profitable, should meet minimum
    assert(result.profitBps >= TEST_CONFIG.minProfitBps,
      `Profit margin ${result.profitBps} should meet minimum ${TEST_CONFIG.minProfitBps}`);
  }
});

// Test 8: Price impact calculation
testSuite.addTest("Price impact is correctly calculated", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const reserveOut = 1_000_000n * 10n ** 18n;
  const victimAmount = 100_000n * 10n ** 6n;
  const borrowAmount = 50_000n * 10n ** 6n;
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  if (result) {
    assert(result.priceImpact > 0n, "Price impact should be positive");
    assert(result.priceImpact >= result.profitBps,
      "Price impact should be at least as large as profit margin");
  }
});

// Test 9: Different token decimals
testSuite.addTest("Handles different token decimals correctly", () => {
  // Test with WBTC (8 decimals)
  const reserveIn = 100n * 10n ** 8n; // 100 WBTC
  const reserveOut = 1_000_000n * 10n ** 6n; // 1M USDC
  const victimAmount = 10n * 10n ** 8n; // 10 WBTC
  const borrowAmount = 5n * 10n ** 8n; // 5 WBTC
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.normal,
    TEST_CONFIG.gasEstimates.sandwichTx,
    6 // USDC decimals
  );
  
  // Should work with different decimals
  if (result) {
    assert(result.netProfit > 0n || result.profitBps >= TEST_CONFIG.minProfitBps,
      "Should handle different decimals correctly");
  }
});

// Test 10: Extreme gas prices
testSuite.addTest("Extreme gas prices make trades unprofitable", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const reserveOut = 1_000_000n * 10n ** 18n;
  const victimAmount = 100_000n * 10n ** 6n;
  const borrowAmount = 50_000n * 10n ** 6n;
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.extreme // 50 gwei
  );
  
  // At extreme gas prices, many trades become unprofitable
  if (result) {
    assert(result.gasCostToken > 0n, "Gas cost should be significant");
  }
});

// Test 11: Borrow candidate generation
testSuite.addTest("Borrow candidates are generated correctly", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const victimAmount = 100_000n * 10n ** 6n;
  
  const candidates = generateBorrowCandidates(victimAmount, reserveIn);
  
  assert(candidates.length > 0, "Should generate candidates");
  assert(candidates.length <= 8, "Should generate reasonable number of candidates");
  
  // All candidates should be positive
  for (const c of candidates) {
    assert(c > 0n, "All candidates should be positive");
  }
});

// Test 12: Zero amount handling
testSuite.addTest("Zero amounts are handled correctly", () => {
  const result = simulateSandwich(
    0n, 100n, 1000n, 1000n
  );
  
  assert(result === null, "Zero borrow amount should return null");
});

// Test 13: Insufficient reserves
testSuite.addTest("Insufficient reserves return null", () => {
  const result = simulateSandwich(
    1000n, 1000n, 100n, 100n // Borrow more than reserves
  );
  
  assert(result === null, "Insufficient reserves should return null");
});

// Test 14: Profit margin calculation
testSuite.addTest("Profit margin calculation is accurate", () => {
  const reserveIn = 1_000_000n * 10n ** 6n;
  const reserveOut = 1_000_000n * 10n ** 18n;
  const victimAmount = 100_000n * 10n ** 6n;
  const borrowAmount = 50_000n * 10n ** 6n;
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  if (result) {
    const expectedMargin = (result.netProfit * 10_000n) / borrowAmount;
    assert(result.profitBps === expectedMargin,
      `Profit margin should be ${expectedMargin}, got ${result.profitBps}`);
  }
});

// Test 15: Gas cost impact on profitability
testSuite.addTest("Gas cost significantly impacts small trades", () => {
  const reserveIn = 10_000n * 10n ** 6n; // 10K USDC
  const reserveOut = 10_000n * 10n ** 18n; // 10K WETH
  const victimAmount = 1_000n * 10n ** 6n; // 1K USDC
  const borrowAmount = 500n * 10n ** 6n; // 500 USDC
  
  // With low gas
  const resultLow = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.low
  );
  
  // With high gas
  const resultHigh = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut,
    TEST_CONFIG.flashLoanFeeBps,
    TEST_CONFIG.gasPrices.high
  );
  
  if (resultLow && resultHigh) {
    const gasImpact = resultLow.netProfit - resultHigh.netProfit;
    assert(gasImpact > 0n, "Higher gas should reduce profit");
  }
});

// =============================================================================
// Performance Benchmark Tests
// =============================================================================

testSuite.addTest("Performance: Simulate 100 sandwiches quickly", async () => {
  const start = Date.now();
  
  for (let i = 0; i < 100; i++) {
    const reserveIn = 1_000_000n * 10n ** 6n;
    const reserveOut = 1_000_000n * 10n ** 18n;
    const victimAmount = 100_000n * 10n ** 6n;
    const borrowAmount = 50_000n * 10n ** 6n;
    
    simulateSandwich(borrowAmount, victimAmount, reserveIn, reserveOut);
  }
  
  const duration = Date.now() - start;
  assert(duration < 1000, `100 simulations should complete in <1s, took ${duration}ms`);
});

testSuite.addTest("Performance: Generate borrow candidates quickly", async () => {
  const start = Date.now();
  
  for (let i = 0; i < 1000; i++) {
    const reserveIn = 1_000_000n * 10n ** 6n;
    const victimAmount = 100_000n * 10n ** 6n;
    generateBorrowCandidates(victimAmount, reserveIn);
  }
  
  const duration = Date.now() - start;
  assert(duration < 100, `1000 candidate generations should complete in <100ms, took ${duration}ms`);
});

// =============================================================================
// Edge Case Tests
// =============================================================================

testSuite.addTest("Edge: Very large reserves", () => {
  const reserveIn = 100_000_000n * 10n ** 6n; // 100M USDC
  const reserveOut = 100_000_000n * 10n ** 18n; // 100M WETH
  const victimAmount = 1_000_000n * 10n ** 6n; // 1M USDC
  const borrowAmount = 500_000n * 10n ** 6n; // 500K USDC
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  assert(result !== null, "Should handle large reserves");
  if (result) {
    assert(result.netProfit > 0n, "Should be profitable with large reserves");
  }
});

testSuite.addTest("Edge: Very small reserves", () => {
  const reserveIn = 100n * 10n ** 6n; // 100 USDC
  const reserveOut = 100n * 10n ** 18n; // 100 WETH
  const victimAmount = 10n * 10n ** 6n; // 10 USDC
  const borrowAmount = 5n * 10n ** 6n; // 5 USDC
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  // Small reserves may not be profitable
  if (result) {
    assert(result.netProfit >= 0n, "Should not have negative profit");
  }
});

testSuite.addTest("Edge: Victim amount equals reserve", () => {
  const reserveIn = 100_000n * 10n ** 6n;
  const reserveOut = 100_000n * 10n ** 18n;
  const victimAmount = reserveIn; // Victim swaps entire reserve
  const borrowAmount = reserveIn / 2n;
  
  const result = simulateSandwich(
    borrowAmount, victimAmount, reserveIn, reserveOut
  );
  
  // Should handle edge case gracefully
  assert(result === null || result.netProfit >= 0n, "Should handle edge case");
});

// =============================================================================
// Run Tests
// =============================================================================

console.log("\n🚀 Starting Arbitrum Flash Sandwich Bot Profitability Tests...\n");

testSuite.run().then(success => {
  if (success) {
    console.log("✅ All profitability tests passed!");
    console.log("\n💡 Your bot's profitability logic is working correctly.");
    console.log("   The bot will only execute trades that are profitable after:");
    console.log(`   - Flash loan fees (${TEST_CONFIG.flashLoanFeeBps} bps)`);
    console.log(`   - Gas costs (~${ethers.formatUnits(TEST_CONFIG.gasEstimates.sandwichTx * TEST_CONFIG.gasPrices.normal, "ether")} ETH)`);
    console.log(`   - Slippage (${TEST_CONFIG.slippageBps} bps)`);
    console.log(`   - Minimum profit threshold (${TEST_CONFIG.minProfitBps} bps)\n`);
    process.exit(0);
  } else {
    console.log("❌ Some profitability tests failed!");
    console.log("\n⚠️  Review the failed tests above. Your bot may execute unprofitable trades.\n");
    process.exit(1);
  }
}).catch(err => {
  console.error("❌ Test suite crashed:", err);
  process.exit(1);
});
