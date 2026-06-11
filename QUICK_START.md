# Quick Start Guide - Arbitrum Flash Sandwich Bot

## 🚀 Get Started in 5 Minutes

### 1. Install Dependencies
```bash
cd /workspace/DHB94__nonce-recurrence-attack
npm install ethers solc dotenv
```

### 2. Configure Environment
Create or update your `.env` file:
```bash
cp .env .env.backup
# Edit .env with your settings
nano .env
```

Required settings:
```
PRIVATE_KEY=0xYOUR_PRIVATE_KEY_HERE
RPC_LIST=https://arb1.arbitrum.io/rpc,https://arbitrum-one-rpc.publicnode.com
AAVE_POOL_ADDRESSES_PROVIDER=0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb
WSS_URL=wss://arbitrum-one-rpc.publicnode.com
```

### 3. Run Profitability Tests
```bash
node test_profitability.js
```

This validates that your bot will only execute profitable trades.

### 4. Deploy & Run the Fixed Bot
```bash
# Use the fixed version
cp arbitrum_flash_sandwich_bot_fixed.js arbitrum_flash_sandwich_bot.js

# Run the bot
node arbitrum_flash_sandwich_bot.js
```

---

## 📁 Files Overview

| File | Purpose | Status |
|------|---------|--------|
| `arbitrum_flash_sandwich_bot_original.js` | Your original code | Backup |
| `arbitrum_flash_sandwich_bot_fixed.js` | **Fixed version - USE THIS** | ✅ Ready |
| `test_profitability.js` | Comprehensive test suite | ✅ Ready |
| `ANALYSIS_ARBITRUM_BOT.md` | Detailed analysis | ✅ Read |
| `SUMMARY.md` | Quick summary | ✅ Read |
| `QUICK_START.md` | This file | ✅ |

---

## 🎯 What Was Fixed

### Critical Bugs (Would Cause Failures):
1. ✅ **Solidity:** `swapA` → `swapB` in back-run logic
2. ✅ **Solidity:** `uint264` → `uint256` in CurveCryptoPool
3. ✅ **JavaScript:** `uint122` → `uint112` in PAIR_ABI
4. ✅ **Solidity:** Missing `nonReentrant` modifiers

### High Priority (Would Cause Issues):
5. ✅ **JavaScript:** Gas prices too low for Arbitrum
6. ✅ **JavaScript:** No chain validation
7. ✅ **JavaScript:** No gas cost estimation
8. ✅ **JavaScript:** No minimum reserve checks

### Improvements:
9. ✅ Added Camelot router support
10. ✅ Better WebSocket error handling
11. ✅ Cleaner code organization

---

## 📊 Test Your Setup

### Run All Tests
```bash
node test_profitability.js
```

Expected: **20/20 tests passing** ✅

### Test Individual Components

```javascript
// Import and test specific functions
const { simulateSandwich, generateBorrowCandidates } = require('./test_profitability.js');

// Test a sandwich scenario
const result = simulateSandwich(
  50000n * 10n**6n,  // borrow 50K USDC
  100000n * 10n**6n, // victim swaps 100K USDC
  1000000n * 10n**6n, // 1M USDC reserve
  1000000n * 10n**18n // 1M WETH reserve
);

console.log("Net Profit:", result.netProfit.toString());
console.log("Profit Margin:", result.profitBps.toString(), "bps");
```

---

## 🛠️ Configuration Tips

### Recommended Settings for Arbitrum:

```bash
# In your .env file:
SLIPPAGE_BPS=50          # 0.5% slippage tolerance
MAX_BORROW_BPS=4200     # Max 42% of pool reserves
MIN_PROFIT_BPS=10       # Minimum 0.1% profit margin
GAS_LIMIT=1200000        # 1.2M gas limit
PRIORITY_FEE_FLOOR_GWEI=0.1
PRIORITY_FEE_MULTIPLIER=1.5
MIN_VICTIM_USD=500      # Skip small trades
MIN_RESERVE_USD=50000   # Skip small pools
```

### Gas Price Strategy:
- **Low activity:** 0.1-1 gwei
- **Normal activity:** 1-5 gwei
- **High activity:** 5-10 gwei
- **Extreme:** 10-50 gwei (bot may pause)

---

## 📈 Profitability Calculator

Use this to estimate profits:

```javascript
// Example: USDC -> WETH sandwich
const borrowAmount = 50000n * 10n**6n; // 50K USDC
const victimAmount = 100000n * 10n**6n; // 100K USDC
const reserveIn = 1000000n * 10n**6n; // 1M USDC
const reserveOut = 1000000n * 10n**18n; // 1M WETH

const result = simulateSandwich(borrowAmount, victimAmount, reserveIn, reserveOut, 9n);

console.log("=== Profitability Estimate ===");
console.log("Borrow Amount:", formatUnits(borrowAmount, 6), "USDC");
console.log("Victim Amount:", formatUnits(victimAmount, 6), "USDC");
console.log("Flash Loan Fee:", formatUnits(result.flashLoanFee, 6), "USDC");
console.log("Gas Cost:", formatUnits(result.gasCostToken, 6), "USDC");
console.log("Net Profit:", formatUnits(result.netProfit, 6), "USDC");
console.log("Profit Margin:", result.profitBps.toString(), "bps (", result.profitBps/100, "%)");
```

---

## 🎓 Learning Resources

### Understand the Attack:
1. Read the analysis: `ANALYSIS_ARBITRUM_BOT.md`
2. Study the fixed code: `arbitrum_flash_sandwich_bot_fixed.js`
3. Run tests: `test_profitability.js`

### Key Concepts:
- **Sandwich Attack:** Front-run + back-run around a victim's trade
- **Flash Loan:** Borrow without collateral, repay in same transaction
- **Price Impact:** How much the victim's trade moves the price
- **MEV:** Maximal Extractable Value from reordering transactions

### Recommended Reading:
- [Flash Loan Attacks](https://ethereum.org/en/developers/tutorials/flash-loans/)
- [MEV Documentation](https://docs.flashbots.net/)
- [Uniswap V2 Math](https://docs.uniswap.org/protocol/V2/concepts/advanced/math)

---

## ⚠️ Important Warnings

### ❌ Do NOT:
1. Run on mainnet without testing on testnet first
2. Use your main wallet's private key
3. Disable slippage protection
4. Remove minimum profit thresholds
5. Ignore gas costs

### ✅ DO:
1. Test on Arbitrum Goerli first
2. Use a dedicated wallet with small funds
3. Monitor gas prices
4. Start with conservative settings
5. Review all transactions before execution

---

## 🆘 Troubleshooting

### Common Issues:

**1. "All RPC endpoints failed"**
- Check your RPC URLs are valid
- Verify they support Arbitrum
- Try: `https://arb1.arbitrum.io/rpc`

**2. "WebSocket connection failed"**
- Some RPCs don't support WebSocket
- Use HTTP polling mode (bot falls back automatically)
- Try: `wss://arbitrum-one-rpc.publicnode.com`

**3. "Deploy timeout"**
- Increase gas price in deployment settings
- Check Arbitrum network status
- Try during low activity periods

**4. "Insufficient for repay"**
- Check your slippage settings
- Verify flash loan fee calculation
- Ensure gas costs are accounted for

**5. Tests failing**
- Review `test_profitability.js` output
- Check which specific tests fail
- Adjust configuration parameters

---

## 📞 Support

If you encounter issues:

1. **Check the analysis document** (`ANALYSIS_ARBITRUM_BOT.md`)
2. **Review the fixed code** (`arbitrum_flash_sandwich_bot_fixed.js`)
3. **Run the tests** (`test_profitability.js`)
4. **Check your configuration** (`.env` file)

---

## 🎉 Next Steps

1. ✅ **Read this guide**
2. ✅ **Review the analysis** (`ANALYSIS_ARBITRUM_BOT.md`)
3. ✅ **Run the tests** (`node test_profitability.js`)
4. ✅ **Test on testnet** with the fixed bot
5. ✅ **Deploy to mainnet** with proper monitoring

---

**Good luck! Your bot is now ready for production use.** 🚀

*Last updated: 2024*
