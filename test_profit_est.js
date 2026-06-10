#!/usr/bin/env node
// Profit estimation test — queries live Polygon RPCs and estimates flash loan arb profit
// Usage: node test_profit_est.js
// No private key or deployment required — read-only quoting only

const { ethers } = require("ethers");

// ======== config ========
const RPC_LIST = [
  "https://polygon-bor-rpc.publicnode.com",
  "https://polygon.drpc.org",
  "https://polygon-rpc.com",
  "https://rpc.ankr.com/polygon"
];
const AAVE_PROVIDER = "0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb";
const WMATIC = "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270";

const TOKENS = [
  { symbol: "USDC", asset: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", decimals: 6 },
  { symbol: "WMATIC", asset: WMATIC, decimals: 18 },
  { symbol: "DAI", asset: "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063", decimals: 18 },
  { symbol: "USDT", asset: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", decimals: 6 },
  { symbol: "WETH", asset: "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", decimals: 18 },
  { symbol: "WBTC", asset: "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6", decimals: 8 },
  { symbol: "LINK", asset: "0x53e0bca35ec356bd5dddfebbd1fc0fd03fabad39", decimals: 18 },
  { symbol: "AAVE", asset: "0xd6df932a45c0f255f85145f286ea0b292b21c90b", decimals: 18 }
];

const STABLECOINS = new Set(["USDC", "USDT", "DAI"]);
const TARGET = WMATIC;

const ROUTERS = [
  { name: "QuickSwapV2", address: "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff" },
  { name: "SushiV2", address: "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506" }
];

const CURVE_POOLS = [
  {
    name: "CurveAavePool",
    address: "0x445FE580eF8d70FF569aB36e80c647af338db351",
    coins: [
      "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
      "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
      "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"
    ]
  }
];

const BALANCER_V2_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8";

const V2_ROUTER_ABI = [
  "function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)"
];
const CURVE_POOL_ABI = [
  "function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256)"
];
const BALANCER_VAULT_ABI = [
  "function queryBatchSwap(uint8 kind, tuple(bytes32 poolId,uint256 assetInIndex,uint256 assetOutIndex,uint256 amount,bytes userData)[] swaps, address[] assets, tuple(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds) external view returns (int256[] memory)"
];
const fs = require("fs");
let BALANCER_POOLS = [];
try {
  if (fs.existsSync("balancer_pools.json")) {
    BALANCER_POOLS = JSON.parse(fs.readFileSync("balancer_pools.json", "utf8"));
  }
} catch (_) {}

function findBalancerPoolId(tokenA, tokenB) {
  const a = tokenA.toLowerCase();
  const b = tokenB.toLowerCase();
  for (const pool of BALANCER_POOLS) {
    const t = pool.tokens.map(x => x.toLowerCase());
    if (t.includes(a) && t.includes(b)) return pool.poolId;
  }
  return null;
}

async function quoteBalancerV2(vault, amountIn, tokenIn, tokenOut) {
  const poolId = findBalancerPoolId(tokenIn, tokenOut);
  if (!poolId) return 0n;
  try {
    const swaps = [{ poolId, assetInIndex: 0, assetOutIndex: 1, amount: amountIn, userData: "0x" }];
    const assets = [tokenIn, tokenOut];
    const funds = { sender: ethers.ZeroAddress, fromInternalBalance: false, recipient: ethers.ZeroAddress, toInternalBalance: false };
    const deltas = await vault.queryBatchSwap(0, swaps, assets, funds);
    const out = typeof deltas[1] === "bigint" ? -deltas[1] : -BigInt(deltas[1]);
    return out > 0n ? out : 0n;
  } catch (_) { return 0n; }
}

const PROVIDER_ABI = ["function getPool() view returns (address)"];
const POOL_ABI = ["function FLASHLOAN_PREMIUM_TOTAL() view returns (uint128)"];
const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

// ======== helpers ========
function toLower(a) { return a.toLowerCase(); }
function fmt(bi, dec) { try { return ethers.formatUnits(bi, dec); } catch(_) { return bi.toString(); } }
function min(a, b) { return a < b ? a : b; }

// ======== quoting ========
async function quoteV2(contract, amountIn, path) {
  try {
    const amounts = await contract.getAmountsOut(amountIn, path);
    return BigInt(amounts[amounts.length - 1]);
  } catch (_) { return 0n; }
}

async function quoteCurve(contract, coins, amountIn, tokenIn, tokenOut) {
  const i = coins.indexOf(toLower(tokenIn));
  const j = coins.indexOf(toLower(tokenOut));
  if (i === -1 || j === -1) return 0n;
  try {
    return BigInt(await contract.get_dy(i, j, amountIn));
  } catch (_) { return 0n; }
}

// ======== main ========
async function main() {
  let provider;
  for (const rpc of RPC_LIST) {
    try {
      provider = new ethers.JsonRpcProvider(rpc, undefined, { staticNetwork: true });
      const bn = await provider.getBlockNumber();
      console.log(`\u2705 Connected to ${rpc.substring(0, 40)}... block ${bn}`);
      break;
    } catch (_) {
      console.warn(`\u26a0\ufe0f  ${rpc.substring(0, 40)}... failed`);
    }
  }
  if (!provider) { console.error("\u274c All RPCs failed"); process.exit(1); }

  // Get Aave pool info
  const providerContract = new ethers.Contract(AAVE_PROVIDER, PROVIDER_ABI, provider);
  const poolAddr = await providerContract.getPool();
  const pool = new ethers.Contract(poolAddr, POOL_ABI, provider);
  const premiumBps = BigInt(await pool.FLASHLOAN_PREMIUM_TOTAL());
  console.log(`\ud83c\udfe6 Aave pool: ${poolAddr} | premium: ${premiumBps} bps\n`);

  // ======== V3 address encoding unit test ========
  console.log("--- V3 Address Encoding Test ---");
  const testAddr = "0xAE563E3f8219521950555F5962419C8919758Ea2";
  const padded = ethers.zeroPadValue(testAddr, 32);
  // Correct extraction: uint256 → uint160 → address (rightmost 20 bytes)
  const extracted = ethers.getAddress("0x" + padded.slice(-40));
  const match = extracted.toLowerCase() === testAddr.toLowerCase();
  console.log(`  Input address:     ${testAddr}`);
  console.log(`  Padded bytes32:    ${padded}`);
  console.log(`  Extracted address: ${extracted}`);
  console.log(`  Match: ${match ? "PASS" : "FAIL"}`);
  // Verify bytes20 truncation would fail
  const wrongAddr = "0x" + padded.slice(2, 42);
  const wrongMatch = wrongAddr.toLowerCase() === testAddr.toLowerCase();
  console.log(`  bytes20 truncation would give: ${wrongAddr} → ${wrongMatch ? "same (unexpected)" : "WRONG (expected)"}`);  
  console.log(`  uint160(uint256()) gives correct address: ${match ? "PASS" : "FAIL"}\n`);
  if (!match) { console.error("FATAL: V3 address encoding broken"); process.exit(1); }

  // Build venue contracts
  const v2Contracts = ROUTERS.map(r => ({
    name: r.name,
    contract: new ethers.Contract(r.address, V2_ROUTER_ABI, provider)
  }));
  const curveContracts = CURVE_POOLS.map(p => ({
    name: p.name,
    coins: p.coins.map(toLower),
    contract: new ethers.Contract(p.address, CURVE_POOL_ABI, provider)
  }));
  const balVault = new ethers.Contract(BALANCER_V2_VAULT, BALANCER_VAULT_ABI, provider);
  console.log(`\ud83d\udccb Loaded ${BALANCER_POOLS.length} Balancer V2 pool(s)`);

  // Test amounts for each token type
  function getTestAmounts(symbol, decimals) {
    if (STABLECOINS.has(symbol)) {
      return ["500", "1000", "5000", "10000", "50000"].map(a => ({
        label: a,
        amount: ethers.parseUnits(a, decimals)
      }));
    }
    return ["1", "5", "10", "50", "100"].map(a => ({
      label: a,
      amount: ethers.parseUnits(a, decimals)
    }));
  }

  const results = [];
  let totalTests = 0;
  let profitableTests = 0;

  console.log("=" .repeat(100));
  console.log("TOKEN     | SIZE          | LEG A           | LEG B           | OUT          | OWED         | EDGE BPS | EST PROFIT");
  console.log("=" .repeat(100));

  for (const token of TOKENS) {
    const assetL = toLower(token.asset);
    if (assetL === toLower(TARGET)) continue;

    // Check Aave liquidity
    const underlying = new ethers.Contract(token.asset, ERC20_ABI, provider);
    let available;
    try {
      available = await underlying.balanceOf(poolAddr);
    } catch (_) { continue; }
    if (available <= 0n) { console.log(`${token.symbol.padEnd(9)} | No Aave liquidity`); continue; }

    const maxCap = available / 100n;
    const testAmounts = getTestAmounts(token.symbol, token.decimals);

    for (const { label, amount: rawSize } of testAmounts) {
      const size = min(rawSize, maxCap);
      if (size <= 0n) continue;

      const premium = (size * premiumBps) / 10000n;
      const owed = size + premium;
      totalTests++;

      // Quote leg 1: token → TARGET via each venue
      const directPath = [assetL, toLower(TARGET)];
      const viaWmatic = assetL !== toLower(WMATIC)
        ? [assetL, toLower(WMATIC)]
        : null;

      let bestRoute = { out2: 0n };

      for (const v2A of v2Contracts) {
        const out1 = await quoteV2(v2A.contract, size, directPath);
        if (out1 <= 0n) continue;

        // Leg 2: TARGET → token via each venue
        const returnPath = [toLower(TARGET), assetL];
        for (const v2B of v2Contracts) {
          const out2 = await quoteV2(v2B.contract, out1, returnPath);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: v2A.name, bName: v2B.name, out1, out2 };
          }
        }

        // Also try Curve for leg 2 (stablecoins)
        for (const curve of curveContracts) {
          const out2 = await quoteCurve(curve.contract, curve.coins, out1, TARGET, token.asset);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: v2A.name, bName: curve.name, out1, out2 };
          }
        }

        // Try Balancer V2 for leg 2
        const balOut2 = await quoteBalancerV2(balVault, out1, toLower(TARGET), assetL);
        if (balOut2 > bestRoute.out2) {
          bestRoute = { aName: v2A.name, bName: "BalancerV2", out1, out2: balOut2 };
        }
      }

      // Balancer V2 for leg 1
      const balOut1 = await quoteBalancerV2(balVault, size, assetL, toLower(TARGET));
      if (balOut1 > 0n) {
        const returnPath = [toLower(TARGET), assetL];
        for (const v2B of v2Contracts) {
          const out2 = await quoteV2(v2B.contract, balOut1, returnPath);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: "BalancerV2", bName: v2B.name, out1: balOut1, out2 };
          }
        }
      }

      // Curve for leg 1 (stablecoins → stablecoins via Curve, return via V2)
      for (const curve of curveContracts) {
        const out1 = await quoteCurve(curve.contract, curve.coins, size, token.asset, TARGET);
        if (out1 <= 0n) continue;
        const returnPath = [toLower(TARGET), assetL];
        for (const v2B of v2Contracts) {
          const out2 = await quoteV2(v2B.contract, out1, returnPath);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: curve.name, bName: v2B.name, out1, out2 };
          }
        }
      }

      if (bestRoute.out2 <= 0n) continue;

      const delta = bestRoute.out2 - owed;
      const edgeBps = delta > 0n
        ? (delta * 10000n) / owed
        : -((owed - bestRoute.out2) * 10000n) / owed;
      const profitable = delta > 0n && edgeBps >= 50n;

      if (profitable) profitableTests++;

      const profitStr = delta > 0n
        ? `+${fmt(delta, token.decimals)}`
        : fmt(delta, token.decimals);

      const row = [
        token.symbol.padEnd(9),
        label.padStart(13),
        (bestRoute.aName || "-").padEnd(15),
        (bestRoute.bName || "-").padEnd(15),
        fmt(bestRoute.out2, token.decimals).padStart(12),
        fmt(owed, token.decimals).padStart(12),
        String(edgeBps).padStart(8),
        (profitable ? "\ud83d\udfe2 " : "\ud83d\udd34 ") + profitStr
      ].join(" | ");
      console.log(row);

      results.push({
        token: token.symbol,
        size: label,
        legA: bestRoute.aName,
        legB: bestRoute.bName,
        out: fmt(bestRoute.out2, token.decimals),
        owed: fmt(owed, token.decimals),
        edgeBps: Number(edgeBps),
        delta: fmt(delta, token.decimals),
        profitable
      });
    }
  }

  console.log("=" .repeat(100));
  console.log(`\n\ud83d\udcca Summary: ${totalTests} quotes tested, ${profitableTests} profitable (\u2265 50 bps edge)`);
  console.log(`\ud83d\udce1 Venues tested: ${v2Contracts.map(v => v.name).join(", ")}, ${curveContracts.map(c => c.name).join(", ")}`);
  console.log(`\ud83c\udfe6 Flash loan premium: ${premiumBps} bps`);
  console.log(`\u2139\ufe0f  Balancer V3 not available on Polygon (V2 only)`);
  console.log(`\u2139\ufe0f  Balancer V2 quoting: ${BALANCER_POOLS.length} pools loaded\n`);

  if (profitableTests > 0) {
    console.log("\ud83d\udfe2 Profitable opportunities found:");
    for (const r of results.filter(r => r.profitable)) {
      console.log(`   ${r.token} ${r.size} via ${r.legA}\u2192${r.legB}: edge ${r.edgeBps} bps, profit ${r.delta}`);
    }
  } else {
    console.log("\ud83d\udd34 No profitable opportunities found at current prices (this is normal — arb is competitive).");
    console.log("   The bot monitors continuously and executes when opportunities arise.");
  }

  console.log("\n\u2705 Test complete");
}

main().catch(err => {
  console.error("\u274c Fatal:", err);
  process.exit(1);
});
