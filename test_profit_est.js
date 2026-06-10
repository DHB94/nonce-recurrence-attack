#!/usr/bin/env node
// Profit estimation test — queries live Arbitrum RPCs and estimates flash loan arb profit
// Usage: node test_profit_est.js
// No private key or deployment required — read-only quoting only

const { ethers } = require("ethers");
const fs = require("fs");

// ======== config (Arbitrum) ========
const RPC_LIST = [
  "https://arb1.arbitrum.io/rpc",
  "https://arbitrum-one-rpc.publicnode.com",
  "https://arbitrum.drpc.org",
  "https://rpc.ankr.com/arbitrum"
];
const AAVE_PROVIDER = "0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb";
const WETH = "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1";

const TOKENS = [
  { symbol: "USDC",   asset: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6 },
  { symbol: "USDC.e", asset: "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", decimals: 6 },
  { symbol: "WETH",   asset: WETH, decimals: 18 },
  { symbol: "DAI",    asset: "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", decimals: 18 },
  { symbol: "USDT",   asset: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6 },
  { symbol: "WBTC",   asset: "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f", decimals: 8 },
  { symbol: "ARB",    asset: "0x912CE59144191C1204E64559FE8253a0e49E6548", decimals: 18 },
  { symbol: "LINK",   asset: "0xf97f4df75117a78c1A5a0DBb814Af92458539FB4", decimals: 18 },
  { symbol: "GMX",    asset: "0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a", decimals: 18 },
  { symbol: "wstETH", asset: "0x5979D7b546E38E414F7E9822514be443A4800529", decimals: 18 }
];

const STABLECOINS = new Set(["USDC", "USDC.e", "USDT", "DAI"]);
const TARGET = WETH;

const ROUTERS = [
  { name: "UniswapV2", address: "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24" },
  { name: "SushiV2",   address: "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506" }
];

const CURVE_POOLS = [
  {
    name: "Curve2Pool",
    address: "0x7f90122BF0700F9E7e1F688fe926940E8839F353",
    coins: [
      "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8",
      "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
    ]
  }
];

// CurveCrypto pools use uint256 indices
const CURVE_CRYPTO_POOLS = [
  {
    name: "CurveTricrypto",
    address: "0x960ea3e3C7FB317332d990873d354E18d7645590",
    coins: [
      "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
      "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f",
      "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"
    ]
  }
];

const BALANCER_V2_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8";
const BALANCER_V3_ROUTER = "0xEAedc32a51c510d35ebC11088fD5fF2b47aACF2E";

const V2_ROUTER_ABI = [
  "function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)"
];
const CURVE_POOL_ABI = [
  "function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256)"
];
const CURVE_CRYPTO_ABI = [
  "function get_dy(uint256 i, uint256 j, uint256 dx) external view returns (uint256)"
];
const BALANCER_VAULT_ABI = [
  "function queryBatchSwap(uint8 kind, tuple(bytes32 poolId,uint256 assetInIndex,uint256 assetOutIndex,uint256 amount,bytes userData)[] swaps, address[] assets, tuple(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds) external view returns (int256[] memory)"
];
const BALANCER_V3_ROUTER_ABI = [
  "function querySwapSingleTokenExactIn(address pool, address tokenIn, address tokenOut, uint256 exactAmountIn, address sender, bytes calldata userData) external returns (uint256 amountOut)"
];

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

function findBalancerV3Pool(tokenA, tokenB) {
  const a = tokenA.toLowerCase();
  const b = tokenB.toLowerCase();
  for (const pool of BALANCER_POOLS) {
    if (!pool.v3Address) continue;
    const t = pool.tokens.map(x => x.toLowerCase());
    if (t.includes(a) && t.includes(b)) return pool.v3Address;
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

async function quoteBalancerV3(router, amountIn, tokenIn, tokenOut) {
  const poolAddr = findBalancerV3Pool(tokenIn, tokenOut);
  if (!poolAddr) return { out: 0n, poolAddr: null };
  try {
    const out = await router.querySwapSingleTokenExactIn.staticCall(
      poolAddr, tokenIn, tokenOut, amountIn, ethers.ZeroAddress, "0x"
    );
    return { out: BigInt(out), poolAddr };
  } catch (_) {
    return { out: 0n, poolAddr };
  }
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

async function quoteCurveCrypto(contract, coins, amountIn, tokenIn, tokenOut) {
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
  const extracted = ethers.getAddress("0x" + padded.slice(-40));
  const match = extracted.toLowerCase() === testAddr.toLowerCase();
  console.log(`  Input address:     ${testAddr}`);
  console.log(`  Padded bytes32:    ${padded}`);
  console.log(`  Extracted address: ${extracted}`);
  console.log(`  Match: ${match ? "PASS" : "FAIL"}`);
  const wrongAddr = "0x" + padded.slice(2, 42);
  const wrongMatch = wrongAddr.toLowerCase() === testAddr.toLowerCase();
  console.log(`  bytes20 truncation would give: ${wrongAddr} \u2192 ${wrongMatch ? "same (unexpected)" : "WRONG (expected)"}`);
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
  const curveCryptoContracts = CURVE_CRYPTO_POOLS.map(p => ({
    name: p.name,
    coins: p.coins.map(toLower),
    contract: new ethers.Contract(p.address, CURVE_CRYPTO_ABI, provider)
  }));
  const balVault = new ethers.Contract(BALANCER_V2_VAULT, BALANCER_VAULT_ABI, provider);
  const balV3Router = new ethers.Contract(BALANCER_V3_ROUTER, BALANCER_V3_ROUTER_ABI, provider);
  console.log(`\ud83d\udccb Loaded ${BALANCER_POOLS.length} Balancer pool(s)`);
  const v3Pools = BALANCER_POOLS.filter(p => p.v3Address);
  console.log(`   V3 pools: ${v3Pools.length}, V2 pools: ${BALANCER_POOLS.filter(p => p.poolId).length}`);

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

  console.log("=" .repeat(110));
  console.log("TOKEN     | SIZE          | LEG A           | LEG B           | OUT          | OWED         | EDGE BPS | EST PROFIT");
  console.log("=" .repeat(110));

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

      let bestRoute = { out2: 0n };

      // V2 routers for leg 1
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

        // Curve stable for leg 2
        for (const curve of curveContracts) {
          const out2 = await quoteCurve(curve.contract, curve.coins, out1, TARGET, token.asset);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: v2A.name, bName: curve.name, out1, out2 };
          }
        }

        // CurveCrypto for leg 2
        for (const cc of curveCryptoContracts) {
          const out2 = await quoteCurveCrypto(cc.contract, cc.coins, out1, TARGET, token.asset);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: v2A.name, bName: cc.name, out1, out2 };
          }
        }

        // Balancer V2 for leg 2
        const balOut2 = await quoteBalancerV2(balVault, out1, toLower(TARGET), assetL);
        if (balOut2 > bestRoute.out2) {
          bestRoute = { aName: v2A.name, bName: "BalancerV2", out1, out2: balOut2 };
        }

        // Balancer V3 for leg 2
        const balV3Out2 = await quoteBalancerV3(balV3Router, out1, toLower(TARGET), assetL);
        if (balV3Out2.out > bestRoute.out2) {
          bestRoute = { aName: v2A.name, bName: "BalancerV3", out1, out2: balV3Out2.out };
        }
      }

      // CurveCrypto for leg 1
      for (const cc of curveCryptoContracts) {
        const out1 = await quoteCurveCrypto(cc.contract, cc.coins, size, token.asset, TARGET);
        if (out1 <= 0n) continue;
        const returnPath = [toLower(TARGET), assetL];
        for (const v2B of v2Contracts) {
          const out2 = await quoteV2(v2B.contract, out1, returnPath);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: cc.name, bName: v2B.name, out1, out2 };
          }
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

      // Balancer V3 for leg 1
      const balV3Out1 = await quoteBalancerV3(balV3Router, size, assetL, toLower(TARGET));
      if (balV3Out1.out > 0n) {
        const returnPath = [toLower(TARGET), assetL];
        for (const v2B of v2Contracts) {
          const out2 = await quoteV2(v2B.contract, balV3Out1.out, returnPath);
          if (out2 > bestRoute.out2) {
            bestRoute = { aName: "BalancerV3", bName: v2B.name, out1: balV3Out1.out, out2 };
          }
        }
      }

      // Curve stable for leg 1
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

  console.log("=" .repeat(110));
  const venueList = [
    ...v2Contracts.map(v => v.name),
    ...curveContracts.map(c => c.name),
    ...curveCryptoContracts.map(c => c.name),
    "BalancerV2",
    "BalancerV3"
  ];
  console.log(`\n\ud83d\udcca Summary: ${totalTests} quotes tested, ${profitableTests} profitable (\u2265 50 bps edge)`);
  console.log(`\ud83d\udce1 Venues tested: ${venueList.join(", ")}`);
  console.log(`\ud83c\udfe6 Flash loan premium: ${premiumBps} bps`);
  console.log(`\u2139\ufe0f  Balancer V3 Router: ${BALANCER_V3_ROUTER}`);
  console.log(`\u2139\ufe0f  Balancer pools loaded: ${BALANCER_POOLS.length} (V3: ${v3Pools.length})\n`);

  if (profitableTests > 0) {
    console.log("\ud83d\udfe2 Profitable opportunities found:");
    for (const r of results.filter(r => r.profitable)) {
      console.log(`   ${r.token} ${r.size} via ${r.legA}\u2192${r.legB}: edge ${r.edgeBps} bps, profit ${r.delta}`);
    }
  } else {
    console.log("\ud83d\udd34 No profitable opportunities found at current prices (this is normal \u2014 arb is competitive).");
    console.log("   The bot monitors continuously and executes when opportunities arise.");
  }

  console.log("\n\u2705 Test complete");
}

main().catch(err => {
  console.error("\u274c Fatal:", err);
  process.exit(1);
});
