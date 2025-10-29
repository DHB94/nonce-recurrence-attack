// ======== requires & config ========
const fs = require("fs");
const solc = require("solc");
const { ethers } = require("ethers");
const dotenv = require("dotenv");
dotenv.config();

// ======== constants & RPC setup ========
const RPC_LIST = (process.env.RPC_LIST || process.env.WRITE_RPC || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);
if (RPC_LIST.length === 0) { console.error("Missing WRITE_RPC or RPC_LIST in .env"); process.exit(1); }
if (!process.env.PRIVATE_KEY) { console.error("Missing PRIVATE_KEY in .env"); process.exit(1); }
if (!process.env.AAVE_POOL_ADDRESSES_PROVIDER) { console.error("Missing AAVE_POOL_ADDRESSES_PROVIDER in .env"); process.exit(1); }
if (!process.env.TARGET_TOKEN) { console.error("Missing TARGET_TOKEN in .env"); process.exit(1); }

const TARGET = process.env.TARGET_TOKEN.toLowerCase();
const ADDRESS_FILE   = "FlashBotArb.address.txt";
const PROFIT_JSON    = "profit_per_token.json";
const PROFIT_CSV     = "profit_per_token.csv";
const MIN_ABS_PROFIT_NATIVE = ethers.parseUnits(process.env.MIN_ABS_PROFIT_NATIVE || "0.002", 18);

let rpcIndex = 0;
function getProvider() { return new ethers.JsonRpcProvider(RPC_LIST[rpcIndex]); }
function rotateRPC() {
  rpcIndex = (rpcIndex + 1) % RPC_LIST.length;
  console.warn("🔁 Switched RPC → " + RPC_LIST[rpcIndex]);
  return getProvider();
}
let provider = getProvider();
let wallet;
try { wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider); }
catch (_) { console.error("Invalid PRIVATE_KEY"); process.exit(1); }

// ======== Solidity contract source ========
const FLASHBOT_SOURCE = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface IPoolAddressesProvider { function getPool() external view returns (address); }
interface IPool {
    function flashLoan(address receiverAddress,address[] calldata assets,uint256[] calldata amounts,uint256[] calldata modes,address onBehalfOf,bytes calldata params,uint16 referralCode) external;
    function FLASHLOAN_PREMIUM_TOTAL() external view returns (uint128);
}
abstract contract FlashLoanReceiverBase {
    IPoolAddressesProvider public immutable ADDRESSES_PROVIDER;
    IPool public immutable POOL;
    constructor(IPoolAddressesProvider provider) {
        ADDRESSES_PROVIDER = provider;
        POOL = IPool(provider.getPool());
    }
    function executeOperation(address[] calldata assets,uint256[] calldata amounts,uint256[] calldata premiums,address initiator,bytes calldata params) external virtual returns (bool);
}
interface IERC20 {
    function approve(address spender,uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient,uint256 amount) external returns (bool);
}
interface IUniswapV2Router02 { function swapExactTokensForTokens(uint amountIn,uint amountOutMin,address[] calldata path,address to,uint deadline) external returns (uint[] memory amounts); }
interface ICurvePool { function exchange(int128 i,int128 j,uint256 dx,uint256 min_dy) external returns (uint256); }
interface IBalancerVault {
    struct SingleSwap { bytes32 poolId; uint8 kind; address assetIn; address assetOut; uint256 amount; bytes userData; }
    struct FundManagement { address sender; bool fromInternalBalance; address recipient; bool toInternalBalance; }
    function swap(SingleSwap calldata singleSwap, FundManagement calldata funds, uint256 limit, uint256 deadline) external returns (uint256);
    function flashLoan(address recipient,address[] calldata tokens,uint256[] calldata amounts,bytes calldata userData) external;
}
interface IBalancerFlashLoanRecipient {
    function receiveFlashLoan(address[] calldata tokens,uint256[] calldata amounts,uint256[] calldata feeAmounts,bytes calldata userData) external;
}

contract FlashBotArbMultiVenue is FlashLoanReceiverBase, IBalancerFlashLoanRecipient {
    address public immutable owner;
    address public immutable balancerVault;
    uint8 public pTypeA;
    uint8 public pTypeB;
    address public pRouterA;
    address public pRouterB;
    address[] public pPath1;
    address[] public pPath2;
    uint256 public pMinOut1;
    uint256 public pMinOut2;
    bytes32 public pBalPoolIdA;
    bytes32 public pBalPoolIdB;
    int128 public pCurveI1;
    int128 public pCurveJ1;
    int128 public pCurveI2;
    int128 public pCurveJ2;

    event Leg1(address router,uint8 legType,address[] path,uint256 amountIn,uint256 minOut,uint256 amountOut);
    event Leg2(address router,uint8 legType,address[] path,uint256 amountIn,uint256 minOut,uint256 amountOut);
    event Repay(uint256 owed,uint256 balance);
    event Profit(uint256 netGain);

    bool private inFlight;

    constructor(address provider,address balancer) FlashLoanReceiverBase(IPoolAddressesProvider(provider)) {
        owner = msg.sender;
        balancerVault = balancer;
    }

    function initiateFlashLoanMulti(
        address asset,uint256 amount,
        address routerA,address routerB,
        address[] calldata path1,address[] calldata path2,
        uint256 minOut1,uint256 minOut2,
        uint8 typeA,uint8 typeB,
        bytes32 balPoolIdA,bytes32 balPoolIdB,
        int128 curveI1,int128 curveJ1,int128 curveI2,int128 curveJ2
    ) external {
        require(msg.sender == owner,"only owner");
        require(routerA != address(0) && routerB != address(0),"invalid routers");
        require(path1.length >= 2 && path2.length >= 2,"invalid paths");
        require(typeA <= 2 && typeB <= 2,"invalid types");

        pRouterA = routerA; pRouterB = routerB;
        pPath1 = path1; pPath2 = path2;
        pMinOut1 = minOut1; pMinOut2 = minOut2;
        pTypeA = typeA; pTypeB = typeB;
        pBalPoolIdA = balPoolIdA; pBalPoolIdB = balPoolIdB;
        pCurveI1 = curveI1; pCurveJ1 = curveJ1; pCurveI2 = curveI2; pCurveJ2 = curveJ2;

        address[] memory assets = new address[](1); assets[0] = asset;
        uint256[] memory amounts = new uint256[](1); amounts[0] = amount;
        uint256[] memory modes = new uint256[](1); modes[0] = 0;

        require(!inFlight, "active");
        inFlight = true;
        POOL.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
        inFlight = false;

        _resetState();
    }

    function initiateBalancerFlashLoanMulti(
        address asset,uint256 amount,
        address routerA,address routerB,
        address[] calldata path1,address[] calldata path2,
        uint256 minOut1,uint256 minOut2,
        uint8 typeA,uint8 typeB,
        bytes32 balPoolIdA,bytes32 balPoolIdB,
        int128 curveI1,int128 curveJ1,int128 curveI2,int128 curveJ2
    ) external {
        require(msg.sender == owner,"only owner");
        require(balancerVault != address(0),"balancer disabled");
        require(routerA != address(0) && routerB != address(0),"invalid routers");
        require(path1.length >= 2 && path2.length >= 2,"invalid paths");
        require(typeA <= 2 && typeB <= 2,"invalid types");

        pRouterA = routerA; pRouterB = routerB;
        pPath1 = path1; pPath2 = path2;
        pMinOut1 = minOut1; pMinOut2 = minOut2;
        pTypeA = typeA; pTypeB = typeB;
        pBalPoolIdA = balPoolIdA; pBalPoolIdB = balPoolIdB;
        pCurveI1 = curveI1; pCurveJ1 = curveJ1; pCurveI2 = curveI2; pCurveJ2 = curveJ2;

        address[] memory tokens = new address[](1); tokens[0] = asset;
        uint256[] memory amounts = new uint256[](1); amounts[0] = amount;

        require(!inFlight, "active");
        inFlight = true;
        IBalancerVault(balancerVault).flashLoan(address(this), tokens, amounts, "");
        inFlight = false;

        _resetState();
    }

    function executeOperation(address[] calldata assets,uint256[] calldata amounts,uint256[] calldata premiums,address,bytes calldata) external override returns (bool) {
        address asset = assets[0]; uint256 amount = amounts[0];
        _processLoan(asset, amount, premiums[0], address(POOL), true);
        return true;
    }

    function receiveFlashLoan(address[] calldata tokens,uint256[] calldata amounts,uint256[] calldata feeAmounts,bytes calldata) external override {
        require(msg.sender == balancerVault, "invalid sender");
        require(tokens.length == 1 && amounts.length == 1 && feeAmounts.length == 1, "multi token not supported");
        _processLoan(tokens[0], amounts[0], feeAmounts[0], msg.sender, false);
    }

    function _processLoan(address asset,uint256 amount,uint256 premium,address repayTarget,bool lenderPulls) internal {
        uint256 out1 = 0;
        if (pTypeA == 0) {
            IERC20(asset).approve(pRouterA, amount);
            uint256 before1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this));
            IUniswapV2Router02(pRouterA).swapExactTokensForTokens(amount, pMinOut1, pPath1, address(this), block.timestamp);
            out1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this)) - before1;
        } else if (pTypeA == 1) {
            IERC20(asset).approve(pRouterA, amount);
            out1 = ICurvePool(pRouterA).exchange(pCurveI1, pCurveJ1, amount, pMinOut1);
        } else {
            IERC20(asset).approve(pRouterA, amount);
            IBalancerVault.SingleSwap memory swapA = IBalancerVault.SingleSwap({
                poolId: pBalPoolIdA, kind: 0, assetIn: pPath1[0], assetOut: pPath1[1], amount: amount, userData: ""
            });
            IBalancerVault.FundManagement memory fundsA = IBalancerVault.FundManagement({
                sender: address(this), fromInternalBalance: false, recipient: address(this), toInternalBalance: false
            });
            out1 = IBalancerVault(pRouterA).swap(swapA, fundsA, pMinOut1, block.timestamp);
        }
        emit Leg1(pRouterA, pTypeA, pPath1, amount, pMinOut1, out1);

        uint256 out2 = 0;
        if (pTypeB == 0) {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            uint256 before2 = IERC20(asset).balanceOf(address(this));
            IUniswapV2Router02(pRouterB).swapExactTokensForTokens(out1, pMinOut2, pPath2, address(this), block.timestamp);
            out2 = IERC20(asset).balanceOf(address(this)) - before2;
        } else if (pTypeB == 1) {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            out2 = ICurvePool(pRouterB).exchange(pCurveI2, pCurveJ2, out1, pMinOut2);
        } else {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            IBalancerVault.SingleSwap memory swapB = IBalancerVault.SingleSwap({
                poolId: pBalPoolIdB, kind: 0, assetIn: pPath2[0], assetOut: pPath2[1], amount: out1, userData: ""
            });
            IBalancerVault.FundManagement memory fundsB = IBalancerVault.FundManagement({
                sender: address(this), fromInternalBalance: false, recipient: address(this), toInternalBalance: false
            });
            out2 = IBalancerVault(pRouterB).swap(swapB, fundsB, pMinOut2, block.timestamp);
        }
        emit Leg2(pRouterB, pTypeB, pPath2, out1, pMinOut2, out2);

        uint256 totalOwed = amount + premium;
        uint256 balNow = IERC20(asset).balanceOf(address(this));
        emit Repay(totalOwed, balNow);
        require(balNow >= totalOwed, "insufficient for repay");

        uint256 netGain = balNow - totalOwed;
        emit Profit(netGain);

        if (lenderPulls) {
            IERC20(asset).approve(repayTarget, totalOwed);
        } else {
            require(IERC20(asset).transfer(repayTarget, totalOwed), "repay failed");
        }
    }

    function _resetState() internal {
        delete pRouterA; delete pRouterB;
        delete pPath1; delete pPath2;
        pMinOut1 = 0; pMinOut2 = 0;
        pTypeA = 0; pTypeB = 0;
        pBalPoolIdA = 0x0; pBalPoolIdB = 0x0;
        pCurveI1 = 0; pCurveJ1 = 0; pCurveI2 = 0; pCurveJ2 = 0;
    }
}
`;

// ======== compiler: hardened dynamic lookup ========
function compileFlashBot() {
  const input = {
    language: "Solidity",
    sources: { "FlashBotArbMultiVenue.sol": { content: FLASHBOT_SOURCE } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true, // <--- THIS IS THE KEY FIX!
      outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } }
    }
  };

  let output;
  try {
    output = JSON.parse(solc.compile(JSON.stringify(input)));
  } catch (err) {
    console.error("❌ solc.compile() failed:", err);
    process.exit(1);
  }

  if (output.errors && output.errors.length) {
    for (const e of output.errors) console.error(e.formattedMessage || e.message || String(e));
    if (output.errors.some(e => e.severity === "error")) {
      console.error("❌ Solidity compile failed due to errors above.");
      process.exit(1);
    }
  }

  const fileNames = Object.keys(output.contracts || {});
  if (!fileNames.length) { console.error("❌ No contracts in compiler output."); process.exit(1); }
  const contracts = output.contracts[fileNames[0]];
  const names = Object.keys(contracts || {});
  if (!names.length) { console.error(`❌ No contract names in ${fileNames[0]}`); process.exit(1); }
  const name = names[0];
  const art = contracts[name];

  if (!art || !art.evm || !art.evm.bytecode || !art.evm.bytecode.object) {
    console.error("❌ Compiled contract artifact missing bytecode.");
    process.exit(1);
  }

  console.log(`✅ Compiled ${name} from ${fileNames[0]}`);
  return { abi: art.abi, bytecode: art.evm.bytecode.object };
}

// ======== ABIs ========
const V2_ROUTER_ABI = [
  "function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)"
];
const CURVE_POOL_ABI = [
  "function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256)"
];
const BALANCER_VAULT_ABI = [
  "function queryBatchSwap(uint8 kind, tuple(bytes32 poolId,uint256 assetInIndex,uint256 assetOutIndex,uint256 amount,bytes userData)[] swaps, address[] assets, tuple(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds) external view returns (int256[] memory)",
  "function getPoolTokens(bytes32 poolId) view returns (address[] memory tokens, uint256[] memory balances, uint256 lastChangeBlock)"
];
const PROVIDER_ABI = ["function getPool() view returns (address)"];
const POOL_ABI     = ["function FLASHLOAN_PREMIUM_TOTAL() view returns (uint128)"];
const ERC20_ABI    = ["function balanceOf(address) view returns (uint256)"];

// ======== deploy ========
async function deploy(force) {
  const { abi, bytecode } = compileFlashBot();
  let addr = process.env.FLASHBOT_ADDRESS;
  if (!force && !addr && fs.existsSync(ADDRESS_FILE)) {
    addr = fs.readFileSync(ADDRESS_FILE, "utf8").trim();
  }
  if (!force && addr) {
    const code = await provider.getCode(addr);
    if (code && code !== "0x") {
      console.log("📌 Using existing FlashBotArb at " + addr);
      return { address: addr, abi };
    }
  }
  console.log("🚀 Deploying FlashBotArb...");
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const balancerAddr = BALANCER_VAULT.address;
  const flashBot = await factory.deploy(process.env.AAVE_POOL_ADDRESSES_PROVIDER, balancerAddr);
  await flashBot.waitForDeployment();
  const deployedAddress = await flashBot.getAddress();
  fs.writeFileSync(ADDRESS_FILE, deployedAddress);
  console.log("✅ Deployed at: " + deployedAddress);
  return { address: deployedAddress, abi };
}

// ======== network tokens & venues (Polygon defaults; adjust as needed) ========
const EXTRA_TOKENS_FILE = "extra_tokens.json";
const YIELD_CONFIG_FILE = "yield_opportunities.json";

const WMATIC = "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270";
const WBTC   = "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6";
const CRV    = "0x172370d5cd63279efa6d502dab29171933a610af";
const GHST   = "0x385eeac5cd83818ab9e8b8e4e6cd4bbd5d0e2aa6";
const QUICK  = "0x831753dd7087cac61ab5644b308642cc1c33dc13";

const BASE_TOKENS = [
  { symbol: "USDC",   asset: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", decimals: 6  },
  { symbol: "USDT",   asset: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", decimals: 6  },
  { symbol: "DAI",    asset: "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063", decimals: 18 },
  { symbol: "WMATIC", asset: WMATIC, decimals: 18 },
  { symbol: "WETH",   asset: "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", decimals: 18 },
  { symbol: "WBTC",   asset: WBTC, decimals: 8 },
  { symbol: "AAVE",   asset: "0xd6df932a45c0f255f85145f286ea0b292b21c90b", decimals: 18 },
  { symbol: "LINK",   asset: "0x53e0bca35ec356bd5dddfebbd1fc0fd03fabad39", decimals: 18 },
  { symbol: "CRV",    asset: CRV, decimals: 18 },
  { symbol: "GHST",   asset: GHST, decimals: 18 },
  { symbol: "QUICK",  asset: QUICK, decimals: 18 }
];

function loadTokens() {
  let merged = [...BASE_TOKENS];
  if (process.env.TOKEN_JSON) {
    try {
      const custom = JSON.parse(process.env.TOKEN_JSON);
      if (Array.isArray(custom)) merged = merged.concat(custom);
    } catch (err) {
      console.warn("⚠️ TOKEN_JSON parse error:", err.message);
    }
  }
  if (fs.existsSync(EXTRA_TOKENS_FILE)) {
    try {
      const extra = JSON.parse(fs.readFileSync(EXTRA_TOKENS_FILE, "utf8"));
      if (Array.isArray(extra)) merged = merged.concat(extra);
    } catch (err) {
      console.warn("⚠️ Failed to read extra_tokens.json:", err.message);
    }
  }
  const seen = new Set();
  return merged.filter(t => {
    const key = (t.asset || "").toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return Boolean(t.symbol) && typeof t.decimals === "number";
  });
}

const TOKENS = loadTokens();

const ROUTERS = [
  { name: "QuickSwapV2", address: "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff" },
  { name: "SushiV2",     address: "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506" },
  { name: "DfynV2",      address: "0x5be02eb3c3ce3ec483d0d3ce0fc284e7370f9ea0" }
];

const CURVE_POOLS = [
  { name: "CurveAavePool", address: "0x445FE580eF8d70FF569aB36e80c647af338db351", coins: [
    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063","0x2791bca1f2de4661ed88a30c99a7a9449aa84174","0xc2132d05d31c914a87c6611c10748aeb04b58e8f"
  ]},
  { name: "CurveAtricrypto3", address: "0x8e0B8c8BB9db49a46697F3a5Bb8A308e744821D2", coins: [
    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063","0x2791bca1f2de4661ed88a30c99a7a9449aa84174","0xc2132d05d31c914a87c6611c10748aeb04b58e8f","0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6","0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"
  ]}
];

const BALANCER_VAULT = {
  name: "BalancerV2",
  address: process.env.BALANCER_VAULT_ADDRESS || "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
  type: "balancer"
};
const BALANCER_FEE_BPS = BigInt(process.env.BALANCER_FLASH_FEE_BPS || "9");
const BALANCER_POOL_REGISTRY_FILE = "balancer_pools.json";
const BALANCER_SUBGRAPH_URL = process.env.BALANCER_SUBGRAPH_URL || "https://api.thegraph.com/subgraphs/name/balancer-labs/balancer-polygon-v2";

const DEFAULT_BALANCER_POOLS = [
  {
    name: "Balancer 50 WMATIC 50 WETH",
    poolId: "0x6cfaf40300aa32fa1a3c453f1a6b3ad72037a4af000200000000000000000000",
    tokens: [toLower(WMATIC), toLower("0x7ceb23fd6bc0add59e62ac25578270cff1b9f619")],
    swapFeeBps: 30
  },
  {
    name: "Balancer 50 WETH 50 USDC",
    poolId: "0x8159462d255c1d24915cb51ec361f700174cd994000200000000000000000000",
    tokens: [toLower("0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"), toLower("0x2791bca1f2de4661ed88a30c99a7a9449aa84174")],
    swapFeeBps: 30
  }
];

const balancerRegistry = loadBalancerPoolRegistry();
const balancerPoolCache = new Map();
const balancerTokenCache = new Map();

// ======== helpers ========
function min(a, b) { return a < b ? a : b; }
function formatUnits(bi, dec) { try { return ethers.formatUnits(bi, dec); } catch (_) { return bi.toString(); } }
function toLower(addr) { return (addr || "").toLowerCase(); }
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

function pairKey(a, b) {
  return [toLower(a), toLower(b)].sort().join(":");
}

function registerBalancerPool(map, pool) {
  if (!pool || !pool.poolId) return;
  const poolId = pool.poolId.toLowerCase();
  if (poolId === "0x" || poolId.length !== 66) return;
  const tokens = Array.isArray(pool.tokens) ? pool.tokens.map(toLower) : [];
  if (tokens.length < 2) return;
  const swapFeeBps = pool.swapFeeBps !== undefined && pool.swapFeeBps !== null
    ? BigInt(Math.max(0, Math.round(Number(pool.swapFeeBps))))
    : null;

  for (let i = 0; i < tokens.length; i++) {
    for (let j = i + 1; j < tokens.length; j++) {
      const key = pairKey(tokens[i], tokens[j]);
      if (!map.has(key)) {
        map.set(key, {
          poolId,
          name: pool.name || "static",
          swapFeeBps,
          tokens
        });
      }
    }
  }
}

function loadBalancerPoolRegistry() {
  const registry = new Map();
  for (const pool of DEFAULT_BALANCER_POOLS) {
    registerBalancerPool(registry, pool);
  }
  if (fs.existsSync(BALANCER_POOL_REGISTRY_FILE)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(BALANCER_POOL_REGISTRY_FILE, "utf8"));
      if (Array.isArray(parsed)) {
        for (const pool of parsed) registerBalancerPool(registry, pool);
      }
    } catch (err) {
      console.warn("⚠️ Failed to parse balancer_pools.json:", err.message);
    }
  }
  return registry;
}

async function fetchBalancerPoolFromGraph(tokenIn, tokenOut) {
  if (typeof fetch !== "function" || !BALANCER_SUBGRAPH_URL) return null;
  const lowerIn = toLower(tokenIn);
  const lowerOut = toLower(tokenOut);
  const body = JSON.stringify({
    query: `query ($tokens: [Bytes!]) {
      pools(first: 6, orderBy: totalLiquidity, orderDirection: desc,
            where: { swapEnabled: true, tokensList_contains: $tokens }) {
        id
        name
        swapFee
        tokensList
      }
    }`,
    variables: { tokens: [lowerIn, lowerOut] }
  });

  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeout = controller ? setTimeout(() => controller.abort(), 4000) : null;

  try {
    const res = await fetch(BALANCER_SUBGRAPH_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: controller ? controller.signal : undefined
    });
    if (!res.ok) return null;
    const json = await res.json();
    const pools = json?.data?.pools;
    if (!Array.isArray(pools)) return null;
    for (const pool of pools) {
      if (!pool?.id || !Array.isArray(pool.tokensList)) continue;
      const tokens = pool.tokensList.map(toLower);
      if (!tokens.includes(lowerIn) || !tokens.includes(lowerOut)) continue;
      const swapFeeBps = pool.swapFee ? BigInt(Math.round(parseFloat(pool.swapFee) * 10000)) : null;
      return {
        poolId: pool.id.toLowerCase(),
        name: pool.name || "subgraph",
        swapFeeBps,
        tokens
      };
    }
  } catch (err) {
    if (process.env.DEBUG_BALANCER === "1") {
      console.warn("⚠️ Balancer subgraph lookup failed:", err.message || err);
    }
  } finally {
    if (timeout) clearTimeout(timeout);
  }
  return null;
}

async function resolveBalancerPool(tokenIn, tokenOut, overridePoolId) {
  const lowerIn = toLower(tokenIn);
  const lowerOut = toLower(tokenOut);
  const key = pairKey(lowerIn, lowerOut);

  if (overridePoolId) {
    const entry = {
      poolId: overridePoolId.toLowerCase(),
      name: "override",
      swapFeeBps: null
    };
    balancerPoolCache.set(key, entry);
    return entry;
  }

  if (balancerPoolCache.has(key)) {
    return balancerPoolCache.get(key);
  }

  if (balancerRegistry.has(key)) {
    const entry = balancerRegistry.get(key);
    balancerPoolCache.set(key, entry);
    return entry;
  }

  const fetched = await fetchBalancerPoolFromGraph(lowerIn, lowerOut);
  if (fetched) {
    registerBalancerPool(balancerRegistry, fetched);
    balancerPoolCache.set(key, fetched);
    return fetched;
  }

  return null;
}

async function getBalancerPoolTokens(vault, poolId) {
  const key = poolId.toLowerCase();
  if (balancerTokenCache.has(key)) {
    return balancerTokenCache.get(key);
  }
  try {
    const result = await vault.contract.getPoolTokens(poolId);
    const tokens = Array.isArray(result?.[0]) ? result[0].map(toLower) : [];
    balancerTokenCache.set(key, tokens);
    return tokens;
  } catch (err) {
    balancerTokenCache.set(key, []);
    if (process.env.DEBUG_BALANCER === "1") {
      console.warn("⚠️ Balancer getPoolTokens failed:", err.message || err);
    }
    return [];
  }
}

function getStaticBalancerPoolId(tokenIn, tokenOut) {
  const entry = balancerRegistry.get(pairKey(tokenIn, tokenOut));
  return entry ? entry.poolId : ethers.ZeroHash;
}

function buildRouters(provider) {
  return ROUTERS.map(r => ({
    name: r.name, address: r.address, type: "v2",
    contract: new ethers.Contract(r.address, V2_ROUTER_ABI, provider)
  }));
}
function buildCurvePools(provider) {
  return CURVE_POOLS.map(p => ({
    name: p.name, address: p.address, type: "curve", coins: p.coins,
    contract: new ethers.Contract(p.address, CURVE_POOL_ABI, provider)
  }));
}
function buildBalancer(provider) {
  return {
    name: BALANCER_VAULT.name,
    address: BALANCER_VAULT.address,
    type: "balancer",
    contract: new ethers.Contract(BALANCER_VAULT.address, BALANCER_VAULT_ABI, provider)
  };
}

function generatePaths(tokenIn, tokenOut) {
  const a = toLower(tokenIn), b = toLower(tokenOut);
  const paths = [];
  if (a !== b) paths.push([a, b]);
  const hubs = new Set([toLower(WMATIC), ...TOKENS.map(t => toLower(t.asset))]);
  for (const hub of hubs) {
    if (hub !== a && hub !== b) paths.push([a, hub, b]);
  }
  return paths;
}

function buildVenueLookup(venues) {
  const map = {};
  for (const venue of venues) map[venue.name] = venue;
  return map;
}

function venueTypeToCode(type) {
  if (type === "v2") return 0;
  if (type === "curve") return 1;
  return 2; // balancer
}

function slippageAdjust(value, bps) {
  const big = BigInt(bps);
  return value - (value * big) / 10000n;
}

function computeSizeSchedule(token, available, cfg) {
  if (available <= 0n) return [];
  const multiplierBps = BigInt(cfg.stepMultiplierBps || 18000);
  const maxSteps = Number(cfg.maxSteps || 5);
  const maxShareBps = BigInt(cfg.maxShareBps || 250);

  let base = 0n;
  try {
    base = ethers.parseUnits(String(cfg.base ?? "0.1"), token.decimals);
  } catch (_) {
    base = 0n;
  }

  let maxNotional = null;
  if (cfg.maxNotional !== undefined && cfg.maxNotional !== null && cfg.maxNotional !== "") {
    try {
      maxNotional = ethers.parseUnits(String(cfg.maxNotional), token.decimals);
    } catch (_) {
      maxNotional = null;
    }
  }

  let cap = maxShareBps > 0n ? (available * maxShareBps) / 10000n : available;
  if (cap <= 0n) cap = available;
  if (maxNotional && maxNotional > 0n) {
    cap = cap > 0n ? min(cap, maxNotional) : maxNotional;
  }

  if (cap <= 0n) return [];

  if (base <= 0n) base = cap;
  else base = min(base, cap);

  if (maxNotional && maxNotional > 0n) {
    base = min(base, maxNotional);
  }

  if (base <= 0n) return [];

  const schedule = [];
  let current = base;
  for (let i = 0; i < maxSteps; i++) {
    let candidate = cap > 0n ? min(current, cap) : current;
    if (maxNotional && maxNotional > 0n) {
      candidate = min(candidate, maxNotional);
    }
    if (candidate <= 0n) break;
    if (!schedule.some(v => v === candidate)) schedule.push(candidate);
    if (multiplierBps <= 10000n) break;
    const next = (candidate * multiplierBps) / 10000n;
    if (next === candidate) break;
    current = next;
  }

  schedule.sort((a, b) => (a === b ? 0 : a > b ? -1 : 1));
  return schedule;
}

function loadYieldOpportunities() {
  const defaults = [
    {
      name: "Stable carry USDC-DAI",
      asset: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
      deposit: { venue: "CurveAavePool", path: ["0x2791bca1f2de4661ed88a30c99a7a9449aa84174", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"] },
      redeem: { venue: "QuickSwapV2", path: ["0x8f3cf7ad23cd3cadbd9735aff958023239c6a063", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"] },
      bonusBps: Number(process.env.DEFAULT_YIELD_BONUS_BPS || 18)
    },
    {
      name: "WMATIC swing via Balancer",
      asset: WMATIC,
      deposit: { venue: "BalancerV2", path: [WMATIC, "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"], poolId: process.env.BALANCER_WMATIC_WETH_POOLID || getStaticBalancerPoolId(WMATIC, "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619") },
      redeem: { venue: "SushiV2", path: ["0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", WMATIC] },
      bonusBps: Number(process.env.WMATIC_YIELD_BONUS_BPS || 22)
    }
  ];

  if (fs.existsSync(YIELD_CONFIG_FILE)) {
    try {
      const file = JSON.parse(fs.readFileSync(YIELD_CONFIG_FILE, "utf8"));
      if (Array.isArray(file) && file.length) return file;
    } catch (err) {
      console.warn("⚠️ Failed to parse yield_opportunities.json:", err.message);
    }
  }
  return defaults;
}

// ======== quoting ========
async function quoteV2(router, amountIn, path) {
  try {
    const amounts = await router.contract.getAmountsOut(amountIn, path);
    return BigInt(amounts[amounts.length - 1]);
  } catch (_) { return 0n; }
}

async function quoteCurve(pool, amountIn, path) {
  if (path.length !== 2) return { out: 0n, i: -1, j: -1 };
  const coins = pool.coins.map(toLower);
  const i = coins.indexOf(toLower(path[0]));
  const j = coins.indexOf(toLower(path[1]));
  if (i === -1 || j === -1) return { out: 0n, i, j };
  try {
    const dy = await pool.contract.get_dy(i, j, amountIn);
    return { out: BigInt(dy), i, j };
  } catch (_) { return { out: 0n, i, j }; }
}

async function quoteBalancer(vault, amountIn, path, opts = {}) {
  if (path.length !== 2) return { out: 0n, poolId: ethers.ZeroHash, source: "invalid", swapFeeBps: null };
  const [tokenIn, tokenOut] = path.map(toLower);
  const inIdx = 0, outIdx = 1;

  const resolved = await resolveBalancerPool(tokenIn, tokenOut, opts.poolId);
  if (!resolved || !resolved.poolId) {
    return { out: 0n, poolId: ethers.ZeroHash, source: "missing", swapFeeBps: null };
  }

  const poolId = resolved.poolId;
  const supportedTokens = await getBalancerPoolTokens(vault, poolId);
  if (!supportedTokens.includes(tokenIn) || !supportedTokens.includes(tokenOut)) {
    return { out: 0n, poolId, source: resolved.name, swapFeeBps: resolved.swapFeeBps };
  }

  try {
    const swaps = [{ poolId, assetInIndex: inIdx, assetOutIndex: outIdx, amount: amountIn, userData: "0x" }];
    const assets = [path[0], path[1]];
    const funds = { sender: ethers.ZeroAddress, fromInternalBalance: false, recipient: ethers.ZeroAddress, toInternalBalance: false };
    const deltas = await vault.contract.queryBatchSwap(0, swaps, assets, funds);
    const outDelta = deltas[outIdx];
    const out = (typeof outDelta === "bigint") ? -outDelta : -(BigInt(outDelta));
    return { out: out > 0n ? out : 0n, poolId, source: resolved.name, swapFeeBps: resolved.swapFeeBps };
  } catch (err) {
    if (process.env.DEBUG_BALANCER === "1") {
      console.warn("⚠️ Balancer quote failed:", err.message || err);
    }
    return { out: 0n, poolId, source: resolved.name, swapFeeBps: resolved.swapFeeBps };
  }
}

async function quoteVenue(venue, amountIn, path, opts = {}) {
  if (venue.type === "v2") {
    const out = await quoteV2(venue, amountIn, path);
    return { out, meta: {} };
  }
  if (venue.type === "curve") {
    const q = await quoteCurve(venue, amountIn, path);
    return { out: q.out, meta: { curveI: q.i, curveJ: q.j } };
  }
  if (venue.type === "balancer") {
    const q = await quoteBalancer(venue, amountIn, path, opts);
    return { out: q.out, meta: { poolId: q.poolId, poolSource: q.source, swapFeeBps: q.swapFeeBps } };
  }
  return { out: 0n, meta: {} };
}

// ======== profit persistence ========
function loadProfitState() {
  try {
    if (fs.existsSync(PROFIT_JSON)) {
      const obj = JSON.parse(fs.readFileSync(PROFIT_JSON, "utf8"));
      return obj && typeof obj === "object" ? obj : {};
    }
  } catch (err) {
    console.warn("⚠️ Failed to load profit state:", err.message);
  }
  return {};
}

function saveProfitState(state) {
  try { fs.writeFileSync(PROFIT_JSON, JSON.stringify(state)); } catch (_) {}
}

function appendProfitCSV(ts, symbol, amountStr) {
  try {
    const headerNeeded = !fs.existsSync(PROFIT_CSV);
    if (headerNeeded) fs.writeFileSync(PROFIT_CSV, "timestamp,symbol,amount\n");
    fs.appendFileSync(PROFIT_CSV, `${ts},${symbol},${amountStr}\n`);
  } catch (_) {}
}

// ======== strategies ========
const YIELD_OPPORTUNITIES = loadYieldOpportunities();

const STRATEGIES = [
  {
    name: "flash-arbitrage",
    lender: "aave",
    minEdgeBps: BigInt(process.env.ARB_MIN_EDGE_BPS || "25"),
    bufferBps: BigInt(process.env.ARB_EXTRA_BUFFER_BPS || "28"),
    cooldownRounds: Number(process.env.ARB_COOLDOWN_ROUNDS || 3),
    sizeConfig: {
      base: process.env.ARB_BASE_SIZE || "0.25",
      stepMultiplierBps: Number(process.env.ARB_STEP_MULTIPLIER_BPS || 17500),
      maxSteps: Number(process.env.ARB_MAX_STEPS || 5),
      maxShareBps: Number(process.env.ARB_MAX_SHARE_BPS || 350),
      maxNotional: process.env.ARB_MAX_NOTIONAL || null
    }
  },
  {
    name: "flash-yield",
    lender: "balancer",
    minBoostBps: BigInt(process.env.YIELD_MIN_BOOST_BPS || "15"),
    bufferBps: BigInt(process.env.YIELD_EXTRA_BUFFER_BPS || "20"),
    cooldownRounds: Number(process.env.YIELD_COOLDOWN_ROUNDS || 4),
    sizeConfig: {
      base: process.env.YIELD_BASE_SIZE || "0.5",
      stepMultiplierBps: Number(process.env.YIELD_STEP_MULTIPLIER_BPS || 16000),
      maxSteps: Number(process.env.YIELD_MAX_STEPS || 4),
      maxShareBps: Number(process.env.YIELD_MAX_SHARE_BPS || 200),
      maxNotional: process.env.YIELD_MAX_NOTIONAL || null
    }
  }
];

function describePlan(strategy, token, size, owed, expectedOut, venueA, venueB, edgeBps) {
  console.log(
    `🔎 [${strategy}] ${token.symbol} size ${formatUnits(size, token.decimals)} ` +
    `via ${venueA} → ${venueB} out ${formatUnits(expectedOut, token.decimals)} owed ${formatUnits(owed, token.decimals)} edge ${edgeBps} bps`
  );
}

async function prepareArbitragePlan(ctx, token, size, premiumBps, strategy) {
  const owed = size + (size * premiumBps) / 10000n;
  const venues = ctx.venues;
  const paths1 = generatePaths(token.asset, TARGET);
  const paths2 = generatePaths(TARGET, token.asset);
  let best = null;

  for (const path1 of paths1) {
    for (const path2 of paths2) {
      for (const venueA of venues) {
        const quote1 = await quoteVenue(venueA, size, path1);
        if (quote1.out <= 0n) continue;
        for (const venueB of venues) {
          const quote2 = await quoteVenue(venueB, quote1.out, path2);
          if (quote2.out <= 0n) continue;
          if (!best || quote2.out > best.out2) {
            best = {
              venueA,
              venueB,
              path1,
              path2,
              out1: quote1.out,
              out2: quote2.out,
              metaA: quote1.meta,
              metaB: quote2.meta
            };
          }
        }
      }
    }
  }

  if (!best || best.out2 <= owed) return null;

  const delta = best.out2 - owed;
  const edgeBps = (delta * 10000n) / owed;
  if (edgeBps < strategy.minEdgeBps) return null;

  const buffer = (owed * strategy.bufferBps) / 10000n;
  if (best.out2 < owed + buffer) return null;

  describePlan(strategy.name, token, size, owed, best.out2, best.venueA.name, best.venueB.name, edgeBps.toString());

  const plan = {
    lender: "aave",
    strategy: strategy.name,
    token,
    size,
    owed,
    venueA: best.venueA,
    venueB: best.venueB,
    path1: best.path1,
    path2: best.path2,
    typeA: venueTypeToCode(best.venueA.type),
    typeB: venueTypeToCode(best.venueB.type),
    minOut1: slippageAdjust(best.out1, ctx.slippageBps),
    minOut2: slippageAdjust(best.out2, ctx.slippageBps),
    curveI1: BigInt(best.metaA.curveI ?? 0),
    curveJ1: BigInt(best.metaA.curveJ ?? 1),
    curveI2: BigInt(best.metaB.curveI ?? 0),
    curveJ2: BigInt(best.metaB.curveJ ?? 1),
    balPidA: best.metaA.poolId || ethers.ZeroHash,
    balPidB: best.metaB.poolId || ethers.ZeroHash,
    expectedOut: best.out2,
    expectedProfit: delta,
    premiumBps
  };
  return plan;
}

async function prepareYieldPlan(ctx, token, size, premiumBps, strategy) {
  const opportunities = YIELD_OPPORTUNITIES.filter(op => toLower(op.asset) === toLower(token.asset));
  if (!opportunities.length) return null;
  const owed = size + (size * premiumBps) / 10000n;
  let best = null;

  for (const op of opportunities) {
    const depositVenue = ctx.venueLookup[op.deposit.venue];
    const redeemVenue = ctx.venueLookup[op.redeem.venue];
    if (!depositVenue || !redeemVenue) continue;

    const depositQuote = await quoteVenue(depositVenue, size, op.deposit.path, op.deposit);
    if (depositQuote.out <= 0n) continue;

    let working = depositQuote.out;
    const bonusBps = BigInt(op.bonusBps || 0);
    if (bonusBps > 0n) working += (working * bonusBps) / 10000n;

    const redeemQuote = await quoteVenue(redeemVenue, working, op.redeem.path, op.redeem);
    if (redeemQuote.out <= 0n) continue;

    const boost = redeemQuote.out - owed;
    if (boost <= 0n) continue;
    const boostBps = (boost * 10000n) / owed;
    if (boostBps < strategy.minBoostBps) continue;

    if (!best || redeemQuote.out > best.out2) {
      best = {
        op,
        venueA: depositVenue,
        venueB: redeemVenue,
        path1: op.deposit.path.map(toLower),
        path2: op.redeem.path.map(toLower),
        out1: depositQuote.out,
        out2: redeemQuote.out,
        metaA: depositQuote.meta,
        metaB: redeemQuote.meta,
        boostBps
      };
    }
  }

  if (!best) return null;

  const buffer = (owed * strategy.bufferBps) / 10000n;
  if (best.out2 < owed + buffer) return null;

  describePlan(strategy.name, token, size, owed, best.out2, best.venueA.name, best.venueB.name, best.boostBps.toString());

  return {
    lender: "balancer",
    strategy: strategy.name,
    token,
    size,
    owed,
    venueA: best.venueA,
    venueB: best.venueB,
    path1: best.path1,
    path2: best.path2,
    typeA: venueTypeToCode(best.venueA.type),
    typeB: venueTypeToCode(best.venueB.type),
    minOut1: slippageAdjust(best.out1, ctx.slippageBps),
    minOut2: slippageAdjust(best.out2, ctx.slippageBps),
    curveI1: BigInt(best.metaA.curveI ?? 0),
    curveJ1: BigInt(best.metaA.curveJ ?? 1),
    curveI2: BigInt(best.metaB.curveI ?? 0),
    curveJ2: BigInt(best.metaB.curveJ ?? 1),
    balPidA: best.metaA.poolId || ethers.ZeroHash,
    balPidB: best.metaB.poolId || ethers.ZeroHash,
    expectedOut: best.out2,
    expectedProfit: best.out2 - owed,
    premiumBps
  };
}

async function executePlan(ctx, plan) {
  const contract = ctx.flashBot;
  const args = [
    plan.token.asset,
    plan.size,
    plan.typeA === 2 ? BALANCER_VAULT.address : plan.venueA.address,
    plan.typeB === 2 ? BALANCER_VAULT.address : plan.venueB.address,
    plan.path1,
    plan.path2,
    plan.minOut1,
    plan.minOut2,
    plan.typeA,
    plan.typeB,
    plan.balPidA,
    plan.balPidB,
    plan.curveI1,
    plan.curveJ1,
    plan.curveI2,
    plan.curveJ2,
    { gasLimit: 2_400_000 }
  ];

  const fn = plan.lender === "balancer"
    ? "initiateBalancerFlashLoanMulti(address,uint256,address,address,address[],address[],uint256,uint256,uint8,uint8,bytes32,bytes32,int128,int128,int128,int128)"
    : "initiateFlashLoanMulti(address,uint256,address,address,address[],address[],uint256,uint256,uint8,uint8,bytes32,bytes32,int128,int128,int128,int128)";

  console.log(`💡 Executing ${plan.strategy} with ${plan.token.symbol}`);
  const tx = await contract[fn](...args);
  console.log("🚀 TX sent:", tx.hash);
  const receipt = await tx.wait();
  console.log("✅ Included in block", receipt.blockNumber);

  const fullReceipt = await ctx.provider.getTransactionReceipt(tx.hash);
  let netGain = 0n;
  for (const log of fullReceipt.logs) {
    try {
      const parsed = ctx.iface.parseLog(log);
      if (parsed && parsed.name === "Profit") {
        netGain = BigInt(parsed.args.netGain.toString());
      }
    } catch (_) {}
  }
  return netGain;
}

// ======== main loop ========
(async () => {
  const deployed = await deploy(false);
  let flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
  let iface = new ethers.Interface(deployed.abi);

  let providerContract = new ethers.Contract(process.env.AAVE_POOL_ADDRESSES_PROVIDER, PROVIDER_ABI, provider);

  async function rebuildVenues() {
    const routers = buildRouters(provider);
    const curvePools = buildCurvePools(provider);
    const balancer = buildBalancer(provider);
    return { routers, curvePools, balancer, all: [...routers, ...curvePools, balancer] };
  }

  async function getPoolAddr() {
    try { return await providerContract.getPool(); }
    catch (_) {
      await rotateAndRebuild();
      return providerContract.getPool();
    }
  }

  async function getPremiumBps(poolAddr) {
    try {
      const pool = new ethers.Contract(poolAddr, POOL_ABI, provider);
      return BigInt(await pool.FLASHLOAN_PREMIUM_TOTAL());
    } catch (_) {
      console.warn("⚠️ Could not read FLASHLOAN_PREMIUM_TOTAL, defaulting to 9 bps");
      return 9n;
    }
  }

  async function rotateAndRebuild() {
    provider = rotateRPC();
    wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
    iface = new ethers.Interface(deployed.abi);
    providerContract = new ethers.Contract(process.env.AAVE_POOL_ADDRESSES_PROVIDER, PROVIDER_ABI, provider);
    const venues = await rebuildVenues();
    ctx.venues = venues.all;
    ctx.venueLookup = buildVenueLookup(venues.all);
    ctx.flashBot = flashBot;
    ctx.provider = provider;
  }

  const ctx = {
    provider,
    wallet,
    flashBot,
    iface,
    venues: [],
    venueLookup: {},
    slippageBps: Number(process.env.SLIPPAGE_BPS || 30)
  };

  const venueBundle = await rebuildVenues();
  ctx.venues = venueBundle.all;
  ctx.venueLookup = buildVenueLookup(venueBundle.all);

  let poolAddr = await getPoolAddr();
  let premiumBps = await getPremiumBps(poolAddr);

  const cooldown = new Map();
  const profitState = loadProfitState();
  let round = 0;

  console.log("🔄 Starting bot with", TOKENS.length, "tokens and", STRATEGIES.length, "strategies...");

  async function getAvailable(token) {
    const contract = new ethers.Contract(token.asset, ERC20_ABI, provider);
    return BigInt(await contract.balanceOf(poolAddr));
  }

  while (true) {
    round++;
    const liquidityCache = new Map();

    for (const strategy of STRATEGIES) {
      for (const token of TOKENS) {
        const tokenKey = `${strategy.name}:${toLower(token.asset)}`;
        if (toLower(token.asset) === TARGET) continue;
        const unlock = cooldown.get(tokenKey) || 0;
        if (round < unlock) continue;

        let available;
        try {
          if (liquidityCache.has(token.asset)) {
            available = liquidityCache.get(token.asset);
          } else {
            available = await getAvailable(token);
            liquidityCache.set(token.asset, available);
          }
        } catch (err) {
          console.warn(`⚠️ Failed to fetch liquidity for ${token.symbol}:`, err.message);
          await rotateAndRebuild();
          try {
            poolAddr = await getPoolAddr();
            premiumBps = await getPremiumBps(poolAddr);
          } catch (_) {}
          available = 0n;
        }

        if (!available || available <= 0n) continue;

        const schedule = computeSizeSchedule(token, available, strategy.sizeConfig);
        if (!schedule.length) continue;

        let executed = false;

        for (const size of schedule) {
          const premium = strategy.lender === "aave" ? premiumBps : BALANCER_FEE_BPS;
          let plan = null;
          if (strategy.lender === "aave") {
            plan = await prepareArbitragePlan(ctx, token, size, premium, strategy);
          } else {
            plan = await prepareYieldPlan(ctx, token, size, premium, strategy);
          }

          if (!plan) continue;

          try {
            const netGain = await executePlan(ctx, plan);
            if (netGain > 0n) {
              const ts = new Date().toISOString();
              const key = `${token.symbol}:${strategy.name}`;
              const prev = profitState[key] ? BigInt(profitState[key]) : 0n;
              const next = prev + netGain;
              profitState[key] = next.toString();
              saveProfitState(profitState);
              appendProfitCSV(ts, `${token.symbol}-${strategy.name}`, formatUnits(netGain, token.decimals));
              console.log(`💰 Profit ${token.symbol} (${strategy.name}): +${formatUnits(netGain, token.decimals)} | total ${formatUnits(next, token.decimals)}`);
            } else {
              console.log("ℹ️ Strategy executed without net profit (<= 0)");
            }
            executed = true;
            cooldown.set(tokenKey, round + strategy.cooldownRounds);
            break;
          } catch (err) {
            const msg = err && (err.reason || err.shortMessage || err.message) || String(err);
            console.warn(`❌ ${strategy.name} tx failed for ${token.symbol}:`, msg);
          }
        }

        if (!executed) {
          const wait = strategy.cooldownRounds + 1;
          console.log(`ℹ️ Cooling ${token.symbol} (${strategy.name}) for ${wait} rounds`);
          cooldown.set(tokenKey, round + wait);
        }
      }
    }

    console.warn("🔁 Cycle complete, rotating RPC for fresh data...");
    await rotateAndRebuild();
    try {
      poolAddr = await getPoolAddr();
      premiumBps = await getPremiumBps(poolAddr);
    } catch (err) {
      console.warn("⚠️ Failed to refresh pool data:", err.message);
    }
    await sleep(Number(process.env.ROUND_SLEEP_MS || 1500));
  }
})();
