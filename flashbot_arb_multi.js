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
interface IERC20 { function approve(address spender,uint256 amount) external returns (bool); function balanceOf(address account) external view returns (uint256); }
interface IUniswapV2Router02 { function swapExactTokensForTokens(uint amountIn,uint amountOutMin,address[] calldata path,address to,uint deadline) external returns (uint[] memory amounts); }
interface ICurvePool { function exchange(int128 i,int128 j,uint256 dx,uint256 min_dy) external returns (uint256); }
interface IBalancerVault {
    struct SingleSwap { bytes32 poolId; uint8 kind; address assetIn; address assetOut; uint256 amount; bytes userData; }
    struct FundManagement { address sender; bool fromInternalBalance; address recipient; bool toInternalBalance; }
    function swap(SingleSwap calldata singleSwap, FundManagement calldata funds, uint256 limit, uint256 deadline) external returns (uint256);
}

contract FlashBotArbMultiVenue is FlashLoanReceiverBase {
    address public immutable owner;
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

    constructor(address provider) FlashLoanReceiverBase(IPoolAddressesProvider(provider)) { owner = msg.sender; }

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

        POOL.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);

        delete pRouterA; delete pRouterB;
        delete pPath1; delete pPath2;
        pMinOut1 = 0; pMinOut2 = 0;
        pTypeA = 0; pTypeB = 0;
        pBalPoolIdA = 0x0; pBalPoolIdB = 0x0;
        pCurveI1 = 0; pCurveJ1 = 0; pCurveI2 = 0; pCurveJ2 = 0;
    }

    function executeOperation(address[] calldata assets,uint256[] calldata amounts,uint256[] calldata premiums,address,bytes calldata) external override returns (bool) {
        address asset = assets[0]; uint256 amount = amounts[0];
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

        uint256 totalOwed = amount + premiums[0];
        uint256 balNow = IERC20(asset).balanceOf(address(this));
        emit Repay(totalOwed, balNow);
        require(balNow >= totalOwed, "insufficient for repay");

        uint256 netGain = balNow - totalOwed;
        emit Profit(netGain);

        IERC20(asset).approve(address(POOL), totalOwed);
        return true;
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
  "function queryBatchSwap(uint8 kind, tuple(bytes32 poolId,uint256 assetInIndex,uint256 assetOutIndex,uint256 amount,bytes userData)[] swaps, address[] assets, tuple(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds) external view returns (int256[] memory)"
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
  const flashBot = await factory.deploy(process.env.AAVE_POOL_ADDRESSES_PROVIDER);
  await flashBot.waitForDeployment();
  const deployedAddress = await flashBot.getAddress();
  fs.writeFileSync(ADDRESS_FILE, deployedAddress);
  console.log("✅ Deployed at: " + deployedAddress);
  return { address: deployedAddress, abi };
}

// ======== network tokens & venues (Polygon defaults; adjust as needed) ========
const WMATIC = "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270";
const TOKENS = [
  { symbol: "USDC",  asset: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", decimals: 6  },
  { symbol: "WMATIC",asset: WMATIC, decimals: 18 },
  { symbol: "DAI",   asset: "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063", decimals: 18 },
  { symbol: "USDT",  asset: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", decimals: 6  },
  { symbol: "WETH",  asset: "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", decimals: 18 },
  { symbol: "LINK",  asset: "0x53e0bca35ec356bd5dddfebbd1fc0fd03fabad39", decimals: 18 },
  { symbol: "AAVE",  asset: "0xd6df932a45c0f255f85145f286ea0b292b21c90b", decimals: 18 }
];

const ROUTERS = [
  { name: "QuickSwapV2", address: "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff" },
  { name: "SushiV2",     address: "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506" }
];

const CURVE_POOLS = [
  { name: "CurveAavePool", address: "0x445FE580eF8d70FF569aB36e80c647af338db351", coins: [
    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063","0x2791bca1f2de4661ed88a30c99a7a9449aa84174","0xc2132d05d31c914a87c6611c10748aeb04b58e8f"
  ]},
  { name: "CurveAtricrypto3", address: "0x8e0B8c8BB9db49a46697F3a5Bb8A308e744821D2", coins: [
    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063","0x2791bca1f2de4661ed88a30c99a7a9449aa84174","0xc2132d05d31c914a87c6611c10748aeb04b58e8f","0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6","0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"
  ]}
];

const BALANCER_VAULT = { name: "BalancerV2", address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8", type: "balancer" };

// ======== helpers ========
function min(a, b) { return a < b ? a : b; }
function formatUnits(bi, dec) { try { return ethers.formatUnits(bi, dec); } catch (_) { return bi.toString(); } }
function toLower(addr) { return addr.toLowerCase(); }
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

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
    name: "BalancerV2", address: BALANCER_VAULT.address, type: "balancer",
    contract: new ethers.Contract(BALANCER_VAULT.address, BALANCER_VAULT_ABI, provider)
  };
}
function generatePaths(tokenIn, tokenOut) {
  const a = toLower(tokenIn), b = toLower(tokenOut);
  const paths = [];
  if (a !== b) paths.push([a, b]);
  for (const h of [WMATIC, ...TOKENS.map(t => t.asset)]) {
    const hub = toLower(h);
    if (hub !== a && hub !== b) paths.push([a, hub, b]);
  }
  return paths;
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
  const i = coins.indexOf(path[0]);
  const j = coins.indexOf(path[1]);
  if (i === -1 || j === -1) return { out: 0n, i, j };
  try {
    const dy = await pool.contract.get_dy(i, j, amountIn);
    return { out: BigInt(dy), i, j };
  } catch (_) { return { out: 0n, i, j }; }
}
async function quoteBalancer(vault, amountIn, path) {
  if (path.length !== 2) return { out: 0n, poolId: "0x00" };
  // Note: In production, map actual poolIds per pair. Here we assume a known pool per pair via metadata if provided.
  const inIdx = 0, outIdx = 1;
  try {
    const poolId = "0x0000000000000000000000000000000000000000000000000000000000000000"; // placeholder unless mapped
    const swaps = [{ poolId, assetInIndex: inIdx, assetOutIndex: outIdx, amount: amountIn, userData: "0x" }];
    const assets = [path[0], path[1]];
    const funds = { sender: ethers.ZeroAddress, fromInternalBalance: false, recipient: ethers.ZeroAddress, toInternalBalance: false };
    const deltas = await vault.contract.queryBatchSwap(0, swaps, assets, funds);
    const outDelta = deltas[outIdx];
    const out = (typeof outDelta === "bigint") ? -outDelta : -(BigInt(outDelta));
    return { out: out > 0n ? out : 0n, poolId };
  } catch (_) { return { out: 0n, poolId: "0x00" }; }
}
async function quoteVenue(venue, amountIn, path) {
  if (venue.type === "v2") {
    const out = await quoteV2(venue, amountIn, path);
    return { out, meta: {} };
  }
  if (venue.type === "curve") {
    const q = await quoteCurve(venue, amountIn, path);
    return { out: q.out, meta: { curveI: q.i, curveJ: q.j } };
  }
  if (venue.type === "balancer") {
    const q = await quoteBalancer(venue, amountIn, path);
    return { out: q.out, meta: { poolId: q.poolId } };
  }
  return { out: 0n, meta: {} };
}

function applySlippage(x) {
  const SLIPPAGE_BPS = 30n;
  return x - (x * SLIPPAGE_BPS) / 10000n;
}

// ======== profit persistence ========
function loadProfitState() {
  try {
    if (fs.existsSync(PROFIT_JSON)) {
      const obj = JSON.parse(fs.readFileSync(PROFIT_JSON, "utf8"));
      return obj && typeof obj === "object" ? obj : {};
    }
  } catch (_) {}
  return {};
}
function saveProfitState(state) {
  try { fs.writeFileSync(PROFIT_JSON, JSON.stringify(state)); } catch (_) {}
}
function appendProfitCSV(ts, symbol, amountStr) {
  try {
    const headerNeeded = !fs.existsSync(PROFIT_CSV);
    if (headerNeeded) fs.writeFileSync(PROFIT_CSV, "timestamp,symbol,amount\n");
    fs.appendFileSync(PROFIT_CSV, ts + "," + symbol + "," + amountStr + "\n");
  } catch (_) {}
}

// ======== main loop ========
(async () => {
  const deployed = await deploy(false);
  const flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
  const iface = new ethers.Interface(deployed.abi);

  const providerContract = new ethers.Contract(process.env.AAVE_POOL_ADDRESSES_PROVIDER, PROVIDER_ABI, provider);
  async function getPoolAddr() {
    try { return await providerContract.getPool(); }
    catch (_) {
      provider = rotateRPC();
      wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
      return getPoolAddr();
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

  let poolAddr = await getPoolAddr();
  let premiumBps = await getPremiumBps(poolAddr);
  let routers = buildRouters(provider);
  let curvePools = buildCurvePools(provider);
  let balancer = buildBalancer(provider);

  const cooldown = new Map();
  let round = 0;
  const profitState = loadProfitState();

  console.log("🔄 Starting bot...");

  while (true) {
    round++;

    for (const token of TOKENS) {
      const assetL = token.asset.toLowerCase();
      if (assetL === TARGET) continue;
      const unlock = cooldown.get(assetL) || 0;
      if (round < unlock) continue;

      const underlying = new ethers.Contract(token.asset, ERC20_ABI, provider);
      let available = 0n;
      try { available = await underlying.balanceOf(poolAddr); }
      catch (_) {
        provider = rotateRPC();
        wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
        routers = buildRouters(provider);
        curvePools = buildCurvePools(provider);
        balancer = buildBalancer(provider);
        try { poolAddr = await getPoolAddr(); } catch (_){ }
        try { premiumBps = await getPremiumBps(poolAddr); } catch (_){ }
        continue;
      }
      if (available <= 0n) continue;

      const ramp = (token.symbol === "USDC" || token.symbol === "USDT" || token.symbol === "DAI")
        ? ["0.1", "0.2", "0.5", "1.0"]
        : ["0.01", "0.05", "0.1"];
      const maxCap = available / 10000n;

      let executed = false;
      let foundProfitable = false;

      for (const step of ramp) {
        let size = ethers.parseUnits(step, token.decimals);
        size = min(size, maxCap);
        if (size <= 0n) continue;

        const premium = (size * premiumBps) / 10000n;
        const owed = size + premium;

        const best = await (async () => {
          let best = { out2: 0n };
          const paths1 = generatePaths(token.asset, TARGET);
          const paths2 = generatePaths(TARGET, token.asset);
          const venues = routers.concat(curvePools).concat([balancer]);

          for (const path1 of paths1) {
            for (const path2 of paths2) {
              for (const rA of venues) {
                const q1 = await quoteVenue(rA, size, path1);
                if (q1.out <= 0n) continue;
                for (const rB of venues) {
                  const q2 = await quoteVenue(rB, q1.out, path2);
                  if (q2.out <= 0n) continue;
                  if (q2.out > best.out2) {
                    best = {
                      aName: rA.name, bName: rB.name,
                      aAddr: rA.address, bAddr: rB.address,
                      aType: rA.type, bType: rB.type,
                      path1, path2, out1: q1.out, out2: q2.out,
                      aMeta: q1.meta || {}, bMeta: q2.meta || {}
                    };
                  }
                }
              }
            }
          }
          return best;
        })();

        if (best.out2 <= 0n) continue;

        const extra = (owed * 30n) / 10000n;
        const delta = best.out2 - owed;
        const edgeBps = delta > 0n ? (delta * 10000n) / owed : -((owed - best.out2) * 10000n) / owed;

        console.log(
          "🔎 " + token.symbol +
          " size " + formatUnits(size, token.decimals) +
          " via " + best.aName + " → " + best.bName +
          " out " + formatUnits(best.out2, token.decimals) +
          " owed " + formatUnits(owed, token.decimals) +
          " edge " + edgeBps.toString() + " bps"
        );

        if (best.out2 < (owed + extra)) continue;
        foundProfitable = true;

        const minOut1 = applySlippage(best.out1);
        const minOut2 = applySlippage(best.out2);
        const typeA = best.aType === "v2" ? 0 : best.aType === "curve" ? 1 : 2;
        const typeB = best.bType === "v2" ? 0 : best.bType === "curve" ? 1 : 2;
        const routerA = typeA === 2 ? BALANCER_VAULT.address : best.aAddr;
        const routerB = typeB === 2 ? BALANCER_VAULT.address : best.bAddr;
        const curveI1 = BigInt(best.aMeta.curveI ?? 0);
        const curveJ1 = BigInt(best.aMeta.curveJ ?? 1);
        const curveI2 = BigInt(best.bMeta.curveI ?? 0);
        const curveJ2 = BigInt(best.bMeta.curveJ ?? 1);
        const balPidA = best.aMeta.poolId ?? "0x0000000000000000000000000000000000000000000000000000000000000000";
        const balPidB = best.bMeta.poolId ?? "0x0000000000000000000000000000000000000000000000000000000000000000";

        try {
          console.log("💡 Attempting flash loan for " + token.symbol);
          const tx = await flashBot["initiateFlashLoanMulti(address,uint256,address,address,address[],address[],uint256,uint256,uint8,uint8,bytes32,bytes32,int128,int128,int128,int128)"](
            token.asset, size,
            routerA, routerB,
            best.path1, best.path2,
            minOut1, minOut2,
            typeA, typeB,
            balPidA, balPidB,
            curveI1, curveJ1, curveI2, curveJ2,
            { gasLimit: 2200000 }
          );
          console.log("🚀 TX sent: " + tx.hash);
          const rec = await tx.wait();
          console.log("✅ Executed in block " + rec.blockNumber);

          let netGain = 0n;
          const receipt = await provider.getTransactionReceipt(tx.hash);
          for (const log of receipt.logs) {
            try {
              const parsed = iface.parseLog(log);
              if (parsed && parsed.name === "Profit") {
                netGain = BigInt(parsed.args.netGain.toString());
              }
            } catch (_) {}
          }

          if (netGain > 0n) {
            const ts = new Date().toISOString();
            const key = token.symbol;
            const prev = profitState[key] ? BigInt(profitState[key]) : 0n;
            const next = prev + netGain;
            profitState[key] = next.toString();
            saveProfitState(profitState);
            appendProfitCSV(ts, key, formatUnits(netGain, token.decimals));
            console.log("💰 Profit " + key + ": +" + formatUnits(netGain, token.decimals) + " | total " + formatUnits(next, token.decimals));
          } else {
            console.log("ℹ️ No profit recorded (<= 0)");
          }

          executed = true;
          break;
        } catch (e) {
          const msg = (e && (e.reason || e.shortMessage || e.message)) || String(e);
          console.warn("❌ TX failed for " + token.symbol + ": " + msg);
        }
      }

      if (executed) { await sleep(1200); continue; }
      if (!foundProfitable) {
        console.log("ℹ️ Cooling down " + token.symbol + " for 3 rounds");
        cooldown.set(assetL, round + 3);
      }
    }

    console.warn("🔁 No success this round, rotating RPC and retrying...");
    provider = rotateRPC();
    wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    routers = buildRouters(provider);
    curvePools = buildCurvePools(provider);
    balancer = buildBalancer(provider);
    try { poolAddr = await getPoolAddr(); } catch (_){ }
    try { premiumBps = await getPremiumBps(poolAddr); } catch (_){ }
    await sleep(1500);
  }
})();
