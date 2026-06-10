// ======== requires & config ========
const fs = require("fs");
const solc = require("solc");
const { ethers } = require("ethers");
const dotenv = require("dotenv");
dotenv.config();

// ======== constants & RPC setup ========
const RPC_LIST = (
  process.env.RPC_LIST ||
  process.env.WRITE_RPC ||
  "https://polygon-rpc.com,https://rpc.ankr.com/polygon,https://1rpc.io/matic"
)
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

if (RPC_LIST.length === 0) {
  console.error("Missing WRITE_RPC or RPC_LIST in .env");
  process.exit(1);
}
if (!process.env.PRIVATE_KEY) {
  console.error("Missing PRIVATE_KEY in .env");
  process.exit(1);
}
if (!process.env.AAVE_POOL_ADDRESSES_PROVIDER) {
  console.error("Missing AAVE_POOL_ADDRESSES_PROVIDER in .env");
  process.exit(1);
}
if (!process.env.TARGET_TOKEN) {
  console.error("Missing TARGET_TOKEN in .env");
  process.exit(1);
}

const TARGET = process.env.TARGET_TOKEN.toLowerCase();
const ADDRESS_FILE = "FlashBotArb.address.txt";
const PROFIT_JSON = "profit_per_token.json";
const PROFIT_CSV = "profit_per_token.csv";
const MIN_EDGE_BPS = BigInt(process.env.MIN_EDGE_BPS || "50");
const MAX_SLIPPAGE_BPS = 30n;

let rpcIndex = 0;

async function getProvider(maxRetries = 3, retryDelay = 1000) {
  const provider = new ethers.JsonRpcProvider(RPC_LIST[rpcIndex], undefined, {
    staticNetwork: true
  });
  for (let i = 0; i < maxRetries; i++) {
    try {
      await provider.getBlockNumber();
      return provider;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      console.warn(`⚠️ RPC connection attempt ${i + 1} failed, retrying...`);
      await new Promise(r => setTimeout(r, retryDelay));
    }
  }
  throw new Error(`Failed to connect to RPC after ${maxRetries} attempts`);
}

async function rotateRPC() {
  const initialIndex = rpcIndex;
  let attempts = 0;
  do {
    rpcIndex = (rpcIndex + 1) % RPC_LIST.length;
    attempts++;
    try {
      console.warn(
        `🔄 Switching to RPC ${rpcIndex + 1}/${RPC_LIST.length}: ${RPC_LIST[rpcIndex].substring(0, 40)}...`
      );
      const p = await getProvider(1);
      return p;
    } catch (error) {
      console.warn(`❌ RPC ${rpcIndex + 1} failed: ${error.message}`);
      if (attempts >= RPC_LIST.length) {
        throw new Error("All RPC endpoints failed");
      }
    }
  } while (rpcIndex !== initialIndex);
  throw new Error("RPC rotation exhausted");
}

// ======== Solidity contract source ========
const FLASHBOT_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface IPoolAddressesProvider {
    function getPool() external view returns (address);
}

interface IPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
    function FLASHLOAN_PREMIUM_TOTAL() external view returns (uint128);
}

abstract contract FlashLoanReceiverBase {
    IPoolAddressesProvider public immutable ADDRESSES_PROVIDER;
    IPool public immutable POOL;
    constructor(IPoolAddressesProvider provider) {
        ADDRESSES_PROVIDER = provider;
        POOL = IPool(provider.getPool());
    }
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external virtual returns (bool);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Router02 {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
}

interface IBalancerVault {
    struct SingleSwap {
        bytes32 poolId;
        uint8 kind;
        address assetIn;
        address assetOut;
        uint256 amount;
        bytes userData;
    }
    struct FundManagement {
        address sender;
        bool fromInternalBalance;
        address recipient;
        bool toInternalBalance;
    }
    function swap(
        SingleSwap calldata singleSwap,
        FundManagement calldata funds,
        uint256 limit,
        uint256 deadline
    ) external returns (uint256);
}

contract FlashBotArbMultiVenue is FlashLoanReceiverBase {
    address public immutable owner;
    bool private locked;

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

    event Leg1(address router, uint8 legType, address[] path, uint256 amountIn, uint256 minOut, uint256 amountOut);
    event Leg2(address router, uint8 legType, address[] path, uint256 amountIn, uint256 minOut, uint256 amountOut);
    event Repay(uint256 owed, uint256 balance);
    event Profit(uint256 netGain);
    event SwapFailed(address indexed router, string reason);
    event EmergencyWithdraw(address indexed token, uint256 amount);

    modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

    constructor(address provider) FlashLoanReceiverBase(IPoolAddressesProvider(provider)) {
        owner = msg.sender;
    }

    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        token.approve(spender, 0);
        token.approve(spender, amount);
    }

    function emergencyWithdraw(address token) external {
        require(msg.sender == owner, "Only owner");
        if (token == address(0)) {
            (bool success, ) = payable(owner).call{value: address(this).balance}("");
            require(success, "ETH transfer failed");
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            IERC20(token).transfer(owner, balance);
            emit EmergencyWithdraw(token, balance);
        }
    }

    receive() external payable {}
    fallback() external payable {}

    function initiateFlashLoanMulti(
        address asset, uint256 amount,
        address routerA, address routerB,
        address[] calldata path1, address[] calldata path2,
        uint256 minOut1, uint256 minOut2,
        uint8 typeA, uint8 typeB,
        bytes32 balPoolIdA, bytes32 balPoolIdB,
        int128 curveI1, int128 curveJ1, int128 curveI2, int128 curveJ2
    ) external {
        require(msg.sender == owner, "only owner");
        require(routerA != address(0) && routerB != address(0), "invalid routers");
        require(path1.length >= 2 && path2.length >= 2, "invalid paths");
        require(typeA <= 2 && typeB <= 2, "invalid types");

        pRouterA = routerA; pRouterB = routerB;
        pPath1 = path1; pPath2 = path2;
        pMinOut1 = minOut1; pMinOut2 = minOut2;
        pTypeA = typeA; pTypeB = typeB;
        pBalPoolIdA = balPoolIdA; pBalPoolIdB = balPoolIdB;
        pCurveI1 = curveI1; pCurveJ1 = curveJ1;
        pCurveI2 = curveI2; pCurveJ2 = curveJ2;

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

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external override noReentrant returns (bool) {
        address asset = assets[0];
        uint256 amount = amounts[0];
        uint256 out1 = 0;

        // ---- Leg 1 ----
        if (pTypeA == 0) {
            safeApprove(IERC20(asset), pRouterA, amount);
            uint256 before1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this));
            try IUniswapV2Router02(pRouterA).swapExactTokensForTokens(
                amount, pMinOut1, pPath1, address(this), block.timestamp
            ) {
                out1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this)) - before1;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("V2 swap A failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("V2 swap A failed");
            }
        } else if (pTypeA == 1) {
            safeApprove(IERC20(asset), pRouterA, amount);
            try ICurvePool(pRouterA).exchange(pCurveI1, pCurveJ1, amount, pMinOut1) returns (uint256 result) {
                out1 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("Curve swap A failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("Curve swap A failed");
            }
        } else {
            safeApprove(IERC20(asset), pRouterA, amount);
            IBalancerVault.SingleSwap memory swapA = IBalancerVault.SingleSwap({
                poolId: pBalPoolIdA, kind: 0, assetIn: pPath1[0], assetOut: pPath1[1],
                amount: amount, userData: ""
            });
            IBalancerVault.FundManagement memory fundsA = IBalancerVault.FundManagement({
                sender: address(this), fromInternalBalance: false,
                recipient: address(this), toInternalBalance: false
            });
            try IBalancerVault(pRouterA).swap(swapA, fundsA, pMinOut1, block.timestamp) returns (uint256 result) {
                out1 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("Balancer swap A failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("Balancer swap A failed");
            }
        }
        emit Leg1(pRouterA, pTypeA, pPath1, amount, pMinOut1, out1);

        // ---- Leg 2 ----
        uint256 out2 = 0;
        if (pTypeB == 0) {
            safeApprove(IERC20(pPath2[0]), pRouterB, out1);
            uint256 before2 = IERC20(asset).balanceOf(address(this));
            try IUniswapV2Router02(pRouterB).swapExactTokensForTokens(
                out1, pMinOut2, pPath2, address(this), block.timestamp
            ) {
                out2 = IERC20(asset).balanceOf(address(this)) - before2;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterB, reason);
                revert(string(abi.encodePacked("V2 swap B failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("V2 swap B failed");
            }
        } else if (pTypeB == 1) {
            safeApprove(IERC20(pPath2[0]), pRouterB, out1);
            try ICurvePool(pRouterB).exchange(pCurveI2, pCurveJ2, out1, pMinOut2) returns (uint256 result) {
                out2 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterB, reason);
                revert(string(abi.encodePacked("Curve swap B failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("Curve swap B failed");
            }
        } else {
            safeApprove(IERC20(pPath2[0]), pRouterB, out1);
            IBalancerVault.SingleSwap memory swapB = IBalancerVault.SingleSwap({
                poolId: pBalPoolIdB, kind: 0, assetIn: pPath2[0], assetOut: pPath2[1],
                amount: out1, userData: ""
            });
            IBalancerVault.FundManagement memory fundsB = IBalancerVault.FundManagement({
                sender: address(this), fromInternalBalance: false,
                recipient: address(this), toInternalBalance: false
            });
            try IBalancerVault(pRouterB).swap(swapB, fundsB, pMinOut2, block.timestamp) returns (uint256 result) {
                out2 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterB, reason);
                revert(string(abi.encodePacked("Balancer swap B failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("Balancer swap B failed");
            }
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
      viaIR: true,
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
    for (const e of output.errors)
      console.error(e.formattedMessage || e.message || String(e));
    if (output.errors.some(e => e.severity === "error")) {
      console.error("❌ Solidity compile failed.");
      process.exit(1);
    }
  }
  const fileNames = Object.keys(output.contracts || {});
  if (!fileNames.length) {
    console.error("❌ No contracts in compiler output.");
    process.exit(1);
  }
  const contracts = output.contracts[fileNames[0]];
  const names = Object.keys(contracts || {});
  if (!names.length) {
    console.error("❌ No contract names found.");
    process.exit(1);
  }
  const name = names[0];
  const art = contracts[name];
  if (!art || !art.evm || !art.evm.bytecode || !art.evm.bytecode.object) {
    console.error("❌ Compiled artifact missing bytecode.");
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
const POOL_ABI = ["function FLASHLOAN_PREMIUM_TOTAL() view returns (uint128)"];
const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

// ======== deploy (with retry & gas ramp) ========
async function deploy(provider, wallet, force) {
  const { abi, bytecode } = compileFlashBot();
  let addr = process.env.FLASHBOT_ADDRESS;

  if (!force && !addr && fs.existsSync(ADDRESS_FILE)) {
    addr = fs.readFileSync(ADDRESS_FILE, "utf8").trim();
  }
  if (!force && addr) {
    try {
      const code = await provider.getCode(addr);
      if (code && code !== "0x") {
        console.log("📌 Using existing FlashBotArb at " + addr);
        return { address: addr, abi };
      }
    } catch (_) {
      console.warn("⚠️ Could not verify existing contract, redeploying...");
    }
  }

  console.log("🚀 Deploying FlashBotArb...");
  const gasSettings = [
    { gasLimit: 5_000_000, gasPrice: ethers.parseUnits("50", "gwei") },
    { gasLimit: 6_000_000, gasPrice: ethers.parseUnits("40", "gwei") },
    { gasLimit: 7_000_000, gasPrice: ethers.parseUnits("30", "gwei") },
    { gasLimit: 8_000_000, gasPrice: ethers.parseUnits("25", "gwei") },
    { gasLimit: 10_000_000, gasPrice: ethers.parseUnits("20", "gwei") }
  ];

  for (let attempt = 0; attempt < gasSettings.length; attempt++) {
    try {
      const gc = gasSettings[attempt];
      console.log(
        `🔄 Attempt ${attempt + 1}/${gasSettings.length} — gas ${ethers.formatUnits(gc.gasPrice, "gwei")} gwei, limit ${gc.gasLimit}`
      );
      const factory = new ethers.ContractFactory(abi, bytecode, wallet);
      const flashBot = await factory.deploy(
        process.env.AAVE_POOL_ADDRESSES_PROVIDER,
        gc
      );
      console.log("📝 Tx sent:", flashBot.deploymentTransaction().hash);
      const timeout = new Promise((_, rej) =>
        setTimeout(() => rej(new Error("Deploy timeout 180s")), 180_000)
      );
      const deployed = await Promise.race([
        flashBot.waitForDeployment(),
        timeout
      ]);
      const deployedAddr = await deployed.getAddress();
      fs.writeFileSync(ADDRESS_FILE, deployedAddr);
      console.log("✅ Deployed at: " + deployedAddr);
      return { address: deployedAddr, abi };
    } catch (error) {
      console.error(`❌ Attempt ${attempt + 1} failed: ${error.message}`);
      if (attempt < gasSettings.length - 1) {
        provider = await rotateRPC();
        wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
        await sleep(10_000);
      }
    }
  }
  console.error("💥 All deployment attempts failed");
  process.exit(1);
}

// ======== network tokens & venues (Polygon) ========
const WMATIC = "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270";

const TOKENS = [
  { symbol: "USDC", asset: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", decimals: 6 },
  { symbol: "WMATIC", asset: WMATIC, decimals: 18 },
  { symbol: "DAI", asset: "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063", decimals: 18 },
  { symbol: "USDT", asset: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", decimals: 6 },
  { symbol: "WETH", asset: "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", decimals: 18 },
  { symbol: "WBTC", asset: "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6", decimals: 8 },
  { symbol: "LINK", asset: "0x53e0bca35ec356bd5dddfebbd1fc0fd03fabad39", decimals: 18 },
  { symbol: "AAVE", asset: "0xd6df932a45c0f255f85145f286ea0b292b21c90b", decimals: 18 },
  { symbol: "CRV", asset: "0x172370d5cd63279efa6d502dab29171933a610af", decimals: 18 },
  { symbol: "SUSHI", asset: "0x0b3f868e0be5597d5db7feb59e1cadbb0fdda50a", decimals: 18 },
  { symbol: "GHST", asset: "0x385eeac5cb85a38a9a07a70c73e0a3271cfb54a7", decimals: 18 },
  { symbol: "QUICK", asset: "0x831753dd7087cac61ab5644b308642cc1c33dc13", decimals: 18 },
  { symbol: "BAL", asset: "0x9a71012b13ca4d3d0cdc72a177df3ef03b0e76a3", decimals: 18 },
  { symbol: "MAI", asset: "0xa3fa99a148fa48d14ed51d610c367c61876997f1", decimals: 18 }
];

const STABLECOINS = new Set(["USDC", "USDT", "DAI", "MAI"]);

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
  },
  {
    name: "CurveAtricrypto3",
    address: "0x8e0B8c8BB9db49a46697F3a5Bb8A308e744821D2",
    coins: [
      "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
      "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
      "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
      "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6",
      "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"
    ]
  }
];

const BALANCER_VAULT = {
  name: "BalancerV2",
  address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
  type: "balancer"
};

// Load real Balancer pool IDs from config
let BALANCER_POOLS = [];
try {
  if (fs.existsSync("balancer_pools.json")) {
    BALANCER_POOLS = JSON.parse(fs.readFileSync("balancer_pools.json", "utf8"));
    console.log(`📋 Loaded ${BALANCER_POOLS.length} Balancer pool(s)`);
  }
} catch (_) {
  console.warn("⚠️ Could not load balancer_pools.json, Balancer quoting disabled");
}

function findBalancerPoolId(tokenA, tokenB) {
  const a = tokenA.toLowerCase();
  const b = tokenB.toLowerCase();
  for (const pool of BALANCER_POOLS) {
    const t = pool.tokens.map(x => x.toLowerCase());
    if (t.includes(a) && t.includes(b)) return pool.poolId;
  }
  return null;
}

// ======== helpers ========
function min(a, b) {
  return a < b ? a : b;
}
function formatUnits(bi, dec) {
  try {
    return ethers.formatUnits(bi, dec);
  } catch (_) {
    return bi.toString();
  }
}
function toLower(addr) {
  return addr.toLowerCase();
}
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function buildRouters(currentProvider) {
  return ROUTERS.map(r => ({
    name: r.name,
    address: r.address,
    type: "v2",
    contract: new ethers.Contract(r.address, V2_ROUTER_ABI, currentProvider)
  }));
}

function buildCurvePools(currentProvider) {
  return CURVE_POOLS.map(p => ({
    name: p.name,
    address: p.address,
    type: "curve",
    coins: p.coins,
    contract: new ethers.Contract(p.address, CURVE_POOL_ABI, currentProvider)
  }));
}

function buildBalancer(currentProvider) {
  return {
    name: "BalancerV2",
    address: BALANCER_VAULT.address,
    type: "balancer",
    contract: new ethers.Contract(
      BALANCER_VAULT.address,
      BALANCER_VAULT_ABI,
      currentProvider
    )
  };
}

function generatePaths(tokenIn, tokenOut) {
  const a = toLower(tokenIn);
  const b = toLower(tokenOut);
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
  } catch (_) {
    return 0n;
  }
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
  } catch (_) {
    return { out: 0n, i, j };
  }
}

async function quoteBalancer(vault, amountIn, path) {
  if (path.length !== 2) return { out: 0n, poolId: null };
  const poolId = findBalancerPoolId(path[0], path[1]);
  if (!poolId) return { out: 0n, poolId: null };
  try {
    const swaps = [
      {
        poolId,
        assetInIndex: 0,
        assetOutIndex: 1,
        amount: amountIn,
        userData: "0x"
      }
    ];
    const assets = [path[0], path[1]];
    const funds = {
      sender: ethers.ZeroAddress,
      fromInternalBalance: false,
      recipient: ethers.ZeroAddress,
      toInternalBalance: false
    };
    const deltas = await vault.contract.queryBatchSwap(0, swaps, assets, funds);
    const outDelta = deltas[1];
    const out =
      typeof outDelta === "bigint" ? -outDelta : -BigInt(outDelta);
    return { out: out > 0n ? out : 0n, poolId };
  } catch (_) {
    return { out: 0n, poolId };
  }
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
  return x - (x * MAX_SLIPPAGE_BPS) / 10000n;
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
  try {
    fs.writeFileSync(PROFIT_JSON, JSON.stringify(state));
  } catch (_) {}
}

function appendProfitCSV(ts, symbol, amountStr) {
  try {
    const headerNeeded = !fs.existsSync(PROFIT_CSV);
    if (headerNeeded)
      fs.writeFileSync(PROFIT_CSV, "timestamp,symbol,amount\n");
    fs.appendFileSync(PROFIT_CSV, `${ts},${symbol},${amountStr}\n`);
  } catch (_) {}
}

// ======== progressive ramp amounts ========
function getRamp(symbol, successCount) {
  if (STABLECOINS.has(symbol)) {
    if (successCount >= 5)
      return ["50000.0", "100000.0", "250000.0", "500000.0"];
    if (successCount >= 3)
      return ["10000.0", "25000.0", "50000.0", "100000.0"];
    if (successCount >= 1) return ["1000.0", "5000.0", "10000.0", "25000.0"];
    return ["500.0", "1000.0", "5000.0"];
  }
  if (successCount >= 5) return ["100.0", "250.0", "500.0", "1000.0"];
  if (successCount >= 3) return ["50.0", "100.0", "250.0", "500.0"];
  if (successCount >= 1) return ["10.0", "25.0", "50.0", "100.0"];
  return ["1.0", "5.0", "10.0", "25.0"];
}

// ======== main ========
async function main() {
  let provider = await getProvider();
  let wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

  console.log("🔍 RPC connected. Block:", await provider.getBlockNumber());

  const deployed = await deploy(provider, wallet, false);
  let flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
  const iface = new ethers.Interface(deployed.abi);

  let providerContract = new ethers.Contract(
    process.env.AAVE_POOL_ADDRESSES_PROVIDER,
    PROVIDER_ABI,
    provider
  );

  async function reconnectAll() {
    provider = await rotateRPC();
    wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    flashBot = flashBot.connect(wallet);
    providerContract = new ethers.Contract(
      process.env.AAVE_POOL_ADDRESSES_PROVIDER,
      PROVIDER_ABI,
      provider
    );
    routers = buildRouters(provider);
    curvePools = buildCurvePools(provider);
    balancer = buildBalancer(provider);
  }

  async function getPoolAddr() {
    try {
      return await providerContract.getPool();
    } catch (_) {
      console.warn("⚠️ Failed to get pool address, rotating RPC...");
      await reconnectAll();
      return providerContract.getPool();
    }
  }

  async function getPremiumBps(poolAddr) {
    try {
      const pool = new ethers.Contract(poolAddr, POOL_ABI, provider);
      return BigInt(await pool.FLASHLOAN_PREMIUM_TOTAL());
    } catch (_) {
      console.warn(
        "⚠️ Could not read FLASHLOAN_PREMIUM_TOTAL, defaulting to 9 bps"
      );
      return 9n;
    }
  }

  let poolAddr = await getPoolAddr();
  let premiumBps = await getPremiumBps(poolAddr);
  console.log("🏦 Aave pool:", poolAddr, "| premium:", premiumBps.toString(), "bps");

  let routers = buildRouters(provider);
  let curvePools = buildCurvePools(provider);
  let balancer = buildBalancer(provider);
  console.log(
    "📡 Venues: " +
      routers.map(r => r.name).join(", ") +
      " | " +
      curvePools.map(p => p.name).join(", ") +
      " | BalancerV2"
  );

  const cooldown = new Map();
  const successHistory = new Map();
  let round = 0;
  const profitState = loadProfitState();

  console.log("🔄 Starting bot loop...\n");

  while (true) {
    round++;
    if (round % 10 === 0) console.log(`── round ${round} ──`);

    for (const token of TOKENS) {
      const assetL = token.asset.toLowerCase();
      if (assetL === TARGET) continue;
      const unlock = cooldown.get(assetL) || 0;
      if (round < unlock) continue;

      const underlying = new ethers.Contract(token.asset, ERC20_ABI, provider);
      let available = 0n;
      try {
        available = await underlying.balanceOf(poolAddr);
      } catch (_) {
        console.warn(`⚠️ balanceOf failed for ${token.symbol}, rotating RPC...`);
        try {
          await reconnectAll();
          poolAddr = await getPoolAddr();
          premiumBps = await getPremiumBps(poolAddr);
        } catch (e) {
          console.error("❌ RPC rotation failed:", e.message);
          await sleep(5000);
        }
        continue;
      }
      if (available <= 0n) continue;

      const successCount = successHistory.get(assetL) || 0;
      const ramp = getRamp(token.symbol, successCount);
      const maxCap = available / 100n;

      let executed = false;
      let foundProfitable = false;

      for (const step of ramp) {
        let size = ethers.parseUnits(step, token.decimals);
        size = min(size, maxCap);
        if (size <= 0n) continue;

        const premium = (size * premiumBps) / 10000n;
        const owed = size + premium;

        const venues = [...routers, ...curvePools, balancer];
        let best = { out2: 0n };
        const paths1 = generatePaths(token.asset, TARGET);
        const paths2 = generatePaths(TARGET, token.asset);

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
                    aName: rA.name,
                    bName: rB.name,
                    aAddr: rA.address,
                    bAddr: rB.address,
                    aType: rA.type,
                    bType: rB.type,
                    path1,
                    path2,
                    out1: q1.out,
                    out2: q2.out,
                    aMeta: q1.meta || {},
                    bMeta: q2.meta || {}
                  };
                }
              }
            }
          }
        }

        if (best.out2 <= 0n) continue;

        const delta = best.out2 - owed;
        const edgeBps =
          delta > 0n
            ? (delta * 10000n) / owed
            : -((owed - best.out2) * 10000n) / owed;

        console.log(
          `🔎 ${token.symbol} size ${formatUnits(size, token.decimals)} ` +
            `via ${best.aName} → ${best.bName} ` +
            `out ${formatUnits(best.out2, token.decimals)} ` +
            `owed ${formatUnits(owed, token.decimals)} ` +
            `edge ${edgeBps} bps`
        );

        if (delta <= 0n || edgeBps < MIN_EDGE_BPS) continue;

        foundProfitable = true;

        const minOut1 = applySlippage(best.out1);
        const minOut2 = applySlippage(best.out2);
        const typeA =
          best.aType === "v2" ? 0 : best.aType === "curve" ? 1 : 2;
        const typeB =
          best.bType === "v2" ? 0 : best.bType === "curve" ? 1 : 2;
        const routerA = typeA === 2 ? BALANCER_VAULT.address : best.aAddr;
        const routerB = typeB === 2 ? BALANCER_VAULT.address : best.bAddr;
        const curveI1 = BigInt(best.aMeta.curveI ?? 0);
        const curveJ1 = BigInt(best.aMeta.curveJ ?? 1);
        const curveI2 = BigInt(best.bMeta.curveI ?? 0);
        const curveJ2 = BigInt(best.bMeta.curveJ ?? 1);
        const balPidA =
          best.aMeta.poolId ||
          "0x0000000000000000000000000000000000000000000000000000000000000000";
        const balPidB =
          best.bMeta.poolId ||
          "0x0000000000000000000000000000000000000000000000000000000000000000";

        try {
          console.log(
            `💡 Flash loan ${token.symbol} size ${formatUnits(size, token.decimals)}`
          );
          const tx = await flashBot[
            "initiateFlashLoanMulti(address,uint256,address,address,address[],address[],uint256,uint256,uint8,uint8,bytes32,bytes32,int128,int128,int128,int128)"
          ](
            token.asset,
            size,
            routerA,
            routerB,
            best.path1,
            best.path2,
            minOut1,
            minOut2,
            typeA,
            typeB,
            balPidA,
            balPidB,
            curveI1,
            curveJ1,
            curveI2,
            curveJ2,
            { gasLimit: 2_200_000 }
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
            console.log(
              `💰 Profit ${key}: +${formatUnits(netGain, token.decimals)} | total ${formatUnits(next, token.decimals)}`
            );
            successHistory.set(
              assetL,
              (successHistory.get(assetL) || 0) + 1
            );
          } else {
            console.log("ℹ️ No profit recorded (≤ 0)");
            successHistory.set(
              assetL,
              Math.max(0, (successHistory.get(assetL) || 0) - 1)
            );
          }
          executed = true;
          break;
        } catch (e) {
          const msg =
            (e && (e.reason || e.shortMessage || e.message)) || String(e);
          console.warn(`❌ TX failed for ${token.symbol}: ${msg}`);
          successHistory.set(
            assetL,
            Math.max(0, (successHistory.get(assetL) || 0) - 2)
          );
        }
      }

      if (executed) {
        await sleep(1200);
        continue;
      }
      if (!foundProfitable) {
        cooldown.set(assetL, round + 3);
      }
    }

    // End-of-round: rotate RPC, refresh pool info, reconnect flashBot
    try {
      await reconnectAll();
      poolAddr = await getPoolAddr();
      premiumBps = await getPremiumBps(poolAddr);
    } catch (e) {
      console.error("❌ End-of-round RPC rotation failed:", e.message);
    }
    await sleep(1500);
  }
}

main().catch(err => {
  console.error("💥 Fatal error:", err);
  process.exit(1);
});
