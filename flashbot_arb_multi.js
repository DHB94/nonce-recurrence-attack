// ======== Flash Sandwich Bot — Arbitrum ========
// Monitors mempool for V2 swaps, simulates sandwich profitability,
// executes atomic front-run + back-run via Aave V3 flash loan.
"use strict";
const fs = require("fs");
const solc = require("solc");
const { ethers } = require("ethers");
const dotenv = require("dotenv");
dotenv.config();

// ======== constants & RPC setup ========
const RPC_LIST = (
  process.env.RPC_LIST ||
  process.env.WRITE_RPC ||
  "https://arb1.arbitrum.io/rpc,https://arbitrum-one-rpc.publicnode.com,https://arbitrum.drpc.org,https://rpc.ankr.com/arbitrum"
)
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const WSS_URL = process.env.WSS_URL || "wss://arbitrum-one-rpc.publicnode.com";

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

const ADDRESS_FILE = "FlashBotSandwich.address.txt";
const DEPLOYMENTS_FILE = ".sandwich_deployments.json";

// Sandwich parameters
const SLIPPAGE_BPS = BigInt(process.env.SLIPPAGE_BPS || "50");
const MAX_BORROW_BPS = BigInt(process.env.MAX_BORROW_BPS || "4200");
const MIN_PROFIT_BPS = BigInt(process.env.MIN_PROFIT_BPS || "10");
const GAS_LIMIT = parseInt(process.env.GAS_LIMIT || "1200000", 10);
const PRIORITY_FEE_FLOOR_GWEI = process.env.PRIORITY_FEE_FLOOR_GWEI || "0.01";
const PRIORITY_FEE_MULTIPLIER = Number(process.env.PRIORITY_FEE_MULTIPLIER || "1.5");
const MIN_VICTIM_USD = Number(process.env.MIN_VICTIM_USD || "500");
const MIN_RESERVE_USD = Number(process.env.MIN_RESERVE_USD || "50000");

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

interface ICurveCryptoPool {
    function exchange(uint256 i, uint256 j, uint256 dx, uint256 min_dy) external returns (uint256);
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

interface IBalancerV3Router {
    function swapSingleTokenExactIn(
        address pool,
        address tokenIn,
        address tokenOut,
        uint256 exactAmountIn,
        uint256 minAmountOut,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    ) external returns (uint256 amountOut);
}

contract FlashSandwichMultiVenue is FlashLoanReceiverBase {
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

    event FrontRun(address router, uint8 legType, address[] path, uint256 amountIn, uint256 amountOut);
    event BackRun(address router, uint8 legType, address[] path, uint256 amountIn, uint256 amountOut);
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

    function initiateSandwich(
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
        require(typeA <= 4 && typeB <= 4, "invalid types");

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

        // ---- Front-run swap ----
        if (pTypeA == 0) {
            safeApprove(IERC20(asset), pRouterA, amount);
            uint256 before1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this));
            try IUniswapV2Router02(pRouterA).swapExactTokensForTokens(
                amount, pMinOut1, pPath1, address(this), block.timestamp
            ) {
                out1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this)) - before1;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("V2 front failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("V2 front failed");
            }
        } else if (pTypeA == 1) {
            safeApprove(IERC20(asset), pRouterA, amount);
            try ICurvePool(pRouterA).exchange(pCurveI1, pCurveJ1, amount, pMinOut1) returns (uint256 result) {
                out1 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("Curve front failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("Curve front failed");
            }
        } else if (pTypeA == 2) {
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
                revert(string(abi.encodePacked("BalV2 front failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("BalV2 front failed");
            }
        } else if (pTypeA == 3) {
            safeApprove(IERC20(asset), pRouterA, amount);
            try IBalancerV3Router(pRouterA).swapSingleTokenExactIn(
                address(uint160(uint256(pBalPoolIdA))), pPath1[0], pPath1[1],
                amount, pMinOut1, block.timestamp, false, ""
            ) returns (uint256 result) {
                out1 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("BalV3 front failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("BalV3 front failed");
            }
        } else {
            safeApprove(IERC20(asset), pRouterA, amount);
            try ICurveCryptoPool(pRouterA).exchange(
                uint256(int256(pCurveI1)), uint256(int256(pCurveJ1)), amount, pMinOut1
            ) returns (uint256 result) {
                out1 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("CurveCrypto front failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "unknown");
                revert("CurveCrypto front failed");
            }
        }
        emit FrontRun(pRouterA, pTypeA, pPath1, amount, out1);

        // ---- Back-run swap ----
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
                revert(string(abi.encodePacked("V2 back failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("V2 back failed");
            }
        } else if (pTypeB == 1) {
            safeApprove(IERC20(pPath2[0]), pRouterB, out1);
            try ICurvePool(pRouterB).exchange(pCurveI2, pCurveJ2, out1, pMinOut2) returns (uint256 result) {
                out2 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterB, reason);
                revert(string(abi.encodePacked("Curve back failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("Curve back failed");
            }
        } else if (pTypeB == 2) {
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
                revert(string(abi.encodePacked("BalV2 back failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("BalV2 back failed");
            }
        } else if (pTypeB == 3) {
            safeApprove(IERC20(pPath2[0]), pRouterB, out1);
            try IBalancerV3Router(pRouterB).swapSingleTokenExactIn(
                address(uint160(uint256(pBalPoolIdB))), pPath2[0], pPath2[1],
                out1, pMinOut2, block.timestamp, false, ""
            ) returns (uint256 result) {
                out2 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterB, reason);
                revert(string(abi.encodePacked("BalV3 back failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("BalV3 back failed");
            }
        } else {
            safeApprove(IERC20(pPath2[0]), pRouterB, out1);
            try ICurveCryptoPool(pRouterB).exchange(
                uint256(int256(pCurveI2)), uint256(int256(pCurveJ2)), out1, pMinOut2
            ) returns (uint256 result) {
                out2 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterB, reason);
                revert(string(abi.encodePacked("CurveCrypto back failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterB, "unknown");
                revert("CurveCrypto back failed");
            }
        }
        emit BackRun(pRouterB, pTypeB, pPath2, out1, out2);

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
    sources: { "FlashSandwichMultiVenue.sol": { content: FLASHBOT_SOURCE } },
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
  "function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)",
  "function factory() external view returns (address)"
];
const FACTORY_ABI = [
  "function getPair(address tokenA, address tokenB) external view returns (address)"
];
const PAIR_ABI = [
  "function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)",
  "function token0() external view returns (address)",
  "function token1() external view returns (address)"
];
const ERC20_META_ABI = [
  "function decimals() external view returns (uint8)",
  "function symbol() external view returns (string)"
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
const PROVIDER_ABI = ["function getPool() view returns (address)"];
const POOL_ABI = ["function FLASHLOAN_PREMIUM_TOTAL() view returns (uint128)"];
const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

// Router interface for decoding victim transactions
const routerInterface = new ethers.Interface([
  "function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline)",
  "function swapExactETHForTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) payable",
  "function swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline)",
  "function swapTokensForExactTokens(uint256 amountOut, uint256 amountInMax, address[] calldata path, address to, uint256 deadline)"
]);
const DECODABLE_METHODS = new Set([
  "swapExactTokensForTokens",
  "swapExactETHForTokens",
  "swapExactTokensForETH"
]);

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
        console.log("📌 Using existing FlashSandwich at " + addr);
        return { address: addr, abi };
      }
    } catch (_) {
      console.warn("⚠️ Could not verify existing contract, redeploying...");
    }
  }

  console.log("🚀 Deploying FlashSandwich...");
  const gasSettings = [
    { gasLimit: 5_000_000, gasPrice: ethers.parseUnits("0.1", "gwei") },
    { gasLimit: 6_000_000, gasPrice: ethers.parseUnits("0.15", "gwei") },
    { gasLimit: 7_000_000, gasPrice: ethers.parseUnits("0.2", "gwei") },
    { gasLimit: 8_000_000, gasPrice: ethers.parseUnits("0.25", "gwei") },
    { gasLimit: 10_000_000, gasPrice: ethers.parseUnits("0.3", "gwei") }
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

// ======== network tokens & venues (Arbitrum) ========
const WETH = "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1";

const TOKENS = [
  { symbol: "USDC", asset: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6 },
  { symbol: "USDC.e", asset: "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", decimals: 6 },
  { symbol: "WETH", asset: WETH, decimals: 18 },
  { symbol: "DAI", asset: "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", decimals: 18 },
  { symbol: "USDT", asset: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6 },
  { symbol: "WBTC", asset: "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f", decimals: 8 },
  { symbol: "ARB", asset: "0x912CE59144191C1204E64559FE8253a0e49E6548", decimals: 18 },
  { symbol: "LINK", asset: "0xf97f4df75117a78c1A5a0DBb814Af92458539FB4", decimals: 18 },
  { symbol: "GMX", asset: "0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a", decimals: 18 },
  { symbol: "wstETH", asset: "0x5979D7b546E38E414F7E9822514be443A4800529", decimals: 18 }
];

const TOKEN_MAP = new Map(TOKENS.map(t => [t.asset.toLowerCase(), t]));

const ROUTERS = [
  { name: "UniswapV2", address: "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24" },
  { name: "SushiV2", address: "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506" }
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
const BALANCER_V3_ROUTERS = {
  mainnet: "0xAE563E3f8219521950555F5962419C8919758Ea2",
  arbitrum: "0xEAedc32a51c510d35ebC11088fD5fF2b47aACF2E",
  base: "0x3f170631ed9821Ca51A59D996aB095162438DC10",
  optimism: "0xe2fa4e1d17725e72dcdAfe943Ecf45dF4B9E285b",
  gnosis: "0x4eff2d77D9fFbAeFB4b141A3e494c085b3FF4Cb5",
  avalanche: "0xF39CA6ede9BF7820a952b52f3c94af526bAB9015"
};
const CHAIN_NAME = (process.env.CHAIN_NAME || "arbitrum").toLowerCase();
const BALANCER_V3_ROUTER_ADDR = BALANCER_V3_ROUTERS[CHAIN_NAME] || null;

let BALANCER_POOLS = [];
try {
  if (fs.existsSync("balancer_pools.json")) {
    BALANCER_POOLS = JSON.parse(fs.readFileSync("balancer_pools.json", "utf8"));
    console.log(`📋 Loaded ${BALANCER_POOLS.length} Balancer pool(s)`);
  }
} catch (_) {
  console.warn("⚠️ Could not load balancer_pools.json");
}

function findBalancerPoolId(tokenA, tokenB) {
  const a = tokenA.toLowerCase(), b = tokenB.toLowerCase();
  for (const pool of BALANCER_POOLS) {
    const t = pool.tokens.map(x => x.toLowerCase());
    if (t.includes(a) && t.includes(b)) return pool.poolId;
  }
  return null;
}

function findBalancerV3Pool(tokenA, tokenB) {
  const a = tokenA.toLowerCase(), b = tokenB.toLowerCase();
  for (const pool of BALANCER_POOLS) {
    if (!pool.v3Address) continue;
    const t = pool.tokens.map(x => x.toLowerCase());
    if (t.includes(a) && t.includes(b)) return pool.v3Address;
  }
  return null;
}

// ======== helpers ========
function toLower(a) { return a.toLowerCase(); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function formatUnits(bi, dec) {
  try { return ethers.formatUnits(bi, dec); } catch(_) { return bi.toString(); }
}

// ======== AMM math (constant product) ========
function getAmountOut(amountIn, reserveIn, reserveOut) {
  if (amountIn <= 0n || reserveIn <= 0n || reserveOut <= 0n) return 0n;
  const amountInWithFee = amountIn * 997n;
  const numerator = amountInWithFee * reserveOut;
  const denominator = reserveIn * 1000n + amountInWithFee;
  if (denominator === 0n) return 0n;
  return numerator / denominator;
}

function clampBorrow(amount, reserveIn) {
  const maxBorrow = (reserveIn * MAX_BORROW_BPS) / 10_000n;
  return maxBorrow === 0n ? 0n : (amount > maxBorrow ? maxBorrow : amount);
}

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

function simulateSandwich(borrowAmount, victimAmount, reserveIn, reserveOut, premiumBps) {
  if (borrowAmount === 0n) return null;
  const flashLoanFee = (borrowAmount * premiumBps) / 10_000n;

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

  const netProfit = backOut - borrowAmount - flashLoanFee;
  if (netProfit <= 0n) return null;

  const minFrontOut = (frontOut * (10_000n - SLIPPAGE_BPS)) / 10_000n;
  const minBackOut = (backOut * (10_000n - SLIPPAGE_BPS)) / 10_000n;

  return {
    borrowAmount, flashLoanFee, frontOut, victimOut, backOut, netProfit,
    minFrontOut, minBackOut
  };
}

// ======== pair & reserve lookups ========
const pairCache = new Map();
const tokenMetaCache = new Map();
const observedVictims = new Set();

async function getPairAddress(factoryContract, tokenA, tokenB) {
  const key = [tokenA, tokenB].sort().join(":");
  if (pairCache.has(key)) return pairCache.get(key);
  try {
    const addr = (await factoryContract.getPair(tokenA, tokenB))?.toLowerCase();
    if (!addr || addr === ethers.ZeroAddress.toLowerCase()) return null;
    pairCache.set(key, addr);
    return addr;
  } catch (_) { return null; }
}

async function getReserves(pairAddress, provider) {
  const pair = new ethers.Contract(pairAddress, PAIR_ABI, provider);
  const [r0, r1] = await pair.getReserves();
  const t0 = (await pair.token0()).toLowerCase();
  const t1 = (await pair.token1()).toLowerCase();
  return { reserve0: BigInt(r0), reserve1: BigInt(r1), token0: t0, token1: t1 };
}

async function getTokenMeta(address, provider) {
  const key = address.toLowerCase();
  if (tokenMetaCache.has(key)) return tokenMetaCache.get(key);
  const known = TOKEN_MAP.get(key);
  if (known) {
    const meta = { decimals: known.decimals, symbol: known.symbol };
    tokenMetaCache.set(key, meta);
    return meta;
  }
  const c = new ethers.Contract(address, ERC20_META_ABI, provider);
  let decimals = 18, symbol = address.slice(0, 6);
  try { decimals = Number(await c.decimals()); } catch (_) {}
  try { symbol = await c.symbol(); } catch (_) {}
  const meta = { decimals, symbol };
  tokenMetaCache.set(key, meta);
  return meta;
}

// ======== sandwich evaluation ========
async function evaluateSandwich(tx, parsed, routerConfig, provider, premiumBps) {
  const path = (parsed.args.path || []).map(a => a.toLowerCase());
  if (path.length !== 2) return null;

  const [tokenIn, tokenOut] = path;
  const pairAddr = await getPairAddress(routerConfig.factoryContract, tokenIn, tokenOut);
  if (!pairAddr) return null;

  let reserves;
  try {
    reserves = await getReserves(pairAddr, provider);
  } catch (_) { return null; }

  const reserveIn = reserves.token0 === tokenIn ? reserves.reserve0 : reserves.reserve1;
  const reserveOut = reserves.token0 === tokenIn ? reserves.reserve1 : reserves.reserve0;
  if (reserveIn === 0n || reserveOut === 0n) return null;

  // Determine victim's input amount
  let victimIn = 0n;
  if (parsed.name === "swapExactTokensForTokens" || parsed.name === "swapExactTokensForETH") {
    victimIn = BigInt(parsed.args.amountIn.toString());
  } else if (parsed.name === "swapExactETHForTokens") {
    victimIn = BigInt(tx.value.toString());
  }
  if (victimIn === 0n) return null;

  const tokenInMeta = await getTokenMeta(tokenIn, provider);

  // Optimize borrow amount
  const candidates = generateBorrowCandidates(victimIn, reserveIn);
  let best = null;
  for (const candidate of candidates) {
    const sim = simulateSandwich(candidate, victimIn, reserveIn, reserveOut, premiumBps);
    if (!sim) continue;
    if (!best || sim.netProfit > best.netProfit) best = sim;
  }
  if (!best) return null;

  // Check minimum profit threshold
  const profitBps = (best.netProfit * 10_000n) / best.borrowAmount;
  if (profitBps < MIN_PROFIT_BPS) return null;

  return {
    asset: tokenIn,
    tokenOut,
    assetMeta: tokenInMeta,
    pathForward: [tokenIn, tokenOut],
    pathBackward: [tokenOut, tokenIn],
    router: routerConfig,
    pairAddress: pairAddr,
    victimIn,
    borrowAmount: best.borrowAmount,
    frontOut: best.frontOut,
    backOut: best.backOut,
    minFrontOut: best.minFrontOut,
    minBackOut: best.minBackOut,
    netProfit: best.netProfit,
    flashLoanFee: best.flashLoanFee,
    profitBps,
    victimTx: tx
  };
}

// ======== gas overrides ========
async function getFeeOverrides(provider) {
  if (process.env.FIXED_GAS_PRICE_GWEI) {
    return { gasPrice: ethers.parseUnits(process.env.FIXED_GAS_PRICE_GWEI, 9) };
  }
  const feeData = await provider.getFeeData();
  const floor = ethers.parseUnits(PRIORITY_FEE_FLOOR_GWEI, 9);
  const basePriority = feeData.maxPriorityFeePerGas ?? 0n;
  const priority = basePriority > floor ? basePriority : floor;
  const boosted = (priority * BigInt(Math.round(PRIORITY_FEE_MULTIPLIER * 100))) / 100n;
  const maxFee = ((feeData.lastBaseFeePerGas ?? boosted) * 2n) + boosted;
  return { maxFeePerGas: maxFee, maxPriorityFeePerGas: boosted };
}

// ======== profit persistence ========
const PROFIT_JSON = "sandwich_profit.json";
const PROFIT_CSV = "sandwich_profit.csv";

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

function appendProfitCSV(ts, symbol, amountStr, victimHash) {
  try {
    const headerNeeded = !fs.existsSync(PROFIT_CSV);
    if (headerNeeded) fs.writeFileSync(PROFIT_CSV, "timestamp,symbol,amount,victim_tx\n");
    fs.appendFileSync(PROFIT_CSV, `${ts},${symbol},${amountStr},${victimHash}\n`);
  } catch (_) {}
}

// ======== main ========
async function main() {
  let httpProvider = await getProvider();
  let wallet = new ethers.Wallet(process.env.PRIVATE_KEY, httpProvider);

  console.log("🔍 HTTP RPC connected. Block:", await httpProvider.getBlockNumber());

  // Deploy/load flash loan contract
  const deployed = await deploy(httpProvider, wallet, false);
  let flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
  const iface = new ethers.Interface(deployed.abi);

  // Aave pool info
  let providerContract = new ethers.Contract(
    process.env.AAVE_POOL_ADDRESSES_PROVIDER, PROVIDER_ABI, httpProvider
  );
  let poolAddr = await providerContract.getPool();
  const poolContract = new ethers.Contract(poolAddr, POOL_ABI, httpProvider);
  let premiumBps;
  try {
    premiumBps = BigInt(await poolContract.FLASHLOAN_PREMIUM_TOTAL());
  } catch (_) {
    console.warn("⚠️ Could not read premium, defaulting to 5 bps");
    premiumBps = 5n;
  }
  console.log("🏦 Aave pool:", poolAddr, "| premium:", premiumBps.toString(), "bps");

  // Discover factory addresses for each V2 router
  const monitoredRouters = [];
  for (const r of ROUTERS) {
    try {
      const routerContract = new ethers.Contract(r.address, V2_ROUTER_ABI, httpProvider);
      const factoryAddr = await routerContract.factory();
      const factoryContract = new ethers.Contract(factoryAddr, FACTORY_ABI, httpProvider);
      monitoredRouters.push({
        ...r,
        factoryAddr,
        factoryContract,
        routerLower: r.address.toLowerCase()
      });
      console.log(`✅ ${r.name}: factory ${factoryAddr}`);
    } catch (err) {
      console.warn(`⚠️ Could not discover factory for ${r.name}: ${err.message}`);
    }
  }
  if (monitoredRouters.length === 0) {
    console.error("❌ No monitored routers discovered");
    process.exit(1);
  }

  const profitState = loadProfitState();
  let sandwichCount = 0;
  let processedCount = 0;

  // Connect WebSocket for mempool monitoring
  console.log(`🌐 Connecting WebSocket: ${WSS_URL.substring(0, 50)}...`);
  let wsProvider;
  try {
    wsProvider = new ethers.WebSocketProvider(WSS_URL, undefined, { timeout: 30_000 });
    const wsBlock = await wsProvider.getBlockNumber();
    console.log(`✅ WebSocket connected, block ${wsBlock}`);
  } catch (err) {
    console.error(`❌ WebSocket connection failed: ${err.message}`);
    console.log("⚠️ Falling back to HTTP polling mode...");
    wsProvider = null;
  }

  async function handlePendingTx(txHash) {
    try {
      if (observedVictims.has(txHash)) return;

      const tx = await (wsProvider || httpProvider).getTransaction(txHash);
      if (!tx || !tx.to) return;

      const toLow = tx.to.toLowerCase();
      const routerConfig = monitoredRouters.find(r => r.routerLower === toLow);
      if (!routerConfig) return;

      let parsed;
      try {
        parsed = routerInterface.parseTransaction({ data: tx.data, value: tx.value });
      } catch { return; }

      if (!parsed || !DECODABLE_METHODS.has(parsed.name)) return;

      observedVictims.add(txHash);
      if (observedVictims.size > 50_000) observedVictims.clear();
      processedCount++;

      const opportunity = await evaluateSandwich(tx, parsed, routerConfig, httpProvider, premiumBps);
      if (!opportunity) return;

      // Log opportunity
      const profit = formatUnits(opportunity.netProfit, opportunity.assetMeta.decimals);
      const borrow = formatUnits(opportunity.borrowAmount, opportunity.assetMeta.decimals);
      const victim = formatUnits(opportunity.victimIn, opportunity.assetMeta.decimals);
      console.log(
        `🥪 [${opportunity.assetMeta.symbol}] victim=${victim} borrow=${borrow} ` +
        `profit=${profit} edge=${opportunity.profitBps} bps via ${routerConfig.name}`
      );

      // Execute sandwich
      const gasOverrides = await getFeeOverrides(httpProvider);

      const ZERO_ID = "0x0000000000000000000000000000000000000000000000000000000000000000";
      try {
        const tx = await flashBot.initiateSandwich(
          opportunity.asset,
          opportunity.borrowAmount,
          routerConfig.address,
          routerConfig.address,
          opportunity.pathForward,
          opportunity.pathBackward,
          opportunity.minFrontOut,
          opportunity.minBackOut,
          0, 0,   // typeA=V2, typeB=V2
          ZERO_ID, ZERO_ID,
          0, 0, 0, 0,
          { gasLimit: GAS_LIMIT, ...gasOverrides }
        );
        console.log("🚀 Sandwich TX sent:", tx.hash);
        const receipt = await tx.wait();
        console.log("✅ Confirmed in block", receipt.blockNumber);

        // Parse profit from events
        let netGain = 0n;
        for (const log of receipt.logs) {
          try {
            const p = iface.parseLog(log);
            if (p && p.name === "Profit") netGain = BigInt(p.args.netGain.toString());
          } catch (_) {}
        }

        sandwichCount++;
        if (netGain > 0n) {
          const ts = new Date().toISOString();
          const sym = opportunity.assetMeta.symbol;
          const prev = profitState[sym] ? BigInt(profitState[sym]) : 0n;
          const next = prev + netGain;
          profitState[sym] = next.toString();
          saveProfitState(profitState);
          appendProfitCSV(ts, sym, formatUnits(netGain, opportunity.assetMeta.decimals), opportunity.victimTx.hash);
          console.log(
            `💰 Profit ${sym}: +${formatUnits(netGain, opportunity.assetMeta.decimals)} ` +
            `| total ${formatUnits(next, opportunity.assetMeta.decimals)}`
          );
        }
      } catch (e) {
        const msg = e.reason || e.shortMessage || e.message || String(e);
        console.warn(`❌ Sandwich TX failed: ${msg}`);
      }
    } catch (err) {
      // Silently ignore individual TX processing errors
    }
  }

  // Subscribe to pending transactions
  if (wsProvider) {
    wsProvider.on("pending", handlePendingTx);
    console.log("👂 Mempool listener attached — awaiting profitable swaps.");
    console.log(`📡 Monitoring routers: ${monitoredRouters.map(r => r.name).join(", ")}`);
    console.log(`🔧 Config: slippage=${SLIPPAGE_BPS} bps, maxBorrow=${MAX_BORROW_BPS} bps, minProfit=${MIN_PROFIT_BPS} bps`);

    // Keepalive: periodically refresh pool info and log stats
    setInterval(async () => {
      try {
        const block = await httpProvider.getBlockNumber();
        console.log(`📊 Stats: block=${block} processed=${processedCount} sandwiches=${sandwichCount}`);

        // Refresh Aave info
        poolAddr = await providerContract.getPool();
        const pc = new ethers.Contract(poolAddr, POOL_ABI, httpProvider);
        premiumBps = BigInt(await pc.FLASHLOAN_PREMIUM_TOTAL());
      } catch (_) {}
    }, 60_000);

    // Handle WebSocket disconnection
    wsProvider.websocket?.on?.("close", async () => {
      console.warn("⚠️ WebSocket disconnected, reconnecting...");
      await sleep(5000);
      try {
        wsProvider = new ethers.WebSocketProvider(WSS_URL, undefined, { timeout: 30_000 });
        wsProvider.on("pending", handlePendingTx);
        console.log("✅ WebSocket reconnected");
      } catch (err) {
        console.error("❌ Reconnection failed:", err.message);
      }
    });
  } else {
    // Fallback: HTTP polling for new blocks (less effective but works without WSS)
    console.log("📡 Running in HTTP polling mode (no WSS)...");
    console.log(`📡 Monitoring routers: ${monitoredRouters.map(r => r.name).join(", ")}`);

    let lastBlock = await httpProvider.getBlockNumber();
    while (true) {
      try {
        const currentBlock = await httpProvider.getBlockNumber();
        if (currentBlock > lastBlock) {
          const block = await httpProvider.getBlock(currentBlock, true);
          if (block && block.transactions) {
            for (const txHash of block.transactions) {
              await handlePendingTx(txHash);
            }
          }
          lastBlock = currentBlock;
          if (currentBlock % 100 === 0) {
            console.log(`📊 Block ${currentBlock} | processed=${processedCount} sandwiches=${sandwichCount}`);
          }
        }
      } catch (err) {
        console.warn("⚠️ Polling error:", err.message);
        try {
          httpProvider = await rotateRPC();
          wallet = new ethers.Wallet(process.env.PRIVATE_KEY, httpProvider);
          flashBot = flashBot.connect(wallet);
          providerContract = new ethers.Contract(
            process.env.AAVE_POOL_ADDRESSES_PROVIDER, PROVIDER_ABI, httpProvider
          );
        } catch (_) {}
      }
      await sleep(250);
    }
  }
}

main().catch(err => {
  console.error("💥 Fatal error:", err);
  process.exit(1);
});
