// ======== requires & config ========
const fs = require("fs");
const solc = require("solc");
const { ethers } = require("ethers");
const dotenv = require("dotenv");
const { FlashbotsBundleProvider } = require("@flashbots/ethers-provider-bundle");
dotenv.config();

// ======== constants & RPC setup ========
const RPC_LIST = (process.env.RPC_LIST || process.env.WRITE_RPC || "")
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

function normalizeAddress(value, envName) {
  const addr = (value || "").trim();
  if (!addr) {
    console.error(`Missing ${envName} value`);
    process.exit(1);
  }
  try {
    return ethers.getAddress(addr);
  } catch (error) {
    try {
      const lowered = addr.toLowerCase();
      const checksummed = ethers.getAddress(lowered);
      console.warn(`⚠️ ${envName} not checksummed, normalized to ${checksummed}`);
      return checksummed;
    } catch (inner) {
      console.error(`Invalid address for ${envName}: ${addr}`);
      console.error(inner.message || inner);
      process.exit(1);
    }
  }
}

const AAVE_PROVIDER_ADDRESS = normalizeAddress(
  process.env.AAVE_POOL_ADDRESSES_PROVIDER,
  "AAVE_POOL_ADDRESSES_PROVIDER"
);
const TARGET_ADDRESS = normalizeAddress(process.env.TARGET_TOKEN, "TARGET_TOKEN");
const TARGET = TARGET_ADDRESS.toLowerCase();
const ADDRESS_FILE = "FlashBotArb.address.txt";
const PROFIT_JSON = "profit_per_token.json";
const PROFIT_CSV = "profit_per_token.csv";
const MIN_ABS_PROFIT_NATIVE = ethers.parseUnits(
  process.env.MIN_ABS_PROFIT_NATIVE || "2",
  18
);
const FLASHBOTS_ENDPOINT = "https://rpc.flashbots.net/"; // Polygon Flashbots RPC

let rpcIndex = 0;
async function getProvider(maxRetries = 3, retryDelay = 1000) {
  const provider = new ethers.JsonRpcProvider(RPC_LIST[rpcIndex]);

  for (let i = 0; i < maxRetries; i++) {
    try {
      await provider.getBlockNumber();
      return provider;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      console.warn(`⚠️ RPC connection attempt ${i + 1} failed, retrying...`);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
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
      console.warn(`🔄 Attempting to switch to RPC ${rpcIndex + 1}/${RPC_LIST.length}`);
      const provider = await getProvider(1);
      console.warn(
        `✅ Connected to RPC ${rpcIndex + 1}: ${RPC_LIST[rpcIndex].substring(0, 40)}...`
      );
      return provider;
    } catch (error) {
      console.warn(`❌ Failed to connect to RPC ${rpcIndex + 1}: ${error.message}`);
      if (attempts >= RPC_LIST.length) {
        throw new Error(
          "All RPC endpoints failed. Please check your internet connection or try again later."
        );
      }
    }
  } while (rpcIndex !== initialIndex);

  throw new Error("RPC rotation failed");
}

let provider;
let wallet;

(async () => {
  try {
    provider = await getProvider();
    wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

    main().catch(error => {
      console.error("❌ Fatal error in main loop:", error);
      process.exit(1);
    });
  } catch (error) {
    console.error("❌ Failed to initialize wallet:", error.message);
    process.exit(1);
  }
})();

// ======== Solidity contract source ========
const FLASHBOT_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface IPoolAddressesProvider { function getPool() external view returns (address); }
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
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}
interface IFlashLoanRecipient {
    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata data
    ) external returns (bool);
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
    function approve(address spender,uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
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
    function exchange(int128 i,int128 j,uint256 dx,uint256 min_dy) external returns (uint256);
}
interface I1InchAggregator {
    function swap(
        address fromToken,
        address toToken,
        uint256 amount,
        uint256 minReturnAmount,
        uint256[] calldata pools,
        uint256 flags,
        address payable referrer
    ) external payable returns (uint256 returnAmount);
}

contract FlashBotArbMultiVenue is FlashLoanReceiverBase, IFlashLoanRecipient {
    struct SwapParams {
        address routerA;
        address routerB;
        address[] path1;
        address[] path2;
        uint256 minOut1;
        uint256 minOut2;
        uint8 legTypeA;
        uint8 legTypeB;
        bytes32 balPoolIdA;
        bytes32 balPoolIdB;
        int128 curveI1;
        int128 curveJ1;
        int128 curveI2;
        int128 curveJ2;
    }

    SwapParams private swapParams;
    address public immutable owner;
    uint8 public pTypeA;
    uint8 public pTypeB;
    address public pRouterA;

    bool private locked;

    event FlashLoanReceived(address indexed token, uint256 amount, uint256 fee);
    event FlashLoanRepaid(address indexed token, uint256 amount, uint256 fee);
    event SwapFailed(address indexed router, string reason);
    event EmergencyWithdraw(address indexed token, uint256 amount);
    event Leg1(address router,uint8 legType,address[] path,uint256 amountIn,uint256 minOut,uint256 amountOut);
    event Leg2(address router,uint8 legType,address[] path,uint256 amountIn,uint256 minOut,uint256 amountOut);
    event Repay(uint256 owed,uint256 balance);
    event Profit(uint256 netGain);

    modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyPool() {
        require(msg.sender == address(POOL), "Caller is not the pool");
        _;
    }

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

    constructor(address provider) FlashLoanReceiverBase(IPoolAddressesProvider(provider)) {
        owner = msg.sender;
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
        require(typeA <= 3 && typeB <= 3,"invalid types");
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

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata data
    ) external override onlyPool noReentrant returns (bool) {
        address token = tokens[0];
        uint256 amount = amounts[0];
        uint256 fee = feeAmounts[0];
        emit FlashLoanReceived(token, amount, fee);
        (bool success, ) = address(this).call(
            abi.encodeWithSignature(
                "executeOperation(address[],uint256[],uint256[],address,bytes)",
                tokens,
                amounts,
                feeAmounts,
                msg.sender,
                data
            )
        );
        require(success, "Execute operation failed");
        (bool transferSuccess, ) = address(token).call(
            abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount + fee)
        );
        require(transferSuccess, "Token transfer failed");
        emit FlashLoanRepaid(token, amount, fee);
        return true;
    }

    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        (bool success1, ) = address(token).call(abi.encodeWithSignature("approve(address,uint256)", spender, 0));
        require(success1, "Approve reset failed");
        (bool success2, ) = address(token).call(abi.encodeWithSignature("approve(address,uint256)", spender, amount));
        require(success2, "Approve failed");
    }

    function emergencyWithdraw(address token) external {
        require(msg.sender == owner, "Only owner");
        if (token == address(0)) {
            (bool success, ) = payable(owner).call{value: address(this).balance}("");
            require(success, "ETH transfer failed");
        } else {
            (bool success, bytes memory data) = address(token).call(
                abi.encodeWithSignature("balanceOf(address)", address(this))
            );
            require(success, "Balance check failed");
            uint256 balance = abi.decode(data, (uint256));
            (success, ) = address(token).call(
                abi.encodeWithSignature("transfer(address,uint256)", owner, balance)
            );
            require(success, "Token transfer failed");
            emit EmergencyWithdraw(token, balance);
        }
    }

    receive() external payable {}
    fallback() external payable {}

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external override noReentrant returns (bool) {
        address asset = assets[0]; uint256 amount = amounts[0];
        uint256 out1 = 0;
        if (pTypeA == 0) {
            safeApprove(IERC20(asset), pRouterA, amount);
            uint256 before1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this));
            try IUniswapV2Router02(pRouterA).swapExactTokensForTokens(
                amount,
                pMinOut1,
                pPath1,
                address(this),
                block.timestamp
            ) {
                out1 = IERC20(pPath1[pPath1.length - 1]).balanceOf(address(this)) - before1;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("V2 swap failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "Unknown error");
                revert("V2 swap failed: Unknown error");
            }
        } else if (pTypeA == 1) {
            safeApprove(IERC20(asset), pRouterA, amount);
            try ICurvePool(pRouterA).exchange(pCurveI1, pCurveJ1, amount, pMinOut1) returns (uint256 returnedAmount) {
                out1 = returnedAmount;
            }
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("Curve swap failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "Unknown error");
                revert("Curve swap failed: Unknown error");
            }
        } else if (pTypeA == 2) {
            safeApprove(IERC20(asset), pRouterA, amount);
            IBalancerVault.SingleSwap memory swapA = IBalancerVault.SingleSwap({
                poolId: pBalPoolIdA,
                kind: 0,
                assetIn: pPath1[0],
                assetOut: pPath1[1],
                amount: amount,
                userData: ""
            });
            IBalancerVault.FundManagement memory fundsA = IBalancerVault.FundManagement({
                sender: address(this),
                fromInternalBalance: false,
                recipient: payable(address(this)),
                toInternalBalance: false
            });
            try IBalancerVault(pRouterA).swap(swapA, fundsA, pMinOut1, block.timestamp) {
                out1 = IERC20(pPath1[1]).balanceOf(address(this));
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("Balancer swap failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "Unknown error");
                revert("Balancer swap failed: Unknown error");
            }
        } else if (pTypeA == 3) {
            safeApprove(IERC20(asset), pRouterA, amount);
            uint256[] memory pools = new uint256[](1);
            pools[0] = 1;
            try I1InchAggregator(pRouterA).swap{ value: 0 }(
                asset,
                pPath1[1],
                amount,
                pMinOut1,
                pools,
                0,
                payable(address(0))
            ) returns (uint256 result) {
                out1 = result;
            } catch Error(string memory reason) {
                emit SwapFailed(pRouterA, reason);
                revert(string(abi.encodePacked("1Inch swap failed: ", reason)));
            } catch (bytes memory) {
                emit SwapFailed(pRouterA, "Unknown error");
                revert("1Inch swap failed: Unknown error");
            }
        }

        emit Leg1(pRouterA, pTypeA, pPath1, amount, pMinOut1, out1);

        uint256 out2 = 0;
        if (pTypeB == 0) {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            uint256 before2 = IERC20(asset).balanceOf(address(this));
            IUniswapV2Router02(pRouterB).swapExactTokensForTokens(
                out1,
                pMinOut2,
                pPath2,
                address(this),
                block.timestamp
            );
            out2 = IERC20(asset).balanceOf(address(this)) - before2;
        } else if (pTypeB == 1) {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            out2 = ICurvePool(pRouterB).exchange(pCurveI2, pCurveJ2, out1, pMinOut2);
        } else if (pTypeB == 2) {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            IBalancerVault.SingleSwap memory swapB = IBalancerVault.SingleSwap({
                poolId: pBalPoolIdB,
                kind: 0,
                assetIn: pPath2[0],
                assetOut: pPath2[1],
                amount: out1,
                userData: ""
            });
            IBalancerVault.FundManagement memory fundsB = IBalancerVault.FundManagement({
                sender: address(this),
                fromInternalBalance: false,
                recipient: address(this),
                toInternalBalance: false
            });
            out2 = IBalancerVault(pRouterB).swap(swapB, fundsB, pMinOut2, block.timestamp);
        } else if (pTypeB == 3) {
            IERC20(pPath2[0]).approve(pRouterB, out1);
            uint256[] memory pools = new uint256[](1);
            pools[0] = 1;
            out2 = I1InchAggregator(pRouterB).swap{ value: 0 }(
                pPath2[0],
                asset,
                out1,
                pMinOut2,
                pools,
                0,
                payable(address(0))
            );
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
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
        details: { yul: true }
      },
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
    for (const e of output.errors) {
      console.error(e.formattedMessage || e.message || String(e));
    }
    if (output.errors.some(e => e.severity === "error")) {
      console.error("❌ Solidity compile failed due to errors above.");
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
    console.error(`❌ No contract names in ${fileNames[0]}`);
    process.exit(1);
  }
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
const CURVE_POOL_ABI = ["function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256)"];
const BALANCER_VAULT_ABI = [
  "function queryBatchSwap(uint8 kind, tuple(bytes32 poolId,uint256 assetInIndex,uint256 assetOutIndex,uint256 amount,bytes userData)[] swaps, address[] assets, tuple(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds) external view returns (int256[] assetDeltas)",
  "function flashLoan(address recipient, address[] calldata tokens, uint256[] calldata amounts, bytes calldata data) external"
];
const I1INCH_ABI = [
  "function swap(address fromToken, address toToken, uint256 amount, uint256 minReturnAmount, uint256[] calldata pools, uint256 flags, address payable referrer) external payable returns (uint256 returnAmount)"
];
const PROVIDER_ABI = ["function getPool() view returns (address)"];
const POOL_ABI = ["function FLASHLOAN_PREMIUM_TOTAL() view returns (uint128)"];
const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

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
  const flashBot = await factory.deploy(AAVE_PROVIDER_ADDRESS);
  await flashBot.waitForDeployment();
  const deployedAddress = await flashBot.getAddress();
  fs.writeFileSync(ADDRESS_FILE, deployedAddress);
  console.log("✅ Deployed at: " + deployedAddress);
  return { address: deployedAddress, abi };
}

// ======== network tokens & venues (Polygon) ========
const WMATIC = "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270";
const TOKENS = [
  { symbol: "USDC", asset: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", decimals: 6 },
  { symbol: "WMATIC", asset: WMATIC, decimals: 18 },
  { symbol: "DAI", asset: "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", decimals: 18 },
  { symbol: "USDT", asset: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", decimals: 6 },
  { symbol: "WETH", asset: "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", decimals: 18 },
  { symbol: "WBTC", asset: "0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6", decimals: 8 },
  { symbol: "LINK", asset: "0x53E0bca35ec356BD5ddDFebbd1FC0fd03FaBad39", decimals: 18 },
  { symbol: "AAVE", asset: "0xD6DF932A45C0f255f85145f286eA0b292B21C90B", decimals: 18 },
  { symbol: "CRV", asset: "0x172370d5Cd63279eFa6d502DAB29171933a610AF", decimals: 18 },
  { symbol: "SUSHI", asset: "0x0b3F868E0BE5597D5DB7fEB59E1CADBb0fdDa50a", decimals: 18 },
  { symbol: "GHST", asset: "0x385Eeac5cB85A38A9a07A70c73e0a3271CfB54A7", decimals: 18 },
  { symbol: "QUICK", asset: "0x831753DD7087CaC61aB5644b308642cc1c33Dc13", decimals: 18 },
  { symbol: "BAL", asset: "0x9a71012B13CA4d3D0Cdc72A177DF3ef03b0E76A3", decimals: 18 },
  { symbol: "MAI", asset: "0xa3Fa99A148fA48D14Ed51d610c367C61876997F1", decimals: 18 }
];

const ROUTERS = [
  { name: "QuickSwapV2", address: "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff", type: "v2" },
  { name: "SushiV2", address: "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506", type: "v2" },
  { name: "1inch", address: "0x1111111254EEB25477B68fb85Ed929f73A960582", type: "1inch" },
  { name: "Paraswap", address: "0xDEF171Fe48CF0115B1d80b88Fb4041C0e2347b4F", type: "paraswap" }
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

const BALANCER_VAULT = { name: "BalancerV2", address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8", type: "balancer" };

// ======== helpers ========
function min(a, b) { return a < b ? a : b; }
function formatUnits(bi, dec) {
  try {
    return ethers.formatUnits(bi, dec);
  } catch (_) {
    return bi.toString();
  }
}
function toLower(addr) { return addr.toLowerCase(); }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function buildRouters(currentProvider) {
  return ROUTERS.map(r => ({
    name: r.name,
    address: r.address,
    type: r.type,
    contract: new ethers.Contract(
      r.address,
      r.type === "v2" ? V2_ROUTER_ABI : r.type === "1inch" ? I1INCH_ABI : [],
      currentProvider
    )
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
    contract: new ethers.Contract(BALANCER_VAULT.address, BALANCER_VAULT_ABI, currentProvider)
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
  if (path.length !== 2) return { out: 0n, poolId: "0x00" };
  const inIdx = 0;
  const outIdx = 1;
  try {
    const poolId = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const swaps = [{ poolId, assetInIndex: inIdx, assetOutIndex: outIdx, amount: amountIn, userData: "0x" }];
    const assets = [path[0], path[1]];
    const funds = {
      sender: ethers.ZeroAddress,
      fromInternalBalance: false,
      recipient: ethers.ZeroAddress,
      toInternalBalance: false
    };
    const deltas = await vault.contract.queryBatchSwap(0, swaps, assets, funds);
    const outDelta = deltas[outIdx];
    const out = typeof outDelta === "bigint" ? -outDelta : -BigInt(outDelta);
    return { out: out > 0n ? out : 0n, poolId };
  } catch (_) {
    return { out: 0n, poolId: "0x00" };
  }
}

async function quote1Inch(router, amountIn, path) {
  try {
    const pools = [1];
    const minReturn = 0;
    const returnAmount = await router.contract.swap.staticCall(
      path[0],
      path[1],
      amountIn,
      minReturn,
      pools,
      0,
      ethers.ZeroAddress,
      { value: 0 }
    );
    return BigInt(returnAmount);
  } catch (_) {
    return 0n;
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
  if (venue.type === "1inch") {
    const out = await quote1Inch(venue, amountIn, path);
    return { out, meta: {} };
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
  try {
    fs.writeFileSync(PROFIT_JSON, JSON.stringify(state));
  } catch (_) {}
}

function appendProfitCSV(ts, symbol, amountStr) {
  try {
    const headerNeeded = !fs.existsSync(PROFIT_CSV);
    if (headerNeeded) fs.writeFileSync(PROFIT_CSV, "timestamp,symbol,amount\n");
    fs.appendFileSync(PROFIT_CSV, `${ts},${symbol},${amountStr}\n`);
  } catch (_) {}
}

// ======== Flashbots MEV protection ========
async function sendWithFlashbots(tx) {
  const flashbotProvider = await FlashbotsBundleProvider.create(
    provider,
    wallet,
    FLASHBOTS_ENDPOINT
  );
  const bundle = [
    {
      transaction: tx,
      signer: wallet
    }
  ];
  const blockNumber = await provider.getBlockNumber();
  const simulation = await flashbotProvider.simulate(bundle, blockNumber + 1);
  if ("error" in simulation) {
    console.error("❌ Flashbots simulation failed:", simulation.error);
    return null;
  }
  const bundleResponse = await flashbotProvider.sendBundle(bundle, blockNumber + 1);
  return bundleResponse;
}

// ======== main loop ========
const main = async () => {
  let lastRpcSwitch = 0;
  const RPC_SWITCH_COOLDOWN = 5000;
  let providerContract;
  try {
    const deployed = await deploy(false);
    const flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
    const iface = new ethers.Interface(deployed.abi);
    providerContract = new ethers.Contract(AAVE_PROVIDER_ADDRESS, PROVIDER_ABI, provider);

    async function getPoolAddr() {
      try {
        return await providerContract.getPool();
      } catch (error) {
        console.warn("⚠️ Failed to get pool address, rotating RPC...");
        provider = await rotateRPC();
        wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
        providerContract = new ethers.Contract(AAVE_PROVIDER_ADDRESS, PROVIDER_ABI, provider);
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
        try {
          available = await underlying.balanceOf(poolAddr);
        } catch (error) {
          console.warn("⚠️ Failed to get balance:", error.message);
          continue;
        }
        if (available <= 0n) {
          continue;
        }
        const now = Date.now();
        if (now - lastRpcSwitch > RPC_SWITCH_COOLDOWN) {
          console.warn("🔁 No success this round, rotating RPC and retrying...");
          try {
            provider = await rotateRPC();
            wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
            routers = buildRouters(provider);
            curvePools = buildCurvePools(provider);
            balancer = buildBalancer(provider);
            providerContract = new ethers.Contract(AAVE_PROVIDER_ADDRESS, PROVIDER_ABI, provider);
            lastRpcSwitch = now;
            await sleep(1000);
            try {
              poolAddr = await getPoolAddr();
              premiumBps = await getPremiumBps(poolAddr);
            } catch (error) {
              console.warn("⚠️ Failed to update pool info after RPC rotation:", error.message);
              continue;
            }
          } catch (error) {
            console.error("❌ Failed to rotate RPC:", error.message);
            await sleep(5000);
            continue;
          }
        } else {
          console.warn("⏳ Waiting for RPC cooldown...");
          await sleep(2000);
        }
        const ramp = [
          "USDC",
          "USDT",
          "DAI"
        ].includes(token.symbol)
          ? ["0.01", "0.05", "0.1"]
          : ["0.1", "0.5", "1.0"];
        const maxCap = available / 10000n;
        let executed = false;
        let foundProfitable = false;
        for (const step of ramp) {
          let size = ethers.parseUnits(step, token.decimals);
          size = min(size, maxCap);
          if (size <= 0n) continue;
          const premium = (size * premiumBps) / 10000n;
          const owed = size + premium;
          const venues = routers.concat(curvePools).concat([balancer]);
          let best = { out2: 0n };
          const paths1 = generatePaths(token.asset, TARGET_ADDRESS);
          const paths2 = generatePaths(TARGET_ADDRESS, token.asset);
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
          const extra = (owed * 30n) / 10000n;
          const delta = best.out2 - owed;
          const edgeBps =
            delta > 0n
              ? (delta * 10000n) / owed
              : -((owed - best.out2) * 10000n) / owed;
          console.log(
            "🔎 " +
              token.symbol +
              " size " +
              formatUnits(size, token.decimals) +
              " via " +
              best.aName +
              " → " +
              best.bName +
              " out " +
              formatUnits(best.out2, token.decimals) +
              " owed " +
              formatUnits(owed, token.decimals) +
              " edge " +
              edgeBps.toString() +
              " bps"
          );
          if (best.out2 < owed + extra) continue;
          foundProfitable = true;
          const minOut1 = applySlippage(best.out1);
          const minOut2 = applySlippage(best.out2);
          const typeA =
            best.aType === "v2"
              ? 0
              : best.aType === "curve"
              ? 1
              : best.aType === "balancer"
              ? 2
              : 3;
          const typeB =
            best.bType === "v2"
              ? 0
              : best.bType === "curve"
              ? 1
              : best.bType === "balancer"
              ? 2
              : 3;
          const routerA = typeA === 2 ? BALANCER_VAULT.address : best.aAddr;
          const routerB = typeB === 2 ? BALANCER_VAULT.address : best.bAddr;
          const curveI1 = BigInt(best.aMeta.curveI ?? 0);
          const curveJ1 = BigInt(best.aMeta.curveJ ?? 1);
          const curveI2 = BigInt(best.bMeta.curveI ?? 0);
          const curveJ2 = BigInt(best.bMeta.curveJ ?? 1);
          const balPidA =
            best.aMeta.poolId ??
            "0x0000000000000000000000000000000000000000000000000000000000000000";
          const balPidB =
            best.bMeta.poolId ??
            "0x0000000000000000000000000000000000000000000000000000000000000000";
          try {
            console.log("💡 Attempting flash loan for " + token.symbol);
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
            const flashbotsResponse = await sendWithFlashbots(tx);
            if (!flashbotsResponse) {
              console.error("❌ Flashbots submission failed");
              continue;
            }
            console.log("✅ Flashbots bundle submitted:", flashbotsResponse.bundleHash);
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
                "💰 Profit " +
                  key +
                  ": +" +
                  formatUnits(netGain, token.decimals) +
                  " | total " +
                  formatUnits(next, token.decimals)
              );
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
        if (executed) {
          await sleep(1200);
          continue;
        }
        if (!foundProfitable) {
          cooldown.set(assetL, round + 1);
        }
      }
      try {
        poolAddr = await getPoolAddr();
      } catch (error) {
        console.error("❌ Failed to get pool address:", error.message);
        await sleep(5000);
      }
      try {
        premiumBps = await getPremiumBps(poolAddr);
      } catch (error) {
        console.error("❌ Failed to get premium bps:", error.message);
        await sleep(5000);
      }
      await sleep(1500);
    }
  } catch (error) {
    console.error("❌ Initialization failed:", error.message);
    process.exit(1);
  }
};

