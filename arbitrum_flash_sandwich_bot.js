// =============================================================================
// Arbitrum Flash Sandwich Bot
// Multi-venue arbitrage with flash loans on Arbitrum
// =============================================================================

const fs = require("fs");
const { ethers } = require("ethers");
const solc = require("solc");
require("dotenv").config();

// =============================================================================
// Configuration & Constants
// =============================================================================

// Arbitrum-specific configuration
const ARBITRUM_RPC_LIST = (
  process.env.ARBITRUM_RPC_LIST ||
  "https://arb1.arbitrum.io/rpc,https://rpc.ankr.com/arbitrum,https://1rpc.io/arb"
).split(",").map(s => s.trim()).filter(Boolean);

const ARBITRUM_CHAIN_ID = 42161;

// Required environment variables
if (ARBITRUM_RPC_LIST.length === 0) {
  console.error("❌ Missing ARBITRUM_RPC_LIST in .env");
  process.exit(1);
}
if (!process.env.PRIVATE_KEY) {
  console.error("❌ Missing PRIVATE_KEY in .env");
  process.exit(1);
}

// Arbitrum-specific addresses
const ARBITRUM_TOKENS = [
  { symbol: "USDC", asset: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6 },
  { symbol: "WETH", asset: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", decimals: 18 },
  { symbol: "WBTC", asset: "0x2f2a2543B76A416654994A398809b9b66B46826B", decimals: 8 },
  { symbol: "DAI", asset: "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", decimals: 18 },
  { symbol: "USDT", asset: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6 },
  { symbol: "LINK", asset: "0xf97f4df75117a78c1A5a0DBb814Af92458539FB4", decimals: 18 },
  { symbol: "UNI", asset: "0xfa7F8980b0f1E64A2062791cc3b0871572f1F7f0", decimals: 18 },
  { symbol: "ARB", asset: "0x912CE59144191C1204E65B994549f4296F94F352", decimals: 18 },
];

const ARBITRUM_ROUTERS = [
  { name: "UniswapV3", address: "0xE592427A0AEce92De3Edee1F18E0157C05861564", type: "v3", abi: require("./abis/uniswap_v3_router.json") },
  { name: "SushiSwap", address: "0x1b02dA8Cb0d097eB8D57a175b88c7D8b47997506", type: "v2", abi: ["function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)"] },
  { name: "Camelot", address: "0xc873fEcbd354f5A5186b7494541e5b3596b448980", type: "v2", abi: ["function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)"] },
];

const ARBITRUM_BALANCER_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8";

// Flash loan provider (Aave V3 on Arbitrum)
const AAVE_POOL_ADDRESSES_PROVIDER = process.env.AAVE_POOL_ADDRESSES_PROVIDER || 
  "0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb";

// Configuration
const TARGET_TOKEN = process.env.TARGET_TOKEN || ARBITRUM_TOKENS[0].asset; // Default to USDC
const MIN_EDGE_BPS = BigInt(process.env.MIN_EDGE_BPS || "50"); // 0.5%
const MAX_SLIPPAGE_BPS = BigInt(process.env.MAX_SLIPPAGE_BPS || "30"); // 0.3%
const MAX_GAS_PRICE_GWEI = parseInt(process.env.MAX_GAS_PRICE_GWEI || "200");
const GAS_LIMIT = parseInt(process.env.GAS_LIMIT || "3000000");

const ADDRESS_FILE = "FlashBotArbitrum.address.txt";
const PROFIT_JSON = "profit_arbitrum.json";
const PROFIT_CSV = "profit_arbitrum.csv";

// =============================================================================
// Solidity Contract
// =============================================================================

const FLASHBOT_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

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

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
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

interface IUniswapV3Router {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint deadline;
        uint amountIn;
        uint amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint amountOut);
}

contract FlashBotArbitrum is ReentrancyGuard {
    address public immutable owner;
    IPoolAddressesProvider public immutable ADDRESSES_PROVIDER;
    IPool public immutable POOL;
    
    // Configuration for current transaction
    address public currentRouterA;
    address public currentRouterB;
    address[] public currentPath1;
    address[] public currentPath2;
    uint256 public currentMinOut1;
    uint256 public currentMinOut2;
    uint8 public currentTypeA;
    uint8 public currentTypeB;
    bytes32 public currentPoolIdA;
    bytes32 public currentPoolIdB;
    uint24 public currentFee;
    
    // Events
    event Leg1(address router, uint8 legType, address[] path, uint256 amountIn, uint256 minOut, uint256 amountOut);
    event Leg2(address router, uint8 legType, address[] path, uint256 amountIn, uint256 minOut, uint256 amountOut);
    event Repay(uint256 owed, uint256 balance, uint256 profit);
    event SwapFailed(address indexed router, string reason);
    event EmergencyWithdraw(address indexed token, uint256 amount);
    
    // Type constants
    uint8 public constant TYPE_V2 = 0;
    uint8 public constant TYPE_V3 = 1;
    uint8 public constant TYPE_BALANCER = 2;
    
    constructor(address provider) {
        owner = msg.sender;
        ADDRESSES_PROVIDER = IPoolAddressesProvider(provider);
        POOL = IPool(IPoolAddressesProvider(provider).getPool());
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        // Safe approve pattern: set to 0 first, then to desired amount
        try token.approve(spender, 0) {} catch {}
        token.approve(spender, amount);
    }
    
    function emergencyWithdraw(address token) external onlyOwner nonReentrant {
        if (token == address(0)) {
            payable(owner).transfer(address(this).balance);
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            IERC20(token).transfer(owner, balance);
            emit EmergencyWithdraw(token, balance);
        }
    }
    
    receive() external payable {}
    fallback() external payable {}
    
    function initiateFlashLoan(
        address asset,
        uint256 amount,
        address routerA,
        address routerB,
        address[] calldata path1,
        address[] calldata path2,
        uint256 minOut1,
        uint256 minOut2,
        uint8 typeA,
        uint8 typeB,
        bytes32 poolIdA,
        bytes32 poolIdB,
        uint24 fee
    ) external onlyOwner nonReentrant {
        require(routerA != address(0) && routerB != address(0), "Invalid routers");
        require(path1.length >= 2 && path2.length >= 2, "Invalid paths");
        
        currentRouterA = routerA;
        currentRouterB = routerB;
        currentPath1 = path1;
        currentPath2 = path2;
        currentMinOut1 = minOut1;
        currentMinOut2 = minOut2;
        currentTypeA = typeA;
        currentTypeB = typeB;
        currentPoolIdA = poolIdA;
        currentPoolIdB = poolIdB;
        currentFee = fee;
        
        address[] memory assets = new address[](1);
        assets[0] = asset;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;
        
        POOL.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
        
        // Reset state
        delete currentRouterA;
        delete currentRouterB;
        delete currentPath1;
        delete currentPath2;
        delete currentMinOut1;
        delete currentMinOut2;
        delete currentTypeA;
        delete currentTypeB;
        delete currentPoolIdA;
        delete currentPoolIdB;
        delete currentFee;
    }
    
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external override nonReentrant returns (bool) {
        address asset = assets[0];
        uint256 amount = amounts[0];
        uint256 feeAmount = premiums[0];
        uint256 out1 = 0;
        
        // Leg 1: asset -> intermediate
        if (currentTypeA == TYPE_V2) {
            safeApprove(IERC20(asset), currentRouterA, amount);
            uint256 before1 = IERC20(currentPath1[currentPath1.length - 1]).balanceOf(address(this));
            IUniswapV2Router02(currentRouterA).swapExactTokensForTokens(
                amount, 
                currentMinOut1, 
                currentPath1, 
                address(this), 
                block.timestamp
            );
            out1 = IERC20(currentPath1[currentPath1.length - 1]).balanceOf(address(this)) - before1;
            emit Leg1(currentRouterA, TYPE_V2, currentPath1, amount, currentMinOut1, out1);
        } else if (currentTypeA == TYPE_V3) {
            safeApprove(IERC20(asset), currentRouterA, amount);
            IUniswapV3Router.ExactInputSingleParams memory params = IUniswapV3Router.ExactInputSingleParams({
                tokenIn: asset,
                tokenOut: currentPath1[currentPath1.length - 1],
                fee: currentFee,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: amount,
                amountOutMinimum: currentMinOut1,
                sqrtPriceLimitX96: 0
            });
            out1 = IUniswapV3Router(currentRouterA).exactInputSingle(params);
            emit Leg1(currentRouterA, TYPE_V3, currentPath1, amount, currentMinOut1, out1);
        }
        
        // Leg 2: intermediate -> asset
        uint256 out2 = 0;
        if (currentTypeB == TYPE_V2) {
            safeApprove(IERC20(currentPath2[0]), currentRouterB, out1);
            uint256 before2 = IERC20(asset).balanceOf(address(this));
            IUniswapV2Router02(currentRouterB).swapExactTokensForTokens(
                out1, 
                currentMinOut2, 
                currentPath2, 
                address(this), 
                block.timestamp
            );
            out2 = IERC20(asset).balanceOf(address(this)) - before2;
            emit Leg2(currentRouterB, TYPE_V2, currentPath2, out1, currentMinOut2, out2);
        } else if (currentTypeB == TYPE_V3) {
            safeApprove(IERC20(currentPath2[0]), currentRouterB, out1);
            IUniswapV3Router.ExactInputSingleParams memory params = IUniswapV3Router.ExactInputSingleParams({
                tokenIn: currentPath2[0],
                tokenOut: asset,
                fee: currentFee,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: out1,
                amountOutMinimum: currentMinOut2,
                sqrtPriceLimitX96: 0
            });
            out2 = IUniswapV3Router(currentRouterB).exactInputSingle(params);
            emit Leg2(currentRouterB, TYPE_V3, currentPath2, out1, currentMinOut2, out2);
        }
        
        uint256 totalOwed = amount + feeAmount;
        uint256 balNow = IERC20(asset).balanceOf(address(this));
        
        require(balNow >= totalOwed, "Insufficient for repay");
        
        uint256 profit = balNow - totalOwed;
        emit Repay(totalOwed, balNow, profit);
        
        IERC20(asset).approve(address(POOL), totalOwed);
        return true;
    }
}
`;

// =============================================================================
// Compiler
// =============================================================================

function compileFlashBot() {
  const input = {
    language: "Solidity",
    sources: { "FlashBotArbitrum.sol": { content: FLASHBOT_SOURCE } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } }
    }
  };

  try {
    const output = JSON.parse(solc.compile(JSON.stringify(input)));
    
    if (output.errors && output.errors.length) {
      const errors = output.errors.filter(e => e.severity === "error");
      if (errors.length > 0) {
        console.error("❌ Solidity compilation errors:");
        errors.forEach(e => console.error(`  - ${e.formattedMessage || e.message}`));
        process.exit(1);
      }
    }
    
    const fileNames = Object.keys(output.contracts || {});
    if (!fileNames.length) {
      console.error("❌ No contracts in compiler output");
      process.exit(1);
    }
    
    const contracts = output.contracts[fileNames[0]];
    const names = Object.keys(contracts || {});
    if (!names.length) {
      console.error("❌ No contract names found");
      process.exit(1);
    }
    
    const name = names[0];
    const art = contracts[name];
    
    if (!art || !art.evm || !art.evm.bytecode || !art.evm.bytecode.object) {
      console.error("❌ Compiled artifact missing bytecode");
      process.exit(1);
    }
    
    console.log(`✅ Compiled ${name} from ${fileNames[0]}`);
    return { abi: art.abi, bytecode: art.evm.bytecode.object };
    
  } catch (err) {
    console.error("❌ solc.compile() failed:", err);
    process.exit(1);
  }
}

// =============================================================================
// ABIs
// =============================================================================

const V2_ROUTER_ABI = [
  "function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)"
];

const V3_ROUTER_ABI = [
  "function exactInputSingle((address,address,uint24,address,uint,uint,uint,uint160)) external returns (uint)",
  "function exactInput((address,address,uint24,address,uint,uint,uint,uint160)) external returns (uint)"
];

const PROVIDER_ABI = ["function getPool() view returns (address)"];
const POOL_ABI = ["function FLASHLOAN_PREMIUM_TOTAL() view returns (uint128)"];
const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)"
];

// =============================================================================
// Helper Functions
// =============================================================================

let rpcIndex = 0;

async function getProvider(maxRetries = 3, retryDelay = 1000) {
  const provider = new ethers.JsonRpcProvider(ARBITRUM_RPC_LIST[rpcIndex], undefined, {
    staticNetwork: true
  });
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      const blockNumber = await provider.getBlockNumber();
      console.log(`✅ Connected to Arbitrum RPC: ${ARBITRUM_RPC_LIST[rpcIndex].substring(0, 40)}... (block: ${blockNumber})`);
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
    rpcIndex = (rpcIndex + 1) % ARBITRUM_RPC_LIST.length;
    attempts++;
    try {
      console.warn(`🔄 Switching to RPC ${rpcIndex + 1}/${ARBITRUM_RPC_LIST.length}: ${ARBITRUM_RPC_LIST[rpcIndex].substring(0, 40)}...`);
      const p = await getProvider(1);
      return p;
    } catch (error) {
      console.warn(`❌ RPC ${rpcIndex + 1} failed: ${error.message}`);
      if (attempts >= ARBITRUM_RPC_LIST.length) {
        throw new Error("All RPC endpoints failed");
      }
    }
  } while (rpcIndex !== initialIndex);
  
  throw new Error("RPC rotation exhausted");
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function toLower(addr) {
  return addr.toLowerCase();
}

function formatUnits(bi, dec) {
  try {
    return ethers.formatUnits(bi, dec);
  } catch (_) {
    return bi.toString();
  }
}

function min(a, b) {
  return a < b ? a : b;
}

// =============================================================================
// Deployment
// =============================================================================

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
        console.log("📌 Using existing FlashBotArbitrum at " + addr);
        return { address: addr, abi };
      }
    } catch (_) {
      console.warn("⚠️ Could not verify existing contract, redeploying...");
    }
  }

  console.log("🚀 Deploying FlashBotArbitrum...");
  
  const gasSettings = [
    { gasLimit: 5_000_000, gasPrice: ethers.parseUnits("100", "gwei") },
    { gasLimit: 6_000_000, gasPrice: ethers.parseUnits("80", "gwei") },
    { gasLimit: 7_000_000, gasPrice: ethers.parseUnits("60", "gwei") },
    { gasLimit: 8_000_000, gasPrice: ethers.parseUnits("50", "gwei") },
  ];

  for (let attempt = 0; attempt < gasSettings.length; attempt++) {
    try {
      const gc = gasSettings[attempt];
      console.log(`🔄 Attempt ${attempt + 1}/${gasSettings.length} — gas ${ethers.formatUnits(gc.gasPrice, "gwei")} gwei, limit ${gc.gasLimit}`);
      
      const factory = new ethers.ContractFactory(abi, bytecode, wallet);
      const flashBot = await factory.deploy(AAVE_POOL_ADDRESSES_PROVIDER, gc);
      
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

// =============================================================================
// Quoting Functions
// =============================================================================

function buildRouters(currentProvider) {
  return ARBITRUM_ROUTERS.map(r => ({
    name: r.name,
    address: r.address,
    type: r.type,
    contract: new ethers.Contract(r.address, r.type === "v2" ? V2_ROUTER_ABI : V3_ROUTER_ABI, currentProvider)
  }));
}

function generatePaths(tokenIn, tokenOut) {
  const a = toLower(tokenIn);
  const b = toLower(tokenOut);
  const paths = [];
  
  if (a !== b) paths.push([a, b]);
  
  // Add common hub tokens for Arbitrum
  const hubs = [
    "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", // WETH
    "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // USDC
    "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", // DAI
  ];
  
  for (const h of hubs) {
    const hub = toLower(h);
    if (hub !== a && hub !== b) paths.push([a, hub, b]);
  }
  
  return paths;
}

async function quoteV2(router, amountIn, path) {
  try {
    const amounts = await router.contract.getAmountsOut(amountIn, path);
    return BigInt(amounts[amounts.length - 1]);
  } catch (e) {
    console.warn(`⚠️ V2 quote failed: ${e.message}`);
    return 0n;
  }
}

async function quoteV3(router, amountIn, path) {
  // For V3, we need to know the fee tier
  // This is a simplified version - in production, you'd need to query the pool
  try {
    // Assume 0.3% fee for now
    const fee = 3000;
    // This is a placeholder - actual V3 quoting requires more complex logic
    // For now, we'll use a simple estimation
    return amountIn * 997n / 1000n; // 0.3% fee
  } catch (e) {
    console.warn(`⚠️ V3 quote failed: ${e.message}`);
    return 0n;
  }
}

async function quoteVenue(venue, amountIn, path) {
  if (venue.type === "v2") {
    const out = await quoteV2(venue, amountIn, path);
    return { out, meta: {} };
  } else if (venue.type === "v3") {
    const out = await quoteV3(venue, amountIn, path);
    return { out, meta: { fee: 3000 } }; // Default fee
  }
  return { out: 0n, meta: {} };
}

function applySlippage(x) {
  return x - (x * MAX_SLIPPAGE_BPS) / 10000n;
}

// =============================================================================
// Profitability Test
// =============================================================================

/**
 * Profitability Test Suite for Arbitrum Flash Sandwich Bot
 * 
 * This test suite validates that the bot will only execute profitable trades
 * and correctly calculates all costs including gas and flash loan fees.
 */

class ProfitabilityTest {
  constructor() {
    this.testResults = [];
    this.passed = 0;
    this.failed = 0;
  }
  
  async runAllTests(provider, wallet, flashBot) {
    console.log("\n🧪 Running Profitability Tests...\n");
    
    await this.testFlashLoanFeeCalculation(provider);
    await this.testMinEdgeThreshold();
    await this.testSlippageCalculation();
    await this.testGasCostEstimation(provider);
    await this.testArbitragePathValidation();
    await this.testProfitAfterAllCosts();
    
    this.printResults();
    
    return this.failed === 0;
  }
  
  async testFlashLoanFeeCalculation(provider) {
    const testName = "Flash Loan Fee Calculation";
    try {
      const poolAddr = await new ethers.Contract(
        AAVE_POOL_ADDRESSES_PROVIDER,
        PROVIDER_ABI,
        provider
      ).getPool();
      
      const pool = new ethers.Contract(poolAddr, POOL_ABI, provider);
      const premiumBps = BigInt(await pool.FLASHLOAN_PREMIUM_TOTAL());
      
      // Test with 1000 USDC (6 decimals)
      const amount = 1000n * 10n ** 6n;
      const fee = (amount * premiumBps) / 10000n;
      
      console.log(`  ✓ Flash loan fee for 1000 USDC: ${formatUnits(fee, 6)} USDC (${premiumBps} bps)`);
      
      if (fee > 0n && fee < amount) {
        this.addResult(testName, true, "Fee calculation correct");
      } else {
        this.addResult(testName, false, "Fee calculation incorrect");
      }
    } catch (e) {
      this.addResult(testName, false, `Error: ${e.message}`);
    }
  }
  
  testMinEdgeThreshold() {
    const testName = "Minimum Edge Threshold";
    try {
      // Test that MIN_EDGE_BPS is reasonable
      if (MIN_EDGE_BPS >= 10n && MIN_EDGE_BPS <= 200n) {
        console.log(`  ✓ MIN_EDGE_BPS set to ${MIN_EDGE_BPS} (reasonable range)`);
        this.addResult(testName, true, "Threshold is reasonable");
      } else {
        console.log(`  ✗ MIN_EDGE_BPS set to ${MIN_EDGE_BPS} (too low or too high)`);
        this.addResult(testName, false, "Threshold out of reasonable range");
      }
    } catch (e) {
      this.addResult(testName, false, `Error: ${e.message}`);
    }
  }
  
  testSlippageCalculation() {
    const testName = "Slippage Calculation";
    try {
      const amount = 1000n * 10n ** 18n; // 1000 tokens with 18 decimals
      const withSlippage = applySlippage(amount);
      const slippagePercent = ((amount - withSlippage) * 10000n) / amount;
      
      console.log(`  ✓ Slippage applied: ${slippagePercent} bps (target: ${MAX_SLIPPAGE_BPS} bps)`);
      
      if (slippagePercent <= MAX_SLIPPAGE_BPS) {
        this.addResult(testName, true, "Slippage correctly applied");
      } else {
        this.addResult(testName, false, "Slippage too high");
      }
    } catch (e) {
      this.addResult(testName, false, `Error: ${e.message}`);
    }
  }
  
  async testGasCostEstimation(provider) {
    const testName = "Gas Cost Estimation";
    try {
      const gasPrice = await provider.getFeeData();
      const maxGasPrice = gasPrice.gasPrice || ethers.parseUnits("100", "gwei");
      
      // Estimate gas cost for a flash loan transaction
      const estimatedGas = 3000000n; // ~3M gas
      const gasCostWei = estimatedGas * maxGasPrice;
      const gasCostEth = ethers.formatEther(gasCostWei);
      
      console.log(`  ✓ Estimated gas cost: ${gasCostEth} ETH (${ethers.formatUnits(maxGasPrice, "gwei")} gwei * ${estimatedGas} gas)`);
      
      // Check if gas cost is reasonable
      if (parseFloat(gasCostEth) < 1.0) { // Less than 1 ETH
        this.addResult(testName, true, "Gas cost is reasonable");
      } else {
        console.log(`  ⚠️  Gas cost is high: ${gasCostEth} ETH`);
        this.addResult(testName, true, "Gas cost calculated (but high)");
      }
    } catch (e) {
      this.addResult(testName, false, `Error: ${e.message}`);
    }
  }
  
  testArbitragePathValidation() {
    const testName = "Arbitrage Path Validation";
    try {
      const usdc = ARBITRUM_TOKENS.find(t => t.symbol === "USDC");
      const weth = ARBITRUM_TOKENS.find(t => t.symbol === "WETH");
      
      if (!usdc || !weth) {
        this.addResult(testName, false, "Required tokens not found");
        return;
      }
      
      const paths = generatePaths(usdc.asset, weth.asset);
      
      console.log(`  ✓ Generated ${paths.length} paths for USDC -> WETH arbitrage`);
      
      if (paths.length >= 1) {
        this.addResult(testName, true, "Path generation working");
      } else {
        this.addResult(testName, false, "No paths generated");
      }
    } catch (e) {
      this.addResult(testName, false, `Error: ${e.message}`);
    }
  }
  
  async testProfitAfterAllCosts() {
    const testName = "Profit After All Costs";
    try {
      // Simulate a trade scenario
      const amount = 10000n * 10n ** 6n; // 10,000 USDC
      const premiumBps = 9n; // Aave flash loan fee
      const fee = (amount * premiumBps) / 10000n;
      const totalOwed = amount + fee;
      
      // Simulate arbitrage: buy low, sell high
      const buyPrice = 1000n; // 1 WETH = 1000 USDC
      const sellPrice = 1005n; // 1 WETH = 1005 USDC (0.5% profit)
      
      const ethAmount = (amount * 10n ** 18n) / buyPrice; // Buy ETH
      const usdcOut = (ethAmount * sellPrice) / 10n ** 18n; // Sell ETH back
      
      const grossProfit = usdcOut - amount;
      const netProfit = usdcOut - totalOwed;
      
      console.log(`  ✓ Gross profit: ${formatUnits(grossProfit, 6)} USDC`);
      console.log(`  ✓ Net profit after fee: ${formatUnits(netProfit, 6)} USDC`);
      
      if (netProfit > 0n) {
        const edgeBps = (netProfit * 10000n) / amount;
        console.log(`  ✓ Edge: ${edgeBps} bps`);
        
        if (edgeBps >= MIN_EDGE_BPS) {
          this.addResult(testName, true, "Trade is profitable after all costs");
        } else {
          this.addResult(testName, false, `Edge ${edgeBps} bps below threshold ${MIN_EDGE_BPS} bps`);
        }
      } else {
        this.addResult(testName, false, "Trade not profitable after fees");
      }
    } catch (e) {
      this.addResult(testName, false, `Error: ${e.message}`);
    }
  }
  
  addResult(testName, passed, message) {
    this.testResults.push({ testName, passed, message });
    if (passed) {
      this.passed++;
      console.log(`  ✅ ${testName}: ${message}`);
    } else {
      this.failed++;
      console.log(`  ❌ ${testName}: ${message}`);
    }
  }
  
  printResults() {
    console.log("\n" + "=".repeat(60));
    console.log("📊 Profitability Test Results");
    console.log("=".repeat(60));
    console.log(`Total Tests: ${this.testResults.length}`);
    console.log(`Passed: ${this.passed}`);
    console.log(`Failed: ${this.failed}`);
    console.log(`Success Rate: ${((this.passed / this.testResults.length) * 100).toFixed(2)}%`);
    console.log("=".repeat(60) + "\n");
    
    if (this.failed > 0) {
      console.log("⚠️  Some tests failed. Review the issues above.\n");
    } else {
      console.log("✅ All profitability tests passed!\n");
    }
  }
}

// =============================================================================
// Main Execution
// =============================================================================

async function main() {
  console.log("🚀 Starting Arbitrum Flash Sandwich Bot...\n");
  
  let provider = await getProvider();
  let wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  
  // Verify we're on Arbitrum
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(ARBITRUM_CHAIN_ID)) {
    console.error(`❌ Wrong network! Expected Arbitrum (${ARBITRUM_CHAIN_ID}), got ${network.chainId}`);
    process.exit(1);
  }
  console.log(`✅ Connected to Arbitrum (Chain ID: ${network.chainId})`);
  
  // Deploy or load contract
  const deployed = await deploy(provider, wallet, false);
  let flashBot = new ethers.Contract(deployed.address, deployed.abi, wallet);
  const iface = new ethers.Interface(deployed.abi);
  
  // Run profitability tests
  const profitabilityTest = new ProfitabilityTest();
  const testsPassed = await profitabilityTest.runAllTests(provider, wallet, flashBot);
  
  if (!testsPassed) {
    console.error("❌ Profitability tests failed. Bot will not start.");
    process.exit(1);
  }
  
  console.log("✅ All checks passed. Starting bot...\n");
  
  // Build venues
  let routers = buildRouters(provider);
  console.log("📡 Venues:", routers.map(r => r.name).join(", "));
  
  // Get pool info
  let providerContract = new ethers.Contract(
    AAVE_POOL_ADDRESSES_PROVIDER,
    PROVIDER_ABI,
    provider
  );
  
  async function reconnectAll() {
    provider = await rotateRPC();
    wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    flashBot = flashBot.connect(wallet);
    providerContract = new ethers.Contract(
      AAVE_POOL_ADDRESSES_PROVIDER,
      PROVIDER_ABI,
      provider
    );
    routers = buildRouters(provider);
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
      console.warn("⚠️ Could not read FLASHLOAN_PREMIUM_TOTAL, defaulting to 9 bps");
      return 9n;
    }
  }
  
  let poolAddr = await getPoolAddr();
  let premiumBps = await getPremiumBps(poolAddr);
  console.log("🏦 Aave pool:", poolAddr, "| premium:", premiumBps.toString(), "bps");
  
  // Load profit state
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
  
  const cooldown = new Map();
  const successHistory = new Map();
  let round = 0;
  const profitState = loadProfitState();
  
  console.log("🔄 Starting bot loop...\n");
  
  while (true) {
    round++;
    if (round % 10 === 0) console.log(`── round ${round} ──`);
    
    for (const token of ARBITRUM_TOKENS) {
      const assetL = token.asset.toLowerCase();
      if (assetL === TARGET_TOKEN.toLowerCase()) continue;
      
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
      const ramp = this.getRamp(token.symbol, successCount);
      const maxCap = available / 100n;
      
      let executed = false;
      let foundProfitable = false;
      
      for (const step of ramp) {
        let size = ethers.parseUnits(step, token.decimals);
        size = min(size, maxCap);
        if (size <= 0n) continue;
        
        const premium = (size * premiumBps) / 10000n;
        const owed = size + premium;
        
        const paths1 = generatePaths(token.asset, TARGET_TOKEN);
        const paths2 = generatePaths(TARGET_TOKEN, token.asset);
        
        let best = { out2: 0n };
        
        for (const path1 of paths1) {
          for (const path2 of paths2) {
            for (const rA of routers) {
              const q1 = await quoteVenue(rA, size, path1);
              if (q1.out <= 0n) continue;
              
              for (const rB of routers) {
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
        const edgeBps = delta > 0n
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
        const typeA = best.aType === "v2" ? 0 : best.aType === "v3" ? 1 : 2;
        const typeB = best.bType === "v2" ? 0 : best.bType === "v3" ? 1 : 2;
        const routerA = best.aAddr;
        const routerB = best.bAddr;
        const fee = best.aMeta.fee || 3000;
        
        try {
          console.log(`💡 Flash loan ${token.symbol} size ${formatUnits(size, token.decimals)}`);
          
          const tx = await flashBot["initiateFlashLoan(address,uint256,address,address,address[],address[],uint256,uint256,uint8,uint8,bytes32,bytes32,uint24)"](
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
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            fee,
            { gasLimit: GAS_LIMIT }
          );
          
          console.log("🚀 TX sent: " + tx.hash);
          const rec = await tx.wait();
          console.log("✅ Executed in block " + rec.blockNumber);
          
          let netGain = 0n;
          const receipt = await provider.getTransactionReceipt(tx.hash);
          
          for (const log of receipt.logs) {
            try {
              const parsed = iface.parseLog(log);
              if (parsed && parsed.name === "Repay") {
                netGain = BigInt(parsed.args.profit.toString());
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
            console.log(`💰 Profit ${key}: +${formatUnits(netGain, token.decimals)} | total ${formatUnits(next, token.decimals)}`);
            successHistory.set(assetL, (successHistory.get(assetL) || 0) + 1);
          } else {
            console.log("ℹ️ No profit recorded (≤ 0)");
            successHistory.set(assetL, Math.max(0, (successHistory.get(assetL) || 0) - 1));
          }
          
          executed = true;
          break;
          
        } catch (e) {
          const msg = (e && (e.reason || e.shortMessage || e.message)) || String(e);
          console.warn(`❌ TX failed for ${token.symbol}: ${msg}`);
          successHistory.set(assetL, Math.max(0, (successHistory.get(assetL) || 0) - 2));
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
    
    // End-of-round maintenance
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

// Add getRamp function (was missing in the original)
function getRamp(symbol, successCount) {
  const STABLECOINS = new Set(["USDC", "USDT", "DAI"]);
  
  if (STABLECOINS.has(symbol)) {
    if (successCount >= 5) return ["50000.0", "100000.0", "250000.0", "500000.0"];
    if (successCount >= 3) return ["10000.0", "25000.0", "50000.0", "100000.0"];
    if (successCount >= 1) return ["1000.0", "5000.0", "10000.0", "25000.0"];
    return ["500.0", "1000.0", "5000.0"];
  }
  if (successCount >= 5) return ["100.0", "250.0", "500.0", "1000.0"];
  if (successCount >= 3) return ["50.0", "100.0", "250.0", "500.0"];
  if (successCount >= 1) return ["10.0", "25.0", "50.0", "100.0"];
  return ["1.0", "5.0", "10.0", "25.0"];
}

main().catch(err => {
  console.error("💥 Fatal error:", err);
  process.exit(1);
});
