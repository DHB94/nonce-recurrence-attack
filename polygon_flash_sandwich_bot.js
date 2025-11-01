"use strict";

const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const solc = require("solc");
require("dotenv").config();

const DEFAULT_WSS = "wss://polygon.llamarpc.com";
const DEFAULT_BALANCER_VAULT = process.env.BALANCER_VAULT_ADDRESS || "0xBA12222222228d8Ba445958a75a0704d566BF2C8";
const QUICKSWAP_ROUTER = (process.env.QUICKSWAP_ROUTER || "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff").toLowerCase();
const QUICKSWAP_FACTORY = (process.env.QUICKSWAP_FACTORY || "0x5757371414417b8c6caad45baef941abc7d3ab32").toLowerCase();
const RPC_URL = process.env.POLYGON_WS_URL || process.env.POLYGON_RPC_URL || DEFAULT_WSS;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

if (!PRIVATE_KEY) throw new Error("Missing PRIVATE_KEY in environment");
if (!RPC_URL || !RPC_URL.startsWith("ws")) {
  throw new Error("Pending transaction stream requires a Polygon websocket endpoint in POLYGON_WS_URL/POLYGON_RPC_URL");
}
if (!DEFAULT_BALANCER_VAULT) {
  throw new Error("BALANCER_VAULT_ADDRESS must be provided for flash-loan execution");
}

const FLASH_LOAN_AMOUNT = process.env.FLASH_LOAN_AMOUNT || "12"; // units in asset decimals
const MIN_PROFIT_AMOUNT = process.env.MIN_PROFIT_AMOUNT || "0.35";
const MIN_POOL_BASE = process.env.MIN_POOL_BASE || "15";
const BALANCER_FEE_BPS = BigInt(process.env.BALANCER_FLASH_LOAN_FEE_BPS || "9");
const SLIPPAGE_BPS = BigInt(process.env.SLIPPAGE_BPS || "35");
const MAX_BORROW_BPS = BigInt(process.env.MAX_BORROW_BPS || "4200");
const GAS_LIMIT = parseInt(process.env.GAS_LIMIT || "520000", 10);
const PRIORITY_FEE_FLOOR_GWEI = process.env.PRIORITY_FEE_FLOOR_GWEI || "60";
const PRIORITY_FEE_MULTIPLIER = Number(process.env.PRIORITY_FEE_MULTIPLIER || "2.5");
const DEPLOYMENTS_FILE = path.join(__dirname, ".polygon_sandwich_deployments.json");

if (BALANCER_FEE_BPS < 0n || BALANCER_FEE_BPS > 10_000n) {
  throw new Error("BALANCER_FLASH_LOAN_FEE_BPS must be between 0 and 10000");
}
if (SLIPPAGE_BPS < 0n || SLIPPAGE_BPS >= 10_000n) {
  throw new Error("SLIPPAGE_BPS must be between 0 and 9999");
}
if (MAX_BORROW_BPS <= 0n || MAX_BORROW_BPS >= 10_000n) {
  throw new Error("MAX_BORROW_BPS must be between 1 and 9999");
}
if (!Number.isFinite(PRIORITY_FEE_MULTIPLIER) || PRIORITY_FEE_MULTIPLIER <= 0) {
  throw new Error("PRIORITY_FEE_MULTIPLIER must be a positive number");
}
if (!Number.isFinite(GAS_LIMIT) || GAS_LIMIT <= 0) {
  throw new Error("GAS_LIMIT must be a positive integer");
}

const provider = new ethers.WebSocketProvider(RPC_URL, undefined, { timeout: 30_000 });
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

const ROUTER_ABI = [
  "function swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] calldata path,address to,uint256 deadline)"
];
const FACTORY_ABI = ["function getPair(address tokenA,address tokenB) external view returns (address)"];
const PAIR_ABI = [
  "function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)",
  "function token0() external view returns (address)",
  "function token1() external view returns (address)"
];
const ERC20_META_ABI = [
  "function decimals() external view returns (uint8)",
  "function symbol() external view returns (string)"
];

const routerInterface = new ethers.Interface([
  "function swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] calldata path,address to,uint256 deadline)",
  "function swapExactTokensForETH(uint256 amountIn,uint256 amountOutMin,address[] calldata path,address to,uint256 deadline)",
  "function swapExactETHForTokens(uint256 amountOutMin,address[] calldata path,address to,uint256 deadline) payable"
]);

const factoryContract = new ethers.Contract(QUICKSWAP_FACTORY, FACTORY_ABI, provider);

const cachedPairs = new Map();
const cachedTokenMeta = new Map();
const observedVictims = new Set();
let flashBotContract = null;
let flashContractInfo = null;

const FLASH_CONTRACT_SOURCE = `
pragma solidity ^0.8.21;

interface IERC20 {
    function approve(address spender, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 value) external returns (bool);
}

interface IUniswapV2Router02 {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external;
}

interface IBalancerFlashLoanRecipient {
    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata userData
    ) external;
}

contract PolygonSandwichFlashLoaner is IBalancerFlashLoanRecipient {
    address public immutable owner;
    address public immutable balancerVault;

    address private forwardRouter;
    address private backwardRouter;
    address[] private forwardPath;
    address[] private backwardPath;
    uint256 private forwardMinOut;
    uint256 private backwardMinOut;

    bool private inFlight;

    error NotOwner();
    error InvalidConfig();
    error RepayFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address vault) {
        if (vault == address(0)) revert InvalidConfig();
        owner = msg.sender;
        balancerVault = vault;
    }

    function initiateSandwich(
        address asset,
        uint256 amount,
        address routerA,
        address routerB,
        address[] calldata pathForward,
        address[] calldata pathBackward,
        uint256 minOutForward,
        uint256 minOutBackward
    ) external onlyOwner {
        if (inFlight || amount == 0 || routerA == address(0) || routerB == address(0)) revert InvalidConfig();
        if (pathForward.length < 2 || pathBackward.length < 2) revert InvalidConfig();
        if (pathForward[0] != asset || pathBackward[pathBackward.length - 1] != asset) revert InvalidConfig();
        if (pathForward[pathForward.length - 1] != pathBackward[0]) revert InvalidConfig();

        forwardRouter = routerA;
        backwardRouter = routerB;
        forwardPath = pathForward;
        backwardPath = pathBackward;
        forwardMinOut = minOutForward;
        backwardMinOut = minOutBackward;

        address[] memory tokens = new address[](1);
        tokens[0] = asset;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        inFlight = true;
        IBalancerVault(balancerVault).flashLoan(address(this), tokens, amounts, "");
        inFlight = false;

        _reset();
    }

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external override {
        if (msg.sender != balancerVault) revert InvalidConfig();
        if (tokens.length != 1 || amounts.length != 1 || feeAmounts.length != 1) revert InvalidConfig();
        _process(tokens[0], amounts[0], feeAmounts[0]);
    }

    function _process(address asset, uint256 amount, uint256 fee) internal {
        uint256 forwardOut = _swap(forwardRouter, forwardPath, amount, forwardMinOut);
        uint256 backwardOut = _swap(backwardRouter, backwardPath, forwardOut, backwardMinOut);
        uint256 totalOwed = amount + fee;
        if (backwardOut < totalOwed) revert RepayFailed();

        if (!IERC20(asset).transfer(balancerVault, totalOwed)) revert RepayFailed();
        uint256 profit = backwardOut - totalOwed;
        if (profit > 0) {
            if (!IERC20(asset).transfer(owner, profit)) revert RepayFailed();
        }
    }

    function _swap(
        address router,
        address[] storage path,
        uint256 amountIn,
        uint256 minOut
    ) internal returns (uint256) {
        IERC20(path[0]).approve(router, 0);
        IERC20(path[0]).approve(router, amountIn);
        uint256[] memory amounts = IUniswapV2Router02(router).swapExactTokensForTokens(
            amountIn,
            minOut,
            path,
            address(this),
            block.timestamp
        );
        return amounts[amounts.length - 1];
    }

    function _reset() internal {
        forwardRouter = address(0);
        backwardRouter = address(0);
        delete forwardPath;
        delete backwardPath;
        forwardMinOut = 0;
        backwardMinOut = 0;
        inFlight = false;
    }
}
`;

const FLASH_CONTRACT_FILENAME = "PolygonSandwichFlashLoaner.sol";
const FLASH_CONTRACT_NAME = "PolygonSandwichFlashLoaner";
let compiledContract = null;

function compileSandwichContract() {
  if (compiledContract) return compiledContract;

  const input = {
    language: "Solidity",
    sources: { [FLASH_CONTRACT_FILENAME]: { content: FLASH_CONTRACT_SOURCE } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } }
    }
  };

  let output;
  try {
    output = JSON.parse(solc.compile(JSON.stringify(input)));
  } catch (error) {
    throw new Error(`Solidity compilation failed: ${error.message}`);
  }

  if (output.errors && output.errors.length) {
    const fatal = output.errors.filter(e => e.severity === "error");
    if (fatal.length) {
      const message = fatal.map(e => e.formattedMessage || e.message).join("\n");
      throw new Error(`Solidity compilation errors:\n${message}`);
    }
    output.errors.forEach(e => console.warn(e.formattedMessage || e.message));
  }

  const contract = output.contracts?.[FLASH_CONTRACT_FILENAME]?.[FLASH_CONTRACT_NAME];
  if (!contract || !contract.abi || !contract.evm?.bytecode?.object) {
    throw new Error("Compiled contract artifact missing ABI or bytecode");
  }

  compiledContract = { abi: contract.abi, bytecode: contract.evm.bytecode.object };
  return compiledContract;
}

async function ensureFlashContract() {
  const compiled = compileSandwichContract();
  const network = await provider.getNetwork();
  const chainKey = String(network.chainId);
  const deployments = fs.existsSync(DEPLOYMENTS_FILE)
    ? JSON.parse(fs.readFileSync(DEPLOYMENTS_FILE, "utf8"))
    : {};

  const configuredAddress = process.env.FLASHBOT_CONTRACT_ADDRESS;
  if (configuredAddress) {
    const code = await provider.getCode(configuredAddress);
    if (!code || code === "0x") {
      throw new Error("FLASHBOT_CONTRACT_ADDRESS does not contain bytecode");
    }
    return { address: ethers.getAddress(configuredAddress), abi: compiled.abi };
  }

  const existing = deployments[chainKey];
  if (existing && existing.address) {
    const code = await provider.getCode(existing.address);
    if (code && code !== "0x") {
      return { address: ethers.getAddress(existing.address), abi: compiled.abi };
    }
  }

  console.info("Deploying PolygonSandwichFlashLoaner contract...");
  const factory = new ethers.ContractFactory(compiled.abi, compiled.bytecode, wallet);
  const contract = await factory.deploy(DEFAULT_BALANCER_VAULT);
  await contract.waitForDeployment();
  const deployedAddress = await contract.getAddress();
  deployments[chainKey] = {
    address: deployedAddress,
    deployedAt: new Date().toISOString()
  };
  fs.writeFileSync(DEPLOYMENTS_FILE, JSON.stringify(deployments, null, 2));
  console.info(`PolygonSandwichFlashLoaner deployed at ${deployedAddress}`);
  return { address: deployedAddress, abi: compiled.abi };
}

async function getPair(tokenA, tokenB) {
  const key = [tokenA, tokenB].sort().join(":");
  if (cachedPairs.has(key)) return cachedPairs.get(key);
  const address = (await factoryContract.getPair(tokenA, tokenB))?.toLowerCase();
  if (!address || address === ethers.ZeroAddress) return null;
  cachedPairs.set(key, address);
  return address;
}

async function getReserves(pairAddress) {
  const pair = new ethers.Contract(pairAddress, PAIR_ABI, provider);
  const [reserve0, reserve1] = await pair.getReserves();
  const token0 = (await pair.token0()).toLowerCase();
  const token1 = (await pair.token1()).toLowerCase();
  return { reserve0: BigInt(reserve0), reserve1: BigInt(reserve1), token0, token1 };
}

async function getTokenMeta(address) {
  const key = address.toLowerCase();
  if (cachedTokenMeta.has(key)) return cachedTokenMeta.get(key);
  const contract = new ethers.Contract(address, ERC20_META_ABI, provider);
  let decimals = 18;
  let symbol = address.slice(0, 6);
  try { decimals = Number(await contract.decimals()); } catch (error) { console.warn(`decimals() failed for ${address}: ${error.message}`); }
  try { symbol = await contract.symbol(); } catch (error) { console.warn(`symbol() failed for ${address}: ${error.message}`); }
  const meta = { decimals, symbol };
  cachedTokenMeta.set(key, meta);
  return meta;
}

function getAmountOut(amountIn, reserveIn, reserveOut) {
  if (amountIn <= 0n || reserveIn <= 0n || reserveOut <= 0n) return 0n;
  const amountInWithFee = amountIn * 997n;
  const numerator = amountInWithFee * reserveOut;
  const denominator = reserveIn * 1000n + amountInWithFee;
  if (denominator === 0n) return 0n;
  return numerator / denominator;
}

function parseAssetUnits(value, decimals) {
  try {
    return ethers.parseUnits(value, decimals);
  } catch (error) {
    throw new Error(`Failed to parse "${value}" with ${decimals} decimals: ${error.message}`);
  }
}

function clampBorrow(amount, reserveIn) {
  const maxBorrow = (reserveIn * MAX_BORROW_BPS) / 10_000n;
  if (maxBorrow === 0n) return 0n;
  return amount > maxBorrow ? maxBorrow : amount;
}

function generateBorrowCandidates(baseAmount, victimAmount, reserveIn) {
  const candidates = new Set();
  const push = amount => {
    const clamped = clampBorrow(amount, reserveIn);
    if (clamped > 0n) candidates.add(clamped);
  };

  push(baseAmount);
  push(baseAmount * 2n);
  push((baseAmount * 3n) / 2n);
  push(victimAmount);
  push(victimAmount * 2n);
  push(reserveIn / 5n);
  push(reserveIn / 4n);
  push(reserveIn / 6n);

  return Array.from(candidates).sort((a, b) => (a > b ? -1 : a < b ? 1 : 0));
}

function simulateOpportunity(borrowAmount, victimAmount, reserveIn, reserveOut) {
  if (borrowAmount === 0n) return null;
  const flashLoanFee = (borrowAmount * BALANCER_FEE_BPS) / 10_000n;

  const frontOut = getAmountOut(borrowAmount, reserveIn, reserveOut);
  if (frontOut === 0n) return null;

  const reserveInAfterFront = reserveIn + borrowAmount;
  const reserveOutAfterFront = reserveOut - frontOut;
  if (reserveOutAfterFront <= 0n) return null;

  const victimOut = getAmountOut(victimAmount, reserveInAfterFront, reserveOutAfterFront);
  if (victimOut === 0n) return null;

  const reserveInAfterVictim = reserveInAfterFront + victimAmount;
  const reserveOutAfterVictim = reserveOutAfterFront - victimOut;
  if (reserveOutAfterVictim <= 0n) return null;

  const backOut = getAmountOut(frontOut, reserveOutAfterVictim, reserveInAfterVictim);
  if (backOut === 0n) return null;

  const netProfit = backOut - borrowAmount - flashLoanFee;
  if (netProfit <= 0n) return null;

  const minFrontOut = (frontOut * (10_000n - SLIPPAGE_BPS)) / 10_000n;
  const minBackOut = (backOut * (10_000n - SLIPPAGE_BPS)) / 10_000n;

  return {
    borrowAmount,
    flashLoanFee,
    frontOut,
    victimOut,
    backOut,
    netProfit,
    minFrontOut,
    minBackOut
  };
}

async function evaluateSandwich(tx, parsedTx) {
  if (!parsedTx.args || parsedTx.args.length < 4) return null;
  const path = parsedTx.args.path.map(addr => addr.toLowerCase());
  if (path.length !== 2) return null; // restrict to single pair for accurate reserve math

  const [tokenIn, tokenOut] = path;
  const pairAddress = await getPair(tokenIn, tokenOut);
  if (!pairAddress) return null;

  const { reserve0, reserve1, token0, token1 } = await getReserves(pairAddress);
  const reserveIn = token0 === tokenIn ? reserve0 : reserve1;
  const reserveOut = token0 === tokenIn ? reserve1 : reserve0;
  if (reserveIn === 0n || reserveOut === 0n) return null;

  const victimIn = BigInt(parsedTx.args.amountIn.toString());
  if (victimIn === 0n) return null;

  const tokenInMeta = await getTokenMeta(tokenIn);
  const tokenOutMeta = await getTokenMeta(tokenOut);

  const minReserve = parseAssetUnits(MIN_POOL_BASE, tokenInMeta.decimals);
  if (reserveIn < minReserve) return null;

  const baseBorrow = clampBorrow(parseAssetUnits(FLASH_LOAN_AMOUNT, tokenInMeta.decimals), reserveIn);
  if (baseBorrow === 0n) return null;

  const candidates = generateBorrowCandidates(baseBorrow, victimIn, reserveIn);
  let best = null;

  for (const candidate of candidates) {
    const simulation = simulateOpportunity(candidate, victimIn, reserveIn, reserveOut);
    if (!simulation) continue;
    if (!best || simulation.netProfit > best.netProfit) {
      best = simulation;
    }
  }

  if (!best) return null;

  const minProfit = parseAssetUnits(MIN_PROFIT_AMOUNT, tokenInMeta.decimals);
  if (best.netProfit < minProfit) return null;

  const borrowShareBps = (best.borrowAmount * 10_000n) / reserveIn;

  return {
    asset: tokenIn,
    assetMeta: tokenInMeta,
    outputMeta: tokenOutMeta,
    pathForward: [tokenIn, tokenOut],
    pathBackward: [tokenOut, tokenIn],
    pairAddress,
    victimIn,
    borrowAmount: best.borrowAmount,
    frontOut: best.frontOut,
    backOut: best.backOut,
    minFrontOut: best.minFrontOut,
    minBackOut: best.minBackOut,
    netProfit: best.netProfit,
    flashLoanFee: best.flashLoanFee,
    borrowShareBps,
    tx
  };
}

async function buildAndSend(opportunity, gasOverrides) {
  if (!flashBotContract) {
    throw new Error("Flash-loan contract not initialised");
  }
  return flashBotContract.initiateSandwich(
    opportunity.asset,
    opportunity.borrowAmount,
    QUICKSWAP_ROUTER,
    QUICKSWAP_ROUTER,
    opportunity.pathForward,
    opportunity.pathBackward,
    opportunity.minFrontOut,
    opportunity.minBackOut,
    { gasLimit: GAS_LIMIT, ...gasOverrides }
  );
}

async function getFeeOverrides() {
  if (process.env.FIXED_GAS_PRICE_GWEI) {
    return { gasPrice: ethers.parseUnits(process.env.FIXED_GAS_PRICE_GWEI, 9) };
  }

  const feeData = await provider.getFeeData();
  let priority = feeData.maxPriorityFeePerGas ?? ethers.parseUnits(PRIORITY_FEE_FLOOR_GWEI, 9);
  const floor = ethers.parseUnits(PRIORITY_FEE_FLOOR_GWEI, 9);
  if (priority < floor) priority = floor;

  let maxFee = feeData.maxFeePerGas ?? priority * BigInt(Math.ceil(PRIORITY_FEE_MULTIPLIER));
  const multiplier = BigInt(Math.ceil(PRIORITY_FEE_MULTIPLIER));
  if (maxFee < priority) {
    maxFee = priority;
  }
  if (maxFee < priority * multiplier) {
    maxFee = priority * multiplier;
  }

  return { maxFeePerGas: maxFee, maxPriorityFeePerGas: priority };
}

async function logOpportunity(opportunity, gasOverrides) {
  const profit = Number(ethers.formatUnits(opportunity.netProfit, opportunity.assetMeta.decimals));
  const borrow = Number(ethers.formatUnits(opportunity.borrowAmount, opportunity.assetMeta.decimals));
  const victim = Number(ethers.formatUnits(opportunity.victimIn, opportunity.assetMeta.decimals));
  const front = Number(ethers.formatUnits(opportunity.frontOut, opportunity.outputMeta.decimals));
  const fee = Number(ethers.formatUnits(opportunity.flashLoanFee, opportunity.assetMeta.decimals));

  const gasText = gasOverrides.gasPrice
    ? `${ethers.formatUnits(gasOverrides.gasPrice, 9)} gwei`
    : `${ethers.formatUnits(gasOverrides.maxPriorityFeePerGas, 9)} gwei prio / ${ethers.formatUnits(gasOverrides.maxFeePerGas, 9)} gwei max`;

  console.info(
    `[${opportunity.assetMeta.symbol}/${opportunity.outputMeta.symbol}] victim=${victim.toFixed(6)} borrow=${borrow.toFixed(6)} frontOut=${front.toFixed(6)} ` +
      `netProfit=${profit.toFixed(6)} fee=${fee.toFixed(6)} share=${(Number(opportunity.borrowShareBps) / 100).toFixed(2)}% gas=${gasText}`
  );
}

async function handlePendingTx(txHash) {
  try {
    if (!flashBotContract) return;
    const tx = await provider.getTransaction(txHash);
    if (!tx || !tx.to || tx.to.toLowerCase() !== QUICKSWAP_ROUTER) return;
    if (!tx.data || observedVictims.has(txHash)) return;

    let parsed;
    try {
      parsed = routerInterface.parseTransaction({ data: tx.data, value: tx.value });
    } catch {
      return;
    }

    if (!parsed || parsed.name !== "swapExactTokensForTokens") return;

    const opportunity = await evaluateSandwich(tx, parsed);
    if (!opportunity) return;

    observedVictims.add(txHash);
    if (observedVictims.size > 20_000) {
      observedVictims.clear();
    }

    const feeOverrides = await getFeeOverrides();
    await logOpportunity(opportunity, feeOverrides);

    const response = await buildAndSend(opportunity, feeOverrides);
    console.info(`Submitted sandwich tx ${response.hash}`);
    await response.wait();
    console.info(`Sandwich confirmed ${response.hash}`);
  } catch (error) {
    console.error("Error processing pending transaction", error);
  }
}

async function initialiseFlashLoanContract() {
  flashContractInfo = await ensureFlashContract();
  flashBotContract = new ethers.Contract(flashContractInfo.address, flashContractInfo.abi, wallet);
  const owner = await flashBotContract.owner();
  if (owner.toLowerCase() !== wallet.address.toLowerCase()) {
    throw new Error(`Flash-loan contract owner ${owner} does not match bot wallet ${wallet.address}`);
  }
  console.info(`Using flash-loan contract ${flashContractInfo.address}`);
}

async function main() {
  console.info("Polygon sandwich bot initialising...");
  console.info(`Monitoring QuickSwap router ${QUICKSWAP_ROUTER}`);
  await initialiseFlashLoanContract();
  provider.on("pending", handlePendingTx);
  console.info("Mempool listener attached – awaiting profitable swaps.");
}

if (require.main === module) {
  main().catch(error => {
    console.error("Fatal startup error", error);
    process.exit(1);
  });
}

module.exports = {
  compileSandwichContract,
  ensureFlashContract,
  evaluateSandwich,
  getAmountOut,
  getReserves,
  getPair
};
