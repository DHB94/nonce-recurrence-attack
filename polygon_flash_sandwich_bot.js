"use strict";

/**
 * Polygon QuickSwap mempool scanner and bundle executor.
 *
 * Important: a Balancer flash loan cannot span three separate transactions.
 * The old version borrowed, swapped twice, and expected a victim transaction to
 * execute between those swaps. Everything happened in one EVM transaction, so
 * it was an atomic two-leg swap rather than a sandwich. This version uses an
 * owner-funded executor and submits [front-run, victim, back-run] as a private
 * bundle. It never sends a public sandwich transaction.
 *
 * The default mode is "scan". Set MODE=execute only after configuring an
 * executor contract, execution capital, and a relay that accepts raw
 * Polygon bundles. The relay API is intentionally kept to the standard
 * eth_sendBundle JSON-RPC method; relay-specific authentication is optional.
 */

const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const solc = require("solc");
require("dotenv").config();

const ZERO_ADDRESS = ethers.ZeroAddress;
const DEFAULT_WSS = "wss://polygon.llamarpc.com";
const DEFAULT_ROUTER = "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff";
const DEFAULT_FACTORY = "0x5757371414417b8c6caad45baef941abc7d3ab32";
const POLYGON_MAINNET_CHAIN_ID = 137n;
const DEPLOYMENTS_FILE = path.join(__dirname, ".polygon_sandwich_deployments.json");

function readEnv(name, fallback) {
  const value = process.env[name];
  return value === undefined || value === "" ? fallback : value;
}

function parseBoolean(name, fallback = false) {
  const value = String(readEnv(name, fallback ? "true" : "false")).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(value)) return true;
  if (["0", "false", "no", "n", "off"].includes(value)) return false;
  throw new Error(`${name} must be true or false`);
}

function parseBigIntEnv(name, fallback) {
  const value = readEnv(name, fallback);
  try {
    return BigInt(value);
  } catch (error) {
    throw new Error(`${name} must be an integer: ${error.message}`);
  }
}

function parsePositiveNumberEnv(name, fallback) {
  const value = Number(readEnv(name, fallback));
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number`);
  }
  return value;
}

function parsePositiveIntegerEnv(name, fallback) {
  const value = Number(readEnv(name, fallback));
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function addressFromEnv(name, fallback) {
  const value = readEnv(name, fallback);
  try {
    return ethers.getAddress(value);
  } catch (error) {
    throw new Error(`${name} is not a valid address: ${error.message}`);
  }
}

const CONFIG = Object.freeze({
  mode: String(readEnv("MODE", "scan")).trim().toLowerCase(),
  rpcUrl: readEnv("POLYGON_WS_URL", readEnv("POLYGON_RPC_URL", DEFAULT_WSS)),
  privateKey: process.env.PRIVATE_KEY,
  router: addressFromEnv("QUICKSWAP_ROUTER", DEFAULT_ROUTER),
  factory: addressFromEnv("QUICKSWAP_FACTORY", DEFAULT_FACTORY),
  tradeAmount: readEnv("TRADE_AMOUNT", readEnv("FLASH_LOAN_AMOUNT", "12")),
  minProfitAmount: readEnv("MIN_PROFIT_AMOUNT", "0.35"),
  minPoolBase: readEnv("MIN_POOL_BASE", "15"),
  estimatedGasCostAsset: readEnv("ESTIMATED_GAS_COST_ASSET", "0"),
  slippageBps: parseBigIntEnv("SLIPPAGE_BPS", "35"),
  maxTradeBps: parseBigIntEnv("MAX_TRADE_BPS", readEnv("MAX_BORROW_BPS", "4200")),
  gasLimit: parsePositiveIntegerEnv("GAS_LIMIT", "520000"),
  priorityFeeFloorGwei: readEnv("PRIORITY_FEE_FLOOR_GWEI", "60"),
  priorityFeeMultiplier: parsePositiveNumberEnv("PRIORITY_FEE_MULTIPLIER", "2.5"),
  maxCandidates: parsePositiveIntegerEnv("MAX_CANDIDATES", "32"),
  maxPendingQueue: parsePositiveIntegerEnv("MAX_PENDING_QUEUE", "256"),
  maxConcurrentEvaluations: parsePositiveIntegerEnv("MAX_CONCURRENT_EVALUATIONS", "4"),
  autoDeploy: parseBoolean("AUTO_DEPLOY", false),
  bundleRelayUrl: process.env.BUNDLE_RELAY_URL,
  bundleRelayAuth: process.env.BUNDLE_RELAY_AUTH,
  executorAddress: process.env.SANDWICH_CONTRACT_ADDRESS || process.env.FLASHBOT_CONTRACT_ADDRESS
});

if (!["scan", "paper", "execute"].includes(CONFIG.mode)) {
  throw new Error("MODE must be one of: scan, paper, execute");
}
if (!CONFIG.rpcUrl || !/^wss?:\/\//i.test(CONFIG.rpcUrl)) {
  throw new Error("Pending transaction scanning requires a websocket endpoint in POLYGON_WS_URL or POLYGON_RPC_URL");
}
if (CONFIG.slippageBps < 0n || CONFIG.slippageBps >= 10_000n) {
  throw new Error("SLIPPAGE_BPS must be between 0 and 9999");
}
if (CONFIG.maxTradeBps <= 0n || CONFIG.maxTradeBps >= 10_000n) {
  throw new Error("MAX_TRADE_BPS/MAX_BORROW_BPS must be between 1 and 9999");
}
if (CONFIG.mode === "execute" && !CONFIG.privateKey) {
  throw new Error("PRIVATE_KEY is required when MODE=execute");
}
if (CONFIG.mode === "execute" && !CONFIG.bundleRelayUrl) {
  throw new Error("BUNDLE_RELAY_URL is required when MODE=execute; public RPC submission cannot sandwich safely");
}

const ROUTER_ABI = [
  "function swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] calldata path,address to,uint256 deadline)"
];
const FACTORY_ABI = ["function getPair(address tokenA,address tokenB) external view returns (address)"];
const PAIR_ABI = [
  "function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)",
  "function token0() external view returns (address)",
  "function token1() external view returns (address)"
];
const ERC20_ABI = [
  "function allowance(address owner,address spender) external view returns (uint256)",
  "function balanceOf(address account) external view returns (uint256)",
  "function decimals() external view returns (uint8)",
  "function symbol() external view returns (string)"
];
const routerInterface = new ethers.Interface([
  "function swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] calldata path,address to,uint256 deadline)",
  "function swapExactTokensForETH(uint256 amountIn,uint256 amountOutMin,address[] calldata path,address to,uint256 deadline)",
  "function swapExactETHForTokens(uint256 amountOutMin,address[] calldata path,address to,uint256 deadline) payable"
]);
const VERSION_ABI = ["function version() external view returns (uint256)"];

/**
 * Owner-funded contract used by the bundle executor. It deliberately does
 * not use a flash loan: a flash loan is repaid before the next transaction.
 */
const EXECUTOR_SOURCE = `
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

interface IERC20 {
    function approve(address spender, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 value) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 value) external returns (bool);
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

contract PolygonSandwichExecutor {
    uint256 public constant version = 1;
    address public immutable owner;

    bool public active;
    address public activeAsset;
    uint256 public principal;
    uint256 public frontOutput;

    address private backRouter;
    address[] private backPath;
    uint256 private backMinOut;

    error NotOwner();
    error InvalidConfig();
    error TokenOperationFailed();
    error SwapFailed();
    error Unprofitable();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function startSandwich(
        address asset,
        uint256 amount,
        address router,
        address[] calldata pathForward,
        address[] calldata pathBackward,
        uint256 minOutForward,
        uint256 minOutBackward,
        uint256 deadline
    ) external onlyOwner {
        if (active || asset == address(0) || amount == 0 || router == address(0)) revert InvalidConfig();
        if (pathForward.length < 2 || pathBackward.length < 2) revert InvalidConfig();
        if (pathForward[0] != asset || pathForward[pathForward.length - 1] != pathBackward[0]) revert InvalidConfig();
        if (pathBackward[pathBackward.length - 1] != asset) revert InvalidConfig();
        if (deadline != 0 && deadline < block.timestamp) revert InvalidConfig();

        active = true;
        activeAsset = asset;
        principal = amount;
        backRouter = router;
        backMinOut = minOutBackward;
        delete backPath;
        for (uint256 i = 0; i < pathBackward.length; i++) {
            backPath.push(pathBackward[i]);
        }

        _callOptionalReturn(
            asset,
            abi.encodeWithSelector(IERC20.transferFrom.selector, owner, address(this), amount)
        );
        frontOutput = _swap(router, pathForward, amount, minOutForward, deadline);
    }

    function finishSandwich(uint256 deadline) external onlyOwner {
        if (!active || activeAsset == address(0) || principal == 0) revert InvalidConfig();
        if (deadline != 0 && deadline < block.timestamp) revert InvalidConfig();

        uint256 backOutput = _swap(backRouter, backPath, frontOutput, backMinOut, deadline);
        if (backOutput < principal) revert Unprofitable();
        _callOptionalReturn(activeAsset, abi.encodeWithSelector(IERC20.transfer.selector, owner, backOutput));
        _reset();
    }

    // Used to recover funds if a relay does not include the victim and the
    // operator wants to unwind manually. The owner is responsible for choosing
    // a safe destination token and path; this is not used by the bot itself.
    function recover(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) revert InvalidConfig();
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20.transfer.selector, owner, amount));
    }

    function _swap(
        address router,
        address[] memory path,
        uint256 amountIn,
        uint256 minOut,
        uint256 deadline
    ) internal returns (uint256) {
        if (router == address(0) || path.length < 2 || amountIn == 0) revert InvalidConfig();
        _callOptionalReturn(path[0], abi.encodeWithSelector(IERC20.approve.selector, router, 0));
        _callOptionalReturn(path[0], abi.encodeWithSelector(IERC20.approve.selector, router, amountIn));
        uint256[] memory amounts = IUniswapV2Router02(router).swapExactTokensForTokens(
            amountIn,
            minOut,
            path,
            address(this),
            deadline == 0 ? block.timestamp : deadline
        );
        if (amounts.length == 0) revert SwapFailed();
        return amounts[amounts.length - 1];
    }

    function _callOptionalReturn(address token, bytes memory data) private {
        (bool success, bytes memory returndata) = token.call(data);
        if (!success || (returndata.length != 0 && !abi.decode(returndata, (bool)))) {
            revert TokenOperationFailed();
        }
    }

    function _reset() private {
        active = false;
        activeAsset = address(0);
        principal = 0;
        frontOutput = 0;
        backRouter = address(0);
        backMinOut = 0;
        delete backPath;
    }
}
`;

const EXECUTOR_FILENAME = "PolygonSandwichExecutor.sol";
const EXECUTOR_NAME = "PolygonSandwichExecutor";
let compiledContract = null;
let runtime = null;

const cachedPairs = new Map();
const cachedTokenMeta = new Map();
const observedVictims = new Map();
const pendingQueue = [];
const queuedHashes = new Set();
let activeEvaluations = 0;
let executorContract = null;
let executorInfo = null;
let executionInFlight = false;
let nextBundleBlock = 0;

function getRuntime({ requireWallet = false } = {}) {
  if (runtime && (!requireWallet || runtime.wallet)) return runtime;
  if (!runtime) {
    const provider = new ethers.WebSocketProvider(CONFIG.rpcUrl, undefined, { timeout: 30_000 });
    const wallet = CONFIG.privateKey ? new ethers.Wallet(CONFIG.privateKey, provider) : null;
    runtime = {
      provider,
      wallet,
      factory: new ethers.Contract(CONFIG.factory, FACTORY_ABI, provider)
    };
  }
  if (requireWallet && !runtime.wallet) {
    throw new Error("PRIVATE_KEY is required for execution");
  }
  return runtime;
}

function trimObservedVictims() {
  const max = 20_000;
  while (observedVictims.size > max) {
    observedVictims.delete(observedVictims.keys().next().value);
  }
}

function compileSandwichContract() {
  if (compiledContract) return compiledContract;

  const input = {
    language: "Solidity",
    sources: { [EXECUTOR_FILENAME]: { content: EXECUTOR_SOURCE } },
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

  const errors = output.errors || [];
  const fatal = errors.filter(error => error.severity === "error");
  if (fatal.length) {
    throw new Error(`Solidity compilation errors:\n${fatal.map(error => error.formattedMessage || error.message).join("\n")}`);
  }
  errors
    .filter(error => error.severity !== "error")
    .forEach(error => console.warn(error.formattedMessage || error.message));

  const contract = output.contracts?.[EXECUTOR_FILENAME]?.[EXECUTOR_NAME];
  if (!contract || !contract.abi || !contract.evm?.bytecode?.object) {
    throw new Error("Compiled executor artifact is missing ABI or bytecode");
  }
  compiledContract = { abi: contract.abi, bytecode: contract.evm.bytecode.object };
  return compiledContract;
}

function readDeployments() {
  if (!fs.existsSync(DEPLOYMENTS_FILE)) return {};
  try {
    const value = JSON.parse(fs.readFileSync(DEPLOYMENTS_FILE, "utf8"));
    return value && typeof value === "object" ? value : {};
  } catch (error) {
    throw new Error(`Unable to parse ${DEPLOYMENTS_FILE}: ${error.message}`);
  }
}

async function isCompatibleExecutor(address, provider) {
  try {
    const code = await provider.getCode(address);
    if (!code || code === "0x") return false;
    const version = await new ethers.Contract(address, VERSION_ABI, provider).version();
    return BigInt(version) === 1n;
  } catch {
    return false;
  }
}

async function ensureExecutorContract() {
  const { provider, wallet } = getRuntime({ requireWallet: true });
  const compiled = compileSandwichContract();
  const network = await provider.getNetwork();
  if (network.chainId !== POLYGON_MAINNET_CHAIN_ID && !parseBoolean("ALLOW_NON_POLYGON", false)) {
    throw new Error(`Connected to chain ${network.chainId}; set ALLOW_NON_POLYGON=true only for an intentional non-Polygon deployment`);
  }
  const chainKey = String(network.chainId);

  const configuredAddress = CONFIG.executorAddress;
  if (configuredAddress) {
    const address = addressFromEnv("SANDWICH_CONTRACT_ADDRESS/FLASHBOT_CONTRACT_ADDRESS", configuredAddress);
    if (!(await isCompatibleExecutor(address, provider))) {
      throw new Error(`${address} is not a compatible PolygonSandwichExecutor deployment`);
    }
    return { address, abi: compiled.abi };
  }

  const deployments = readDeployments();
  const existing = deployments[chainKey];
  if (existing?.address) {
    const existingAddress = addressFromEnv("deployment address", existing.address);
    if (await isCompatibleExecutor(existingAddress, provider)) {
      return { address: existingAddress, abi: compiled.abi };
    }
  }

  if (!CONFIG.autoDeploy) {
    throw new Error(
      "No compatible executor configured. Set SANDWICH_CONTRACT_ADDRESS or AUTO_DEPLOY=true; " +
      "deployment is disabled by default."
    );
  }

  console.info("Deploying PolygonSandwichExecutor...");
  const factory = new ethers.ContractFactory(compiled.abi, compiled.bytecode, wallet);
  const contract = await factory.deploy({ gasLimit: CONFIG.gasLimit });
  await contract.waitForDeployment();
  const deployedAddress = await contract.getAddress();
  deployments[chainKey] = { address: deployedAddress, deployedAt: new Date().toISOString(), version: 1 };
  fs.writeFileSync(DEPLOYMENTS_FILE, JSON.stringify(deployments, null, 2) + "\n", { mode: 0o600 });
  console.info(`PolygonSandwichExecutor deployed at ${deployedAddress}`);
  return { address: deployedAddress, abi: compiled.abi };
}

async function getPair(tokenA, tokenB) {
  const a = ethers.getAddress(tokenA);
  const b = ethers.getAddress(tokenB);
  if (a.toLowerCase() === b.toLowerCase()) return null;
  const key = [a.toLowerCase(), b.toLowerCase()].sort().join(":");
  if (cachedPairs.has(key)) return cachedPairs.get(key);

  const promise = getRuntime().factory.getPair(a, b)
    .then(value => {
      const address = String(value).toLowerCase();
      return address === ZERO_ADDRESS.toLowerCase() ? null : address;
    })
    .catch(error => {
      cachedPairs.delete(key);
      throw error;
    });
  cachedPairs.set(key, promise);
  return promise;
}

async function getReserves(pairAddress) {
  const address = ethers.getAddress(pairAddress);
  const pair = new ethers.Contract(address, PAIR_ABI, getRuntime().provider);
  const [reserves, token0Value, token1Value] = await Promise.all([
    pair.getReserves(),
    pair.token0(),
    pair.token1()
  ]);
  return {
    reserve0: BigInt(reserves[0]),
    reserve1: BigInt(reserves[1]),
    token0: String(token0Value).toLowerCase(),
    token1: String(token1Value).toLowerCase()
  };
}

async function getTokenMeta(address) {
  const normalized = ethers.getAddress(address).toLowerCase();
  if (cachedTokenMeta.has(normalized)) return cachedTokenMeta.get(normalized);
  const token = new ethers.Contract(normalized, ERC20_ABI, getRuntime().provider);
  let decimals;
  try {
    decimals = Number(await token.decimals());
  } catch (error) {
    throw new Error(`decimals() failed for ${normalized}: ${error.message}`);
  }
  if (!Number.isSafeInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error(`Unsupported decimals value ${decimals} for ${normalized}`);
  }

  let symbol = normalized.slice(0, 8);
  try {
    const value = await token.symbol();
    if (typeof value === "string" && value.length > 0 && value.length <= 32) symbol = value;
  } catch (error) {
    console.warn(`symbol() failed for ${normalized}: ${error.message}`);
  }
  const meta = Object.freeze({ decimals, symbol });
  cachedTokenMeta.set(normalized, meta);
  return meta;
}

function getAmountOut(amountIn, reserveIn, reserveOut, feeNumerator = 997n, feeDenominator = 1000n) {
  if (amountIn <= 0n || reserveIn <= 0n || reserveOut <= 0n || feeNumerator <= 0n || feeDenominator <= 0n) return 0n;
  const amountInWithFee = amountIn * feeNumerator;
  const numerator = amountInWithFee * reserveOut;
  const denominator = reserveIn * feeDenominator + amountInWithFee;
  return denominator > 0n ? numerator / denominator : 0n;
}

function parseAssetUnits(value, decimals) {
  if (typeof value !== "string" && typeof value !== "number") {
    throw new Error(`Asset amount must be a string or number, received ${typeof value}`);
  }
  try {
    const result = ethers.parseUnits(String(value), decimals);
    if (result < 0n) throw new Error("amount cannot be negative");
    return result;
  } catch (error) {
    throw new Error(`Failed to parse ${JSON.stringify(String(value))} with ${decimals} decimals: ${error.message}`);
  }
}

function clampBorrow(amount, reserveIn) {
  if (amount <= 0n || reserveIn <= 0n) return 0n;
  const maxTrade = (reserveIn * CONFIG.maxTradeBps) / 10_000n;
  return maxTrade > 0n ? (amount > maxTrade ? maxTrade : amount) : 0n;
}

function generateBorrowCandidates(baseAmount, victimAmount, reserveIn) {
  const candidates = new Set();
  const push = amount => {
    if (amount <= 0n) return;
    const clamped = clampBorrow(amount, reserveIn);
    if (clamped > 0n) candidates.add(clamped);
  };

  push(baseAmount);
  push(baseAmount / 2n);
  push((baseAmount * 3n) / 2n);
  push(baseAmount * 2n);
  push(victimAmount / 2n);
  push(victimAmount);
  push(victimAmount * 2n);
  push(reserveIn / 10n);
  push(reserveIn / 6n);
  push(reserveIn / 5n);
  push(reserveIn / 4n);

  // A small geometric grid catches better sizes without making every pending
  // transaction expensive to evaluate.
  for (let i = 1n; i <= BigInt(CONFIG.maxCandidates); i++) {
    push((reserveIn * i) / BigInt(CONFIG.maxCandidates + 1));
  }
  return Array.from(candidates).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).slice(0, CONFIG.maxCandidates);
}

function simulateOpportunity(
  tradeAmount,
  victimAmount,
  reserveIn,
  reserveOut,
  { slippageBps = CONFIG.slippageBps, estimatedGasCostAsset = 0n } = {}
) {
  if (tradeAmount <= 0n || victimAmount <= 0n || reserveIn <= 0n || reserveOut <= 0n) return null;
  if (estimatedGasCostAsset < 0n || slippageBps < 0n || slippageBps >= 10_000n) return null;

  const frontOut = getAmountOut(tradeAmount, reserveIn, reserveOut);
  if (frontOut <= 0n || frontOut >= reserveOut) return null;

  const reserveInAfterFront = reserveIn + tradeAmount;
  const reserveOutAfterFront = reserveOut - frontOut;
  const victimOut = getAmountOut(victimAmount, reserveInAfterFront, reserveOutAfterFront);
  if (victimOut <= 0n || victimOut >= reserveOutAfterFront) return null;

  const reserveInAfterVictim = reserveInAfterFront + victimAmount;
  const reserveOutAfterVictim = reserveOutAfterFront - victimOut;
  const backOut = getAmountOut(frontOut, reserveOutAfterVictim, reserveInAfterVictim);
  if (backOut <= 0n) return null;

  const grossProfit = backOut > tradeAmount ? backOut - tradeAmount : 0n;
  const totalCosts = estimatedGasCostAsset;
  const netProfit = grossProfit > totalCosts ? grossProfit - totalCosts : 0n;
  if (netProfit <= 0n) return null;

  const minFrontOut = (frontOut * (10_000n - slippageBps)) / 10_000n;
  // Never allow the back-run to complete below principal plus the configured
  // gas reserve. Otherwise a "profitable" simulation could lose money.
  const slippageBackOut = (backOut * (10_000n - slippageBps)) / 10_000n;
  const protectedBackOut = tradeAmount + estimatedGasCostAsset;
  const minBackOut = slippageBackOut > protectedBackOut ? slippageBackOut : protectedBackOut;
  if (minBackOut > backOut) return null;

  return {
    tradeAmount,
    borrowAmount: tradeAmount, // backwards-compatible field name for callers
    victimAmount,
    frontOut,
    victimOut,
    backOut,
    grossProfit,
    estimatedGasCostAsset,
    totalCosts,
    netProfit,
    minFrontOut,
    minBackOut
  };
}

async function latestBlockTimestamp(provider) {
  try {
    const block = await provider.getBlock("latest");
    return block?.timestamp ?? Math.floor(Date.now() / 1000);
  } catch {
    return Math.floor(Date.now() / 1000);
  }
}

async function evaluateSandwich(tx, parsedTx) {
  if (!tx || !parsedTx?.args || parsedTx.name !== "swapExactTokensForTokens") return null;
  if (!tx.to || tx.to.toLowerCase() !== CONFIG.router.toLowerCase()) return null;
  if (tx.value !== undefined && tx.value !== null && BigInt(tx.value) !== 0n) return null;

  const args = parsedTx.args;
  if (args.length < 5) return null;
  const path = Array.from(args[2], address => String(address).toLowerCase());
  if (path.length !== 2 || path[0] === path[1]) return null;
  const [tokenIn, tokenOut] = path;

  const deadline = BigInt(args[4]);
  if (deadline !== 0n && deadline < BigInt(await latestBlockTimestamp(getRuntime().provider))) return null;
  const victimIn = BigInt(args[0]);
  const victimMinOut = BigInt(args[1]);
  if (victimIn <= 0n) return null;

  const pairAddress = await getPair(tokenIn, tokenOut);
  if (!pairAddress) return null;
  const { reserve0, reserve1, token0, token1 } = await getReserves(pairAddress);
  if (tokenIn !== token0 && tokenIn !== token1) return null;
  const reserveIn = token0 === tokenIn ? reserve0 : reserve1;
  const reserveOut = token0 === tokenIn ? reserve1 : reserve0;
  if (reserveIn <= 0n || reserveOut <= 0n) return null;

  const [tokenInMeta, tokenOutMeta] = await Promise.all([getTokenMeta(tokenIn), getTokenMeta(tokenOut)]);
  if (reserveIn < parseAssetUnits(CONFIG.minPoolBase, tokenInMeta.decimals)) return null;

  const baseTrade = clampBorrow(parseAssetUnits(CONFIG.tradeAmount, tokenInMeta.decimals), reserveIn);
  if (baseTrade <= 0n) return null;
  const estimatedGasCostAsset = parseAssetUnits(CONFIG.estimatedGasCostAsset, tokenInMeta.decimals);
  const candidates = generateBorrowCandidates(baseTrade, victimIn, reserveIn);

  let best = null;
  for (const candidate of candidates) {
    const simulation = simulateOpportunity(candidate, victimIn, reserveIn, reserveOut, {
      estimatedGasCostAsset,
      slippageBps: CONFIG.slippageBps
    });
    if (!simulation || simulation.victimOut < victimMinOut) continue;
    if (!best || simulation.netProfit > best.netProfit) best = simulation;
  }
  if (!best) return null;

  const minProfit = parseAssetUnits(CONFIG.minProfitAmount, tokenInMeta.decimals);
  if (best.netProfit < minProfit) return null;

  return {
    asset: tokenIn,
    assetMeta: tokenInMeta,
    outputAsset: tokenOut,
    outputMeta: tokenOutMeta,
    pathForward: [tokenIn, tokenOut],
    pathBackward: [tokenOut, tokenIn],
    pairAddress,
    victimIn,
    victimMinOut,
    victimDeadline: deadline,
    tradeAmount: best.tradeAmount,
    borrowAmount: best.tradeAmount,
    frontOut: best.frontOut,
    victimOut: best.victimOut,
    backOut: best.backOut,
    minFrontOut: best.minFrontOut,
    minBackOut: best.minBackOut,
    grossProfit: best.grossProfit,
    estimatedGasCostAsset: best.estimatedGasCostAsset,
    netProfit: best.netProfit,
    borrowShareBps: (best.tradeAmount * 10_000n) / reserveIn,
    tx,
    pairReserves: { reserveIn, reserveOut }
  };
}

function multiplyCeiling(value, multiplier) {
  const scale = 1_000_000n;
  const scaled = BigInt(Math.ceil(multiplier * Number(scale)));
  return (value * scaled + scale - 1n) / scale;
}

async function getFeeOverrides() {
  const { provider } = getRuntime();
  if (process.env.FIXED_GAS_PRICE_GWEI) {
    const gasPrice = ethers.parseUnits(process.env.FIXED_GAS_PRICE_GWEI, 9);
    if (gasPrice <= 0n) throw new Error("FIXED_GAS_PRICE_GWEI must be positive");
    return { gasPrice };
  }

  const feeData = await provider.getFeeData();
  const floor = ethers.parseUnits(CONFIG.priorityFeeFloorGwei, 9);
  const observedPriority = feeData.maxPriorityFeePerGas ?? feeData.gasPrice ?? floor;
  const priority = observedPriority > floor
    ? multiplyCeiling(observedPriority, CONFIG.priorityFeeMultiplier)
    : floor;
  const base = feeData.lastBaseFeePerGas;

  if (base === null || base === undefined) {
    const gasPrice = feeData.gasPrice && feeData.gasPrice > priority ? feeData.gasPrice : priority;
    return { gasPrice };
  }
  return {
    maxFeePerGas: base * 2n + priority,
    maxPriorityFeePerGas: priority
  };
}

function formatAmount(amount, decimals) {
  return ethers.formatUnits(amount, decimals);
}

function logOpportunity(opportunity, gasOverrides, prefix = "Opportunity") {
  const gasText = gasOverrides
    ? gasOverrides.gasPrice
      ? `${ethers.formatUnits(gasOverrides.gasPrice, 9)} gwei`
      : `${ethers.formatUnits(gasOverrides.maxPriorityFeePerGas, 9)} gwei prio / ${ethers.formatUnits(gasOverrides.maxFeePerGas, 9)} gwei max`
    : "not priced";
  console.info(
    `${prefix} [${opportunity.assetMeta.symbol}/${opportunity.outputMeta.symbol}] ` +
      `victim=${formatAmount(opportunity.victimIn, opportunity.assetMeta.decimals)} ` +
      `trade=${formatAmount(opportunity.tradeAmount, opportunity.assetMeta.decimals)} ` +
      `frontOut=${formatAmount(opportunity.frontOut, opportunity.outputMeta.decimals)} ` +
      `gross=${formatAmount(opportunity.grossProfit, opportunity.assetMeta.decimals)} ` +
      `gasReserve=${formatAmount(opportunity.estimatedGasCostAsset, opportunity.assetMeta.decimals)} ` +
      `net=${formatAmount(opportunity.netProfit, opportunity.assetMeta.decimals)} ` +
      `share=${(Number(opportunity.borrowShareBps) / 100).toFixed(2)}% gas=${gasText}`
  );
}

function serializeVictimTransaction(tx) {
  if (tx.serialized && tx.serialized !== "0x") return tx.serialized;
  if (!tx.signature) throw new Error("Pending victim transaction has no signature");
  const txLike = {
    type: tx.type ?? 0,
    to: tx.to,
    nonce: tx.nonce,
    gasLimit: tx.gasLimit,
    gasPrice: tx.gasPrice ?? undefined,
    maxFeePerGas: tx.maxFeePerGas ?? undefined,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas ?? undefined,
    value: tx.value ?? 0n,
    data: tx.data ?? "0x",
    chainId: tx.chainId,
    accessList: tx.accessList ?? undefined,
    blobVersionedHashes: tx.blobVersionedHashes ?? undefined,
    signature: tx.signature
  };
  return ethers.Transaction.from(txLike).serialized;
}

async function assertExecutionFunding(opportunity) {
  const { provider, wallet } = getRuntime({ requireWallet: true });
  if (!executorContract) throw new Error("Executor contract not initialised");
  const token = new ethers.Contract(opportunity.asset, ERC20_ABI, provider);
  const [balance, allowance] = await Promise.all([
    token.balanceOf(wallet.address),
    token.allowance(wallet.address, executorInfo.address)
  ]);
  if (BigInt(balance) < opportunity.tradeAmount) {
    throw new Error(`Insufficient ${opportunity.assetMeta.symbol} balance for bundle trade`);
  }
  if (BigInt(allowance) < opportunity.tradeAmount) {
    throw new Error(
      `Insufficient ${opportunity.assetMeta.symbol} allowance. Approve ${executorInfo.address} before enabling execution.`
    );
  }
}

async function sendBundle(rawTransactions, targetBlock) {
  if (!CONFIG.bundleRelayUrl) throw new Error("BUNDLE_RELAY_URL is not configured");
  const headers = { "content-type": "application/json" };
  if (CONFIG.bundleRelayAuth) headers.authorization = CONFIG.bundleRelayAuth;
  const body = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: "eth_sendBundle",
    params: [{ txs: rawTransactions, blockNumber: ethers.toBeHex(targetBlock) }]
  };
  const response = await fetch(CONFIG.bundleRelayUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let result;
  try {
    result = JSON.parse(text);
  } catch {
    throw new Error(`Bundle relay returned non-JSON HTTP ${response.status}: ${text.slice(0, 300)}`);
  }
  if (!response.ok || result.error) {
    throw new Error(`Bundle relay rejected request: ${JSON.stringify(result.error || result)}`);
  }
  return result.result;
}

async function buildAndSend(opportunity, gasOverrides) {
  if (!executorContract || !executorInfo) throw new Error("Executor contract not initialised");
  await assertExecutionFunding(opportunity);
  const { provider, wallet } = getRuntime({ requireWallet: true });
  const latestBlock = await provider.getBlockNumber();
  const network = await provider.getNetwork();
  const latestNonce = await provider.getTransactionCount(wallet.address, "latest");
  const pendingNonce = await wallet.getNonce("pending");
  if (pendingNonce !== latestNonce) {
    throw new Error("Executor wallet has pending transactions; refusing to create a bundle with a nonce gap");
  }
  const nonce = latestNonce;
  const now = BigInt(Math.floor(Date.now() / 1000));
  const defaultDeadline = now + 60n;
  let deadline = Number(defaultDeadline);
  if (opportunity.victimDeadline > 0n && opportunity.victimDeadline < defaultDeadline) {
    if (opportunity.victimDeadline <= now) throw new Error("Victim deadline expired while building bundle");
    deadline = Number(opportunity.victimDeadline);
  }

  const start = await executorContract.startSandwich.populateTransaction(
    opportunity.asset,
    opportunity.tradeAmount,
    CONFIG.router,
    opportunity.pathForward,
    opportunity.pathBackward,
    opportunity.minFrontOut,
    opportunity.minBackOut,
    deadline
  );
  const finish = await executorContract.finishSandwich.populateTransaction(deadline);
  const feeFields = { ...gasOverrides };
  const startUnsigned = await wallet.populateTransaction({
    ...start,
    ...feeFields,
    chainId: network.chainId,
    nonce,
    gasLimit: CONFIG.gasLimit
  });
  const finishUnsigned = await wallet.populateTransaction({
    ...finish,
    ...feeFields,
    chainId: network.chainId,
    nonce: nonce + 1,
    gasLimit: CONFIG.gasLimit
  });
  const [startRaw, victimRaw, finishRaw] = await Promise.all([
    wallet.signTransaction(startUnsigned),
    Promise.resolve(serializeVictimTransaction(opportunity.tx)),
    wallet.signTransaction(finishUnsigned)
  ]);
  const bundleId = await sendBundle([startRaw, victimRaw, finishRaw], latestBlock + 1);
  return { bundleId, targetBlock: latestBlock + 1, startRaw, finishRaw };
}

async function processPendingTx(txHash) {
  if (observedVictims.has(txHash)) return;
  observedVictims.set(txHash, Date.now());
  trimObservedVictims();

  const { provider, wallet } = getRuntime();
  const tx = await provider.getTransaction(txHash);
  if (!tx || !tx.to || tx.to.toLowerCase() !== CONFIG.router.toLowerCase()) return;
  if (wallet && tx.from && tx.from.toLowerCase() === wallet.address.toLowerCase()) return;

  let parsed;
  try {
    parsed = routerInterface.parseTransaction({ data: tx.data, value: tx.value });
  } catch {
    return;
  }
  if (!parsed || parsed.name !== "swapExactTokensForTokens") return;

  const opportunity = await evaluateSandwich(tx, parsed);
  if (!opportunity) return;
  if (CONFIG.mode !== "execute") {
    logOpportunity(opportunity, null, "Scan candidate");
    return;
  }
  if (executionInFlight) return;
  const head = await provider.getBlockNumber();
  if (head + 1 <= nextBundleBlock) return;

  executionInFlight = true;
  try {
    const gasOverrides = await getFeeOverrides();
    logOpportunity(opportunity, gasOverrides, "Bundle candidate");
    const response = await buildAndSend(opportunity, gasOverrides);
    nextBundleBlock = response.targetBlock;
    console.info(`Submitted private bundle ${response.bundleId || "(relay accepted)"} for block ${response.targetBlock}`);
  } finally {
    executionInFlight = false;
  }
}

async function drainPendingQueue() {
  while (activeEvaluations < CONFIG.maxConcurrentEvaluations && pendingQueue.length > 0) {
    const txHash = pendingQueue.shift();
    queuedHashes.delete(txHash);
    activeEvaluations += 1;
    processPendingTx(txHash)
      .catch(error => console.error(`Error processing pending transaction ${txHash}:`, error.message))
      .finally(() => {
        activeEvaluations -= 1;
        void drainPendingQueue();
      });
  }
}

function handlePendingTx(txHash) {
  if (typeof txHash !== "string" || queuedHashes.has(txHash) || observedVictims.has(txHash)) return;
  if (pendingQueue.length >= CONFIG.maxPendingQueue) pendingQueue.shift();
  queuedHashes.add(txHash);
  pendingQueue.push(txHash);
  void drainPendingQueue();
}

async function initialiseExecutorContract() {
  executorInfo = await ensureExecutorContract();
  executorContract = new ethers.Contract(executorInfo.address, executorInfo.abi, getRuntime({ requireWallet: true }).wallet);
  const owner = await executorContract.owner();
  const walletAddress = getRuntime({ requireWallet: true }).wallet.address;
  if (owner.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error(`Executor owner ${owner} does not match bot wallet ${walletAddress}`);
  }
  console.info(`Using PolygonSandwichExecutor ${executorInfo.address}`);
}

async function main() {
  const { provider } = getRuntime({ requireWallet: CONFIG.mode === "execute" });
  const network = await provider.getNetwork();
  if (network.chainId !== POLYGON_MAINNET_CHAIN_ID) {
    console.warn(`Connected to chain ${network.chainId}; this process is intended for Polygon mainnet (137).`);
  }
  if (CONFIG.mode === "execute") await initialiseExecutorContract();
  console.info(`${CONFIG.mode === "execute" ? "Bundle executor" : "Mempool scanner"} monitoring QuickSwap router ${CONFIG.router}`);
  provider.on("error", error => console.error("WebSocket provider error:", error.message));
  provider.on("pending", handlePendingTx);
  console.info("Pending transaction listener attached.");
}

if (require.main === module) {
  main().catch(error => {
    console.error("Fatal startup error:", error);
    process.exitCode = 1;
  });
}

module.exports = {
  CONFIG,
  compileSandwichContract,
  ensureExecutorContract,
  ensureFlashContract: ensureExecutorContract,
  evaluateSandwich,
  getAmountOut,
  parseAssetUnits,
  clampBorrow,
  generateBorrowCandidates,
  simulateOpportunity,
  serializeVictimTransaction,
  getReserves,
  getPair,
  getFeeOverrides,
  handlePendingTx
};
