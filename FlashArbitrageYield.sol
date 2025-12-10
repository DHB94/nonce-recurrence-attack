// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "@aave/core-v3/contracts/flashloan/interfaces/IFlashLoanSimpleReceiver.sol";
import "@aave/core-v3/contracts/interfaces/IPoolAddressesProvider.sol";
import "@aave/core-v3/contracts/interfaces/IPool.sol";

/// @notice Flash arbitrage, depeg trading and yield farming executor for Polygon (Aave v3)
contract FlashArbitrageYield is Ownable, Pausable, ReentrancyGuard, IFlashLoanSimpleReceiver {
    using SafeERC20 for IERC20;

    struct SwapStep {
        address router;        // Router that should execute the swap
        address tokenIn;       // token to spend
        address tokenOut;      // token to receive
        uint256 amountIn;      // amount to spend (0 = use contract balance)
        uint256 minAmountOut;  // minimum expected amount out to guard against slippage
        uint24 fee;            // fee tier for Uniswap V3 swaps (ignored for V2 routers)
        bool useUniV3;         // indicates if router is a Uniswap V3 style router
    }

    struct FlashLoanParams {
        SwapStep[] steps;      // steps to execute in order
        uint256 minProfit;     // minimum USD denominated profit required (18 decimals)
        uint256 deadline;      // unix timestamp deadline to execute the plan
        bool depositRemainderToAave; // optionally deposit leftover profits into Aave to earn yield
        address depositToken;  // token to deposit into Aave when depositRemainderToAave is true
    }

    struct FarmingPosition {
        uint256 supplied;  // total principal supplied to Aave
        uint256 timestamp; // last interaction timestamp
    }

    /// @notice Minimal Uniswap V3 router interface (SwapRouter02 compatible)
    interface IUniswapV3Router {
        struct ExactInputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }

        function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
    }

    /// @notice Generic Uniswap V2 style router interface
    interface IV2Router {
        function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts);

        function swapExactTokensForTokens(
            uint256 amountIn,
            uint256 amountOutMin,
            address[] calldata path,
            address to,
            uint256 deadline
        ) external returns (uint256[] memory amounts);
    }

    // Polygon mainnet production router addresses
    address public constant QUICKSWAP_ROUTER = 0xa5E0829CaCEd8fFDD4De3c43696c57f7D7A678ff;
    address public constant UNISWAP_V3_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    address public constant SUSHISWAP_ROUTER = 0x1b02dA8Cb0d097eB8D57A175B88c7D8b47997506;

    // Polygon blue-chip token addresses
    address public constant WETH = 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619;
    address public constant WBTC = 0x1BFD67037B42Cf73acf2047067bd4F2C47D9BfD6;
    address public constant USDC = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address public constant DAI = 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063;

    // Chainlink price feeds (USD denominated)
    address private constant FEED_WETH_USD = 0xF9680D99D6C9589E2A93a78A04D88F6b3eC1C3A0;
    address private constant FEED_WBTC_USD = 0xc907E116054Ad103354f2D350FD2514433D57F6f;
    address private constant FEED_DAI_USD = 0x4746DE7C27bD0A1d0C6b3f96f38C61C30bE95825;
    address private constant FEED_USDC_USD = 0xf9d5AAC6E5572AEFa6bd64108ff86a222F69B64d;

    uint256 public constant MAX_BPS = 10_000;

    IPoolAddressesProvider public immutable addressesProvider;
    IPool public immutable aavePool;

    uint256 public maxPriceDeviationBps = 150; // 1.5% default deviation tolerance
    uint256 public lastExecutionBlock;         // simple same-block MEV protection

    mapping(address => AggregatorV3Interface) public priceFeeds;
    mapping(address => bool) public keepers;
    mapping(address => FarmingPosition) public farmingPositions;

    event KeeperSet(address indexed keeper, bool allowed);
    event PriceFeedUpdated(address indexed token, address indexed feed);
    event ArbitrageExecuted(address indexed baseAsset, uint256 profitAssetAmount, uint256 profitUsdValue);
    event YieldFarmed(address indexed token, uint256 amountSupplied, uint256 totalPrincipal);
    event YieldWithdrawn(address indexed token, uint256 amountWithdrawn, uint256 principalRemaining);
    event DepegArbitrage(address indexed peggedToken, address indexed collateralToken, uint256 profitAmount, uint256 profitUsdValue);
    event MaxPriceDeviationUpdated(uint256 bps);

    modifier onlyKeeper() {
        require(msg.sender == owner() || keepers[msg.sender], "FlashArb: unauthorized");
        _;
    }

    modifier mevGuard() {
        require(block.number > lastExecutionBlock, "FlashArb: MEV blocked");
        lastExecutionBlock = block.number;
        _;
    }

    constructor(IPoolAddressesProvider provider) {
        require(address(provider) != address(0), "FlashArb: invalid provider");
        addressesProvider = provider;
        aavePool = IPool(provider.getPool());

        priceFeeds[WETH] = AggregatorV3Interface(FEED_WETH_USD);
        priceFeeds[WBTC] = AggregatorV3Interface(FEED_WBTC_USD);
        priceFeeds[DAI] = AggregatorV3Interface(FEED_DAI_USD);
        priceFeeds[USDC] = AggregatorV3Interface(FEED_USDC_USD);

        emit PriceFeedUpdated(WETH, FEED_WETH_USD);
        emit PriceFeedUpdated(WBTC, FEED_WBTC_USD);
        emit PriceFeedUpdated(DAI, FEED_DAI_USD);
        emit PriceFeedUpdated(USDC, FEED_USDC_USD);
    }

    // ================== Flash Loan Entry Point ==================

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address, /*initiator*/
        bytes calldata params
    ) external override nonReentrant mevGuard whenNotPaused returns (bool) {
        require(msg.sender == address(aavePool), "FlashArb: invalid caller");

        FlashLoanParams memory decoded = _decodeParams(params);
        require(block.timestamp <= decoded.deadline, "FlashArb: expired");
        require(decoded.steps.length > 0, "FlashArb: no steps");
        require(decoded.steps[0].tokenIn == asset, "FlashArb: path mismatch");
        require(decoded.steps[decoded.steps.length - 1].tokenOut == asset, "FlashArb: terminal mismatch");

        uint256 startingBalance = IERC20(asset).balanceOf(address(this));

        _executeSwapSequence(amount, decoded.steps, decoded.deadline);

        uint256 totalDebt = amount + premium;
        uint256 balanceAfter = IERC20(asset).balanceOf(address(this));
        require(balanceAfter >= startingBalance + premium, "FlashArb: insufficient funds");

        uint256 profit = balanceAfter - startingBalance - premium;
        _approveIfNeeded(asset, address(aavePool), totalDebt);

        uint256 profitUsd = _toUsdValue(asset, profit);
        require(profitUsd >= decoded.minProfit, "FlashArb: min profit");

        emit ArbitrageExecuted(asset, profit, profitUsd);

        if (decoded.depositRemainderToAave && decoded.depositToken != address(0)) {
            uint256 balance = IERC20(decoded.depositToken).balanceOf(address(this));
            if (decoded.depositToken == asset) {
                if (balance > totalDebt) {
                    _depositToAave(decoded.depositToken, balance - totalDebt);
                }
            } else if (balance > 0) {
                _depositToAave(decoded.depositToken, balance);
            }
        }

        return true;
    }

    function POOL() external view override returns (IPool) {
        return aavePool;
    }

    function ADDRESSES_PROVIDER() external view override returns (IPoolAddressesProvider) {
        return addressesProvider;
    }

    // ================== Arbitrage Helpers ==================

    function _executeSwapSequence(
        uint256 amountIn,
        SwapStep[] memory steps,
        uint256 deadline
    ) internal returns (uint256) {
        require(steps.length > 0, "FlashArb: empty sequence");

        uint256 currentAmount = amountIn;
        address currentToken = steps[0].tokenIn;

        if (currentToken != address(0)) {
            _approveIfNeeded(currentToken, steps[0].router, amountIn);
        }

        for (uint256 i = 0; i < steps.length; i++) {
            SwapStep memory step = steps[i];
            if (step.amountIn > 0) {
                currentAmount = step.amountIn;
            }
            address tokenIn = step.tokenIn;
            if (tokenIn == address(0)) {
                tokenIn = currentToken;
            }
            require(tokenIn != address(0) && step.tokenOut != address(0), "FlashArb: invalid tokens");

            currentAmount = _executeSwap(step, currentAmount, tokenIn, deadline);
            currentToken = step.tokenOut;
        }

        return IERC20(currentToken).balanceOf(address(this));
    }

    function _executeSwap(
        SwapStep memory step,
        uint256 amountIn,
        address tokenIn,
        uint256 deadline
    ) internal returns (uint256 amountOut) {
        require(step.router != address(0), "FlashArb: invalid router");
        require(amountIn > 0, "FlashArb: zero amount");

        if (step.useUniV3) {
            _approveIfNeeded(tokenIn, step.router, amountIn);
            amountOut = IUniswapV3Router(step.router).exactInputSingle(
                IUniswapV3Router.ExactInputSingleParams({
                    tokenIn: tokenIn,
                    tokenOut: step.tokenOut,
                    fee: step.fee,
                    recipient: address(this),
                    deadline: deadline,
                    amountIn: amountIn,
                    amountOutMinimum: step.minAmountOut,
                    sqrtPriceLimitX96: 0
                })
            );
        } else {
            address[] memory path = new address[](2);
            path[0] = tokenIn;
            path[1] = step.tokenOut;
            _approveIfNeeded(tokenIn, step.router, amountIn);
            uint256[] memory amounts = IV2Router(step.router).swapExactTokensForTokens(
                amountIn,
                step.minAmountOut,
                path,
                address(this),
                deadline
            );
            amountOut = amounts[amounts.length - 1];
        }

        _validatePriceInvariant(tokenIn, step.tokenOut, amountIn, amountOut);
    }

    // ================== Yield Farming (Aave supply / withdraw) ==================

    function supplyToAave(address token, uint256 amount) external onlyKeeper whenNotPaused nonReentrant mevGuard {
        _depositToAave(token, amount);
    }

    function withdrawFromAave(address token, uint256 amount) external onlyKeeper whenNotPaused nonReentrant mevGuard {
        require(amount > 0, "FlashArb: zero amount");
        uint256 withdrawn = aavePool.withdraw(token, amount, address(this));
        require(withdrawn >= amount, "FlashArb: withdraw shortfall");

        FarmingPosition storage position = farmingPositions[token];
        if (position.supplied > withdrawn) {
            position.supplied -= withdrawn;
        } else {
            position.supplied = 0;
        }
        position.timestamp = block.timestamp;

        emit YieldWithdrawn(token, withdrawn, position.supplied);
    }

    function _depositToAave(address token, uint256 amount) internal whenNotPaused {
        require(amount > 0, "FlashArb: zero amount");
        _approveIfNeeded(token, address(aavePool), amount);
        aavePool.supply(token, amount, address(this), 0);

        FarmingPosition storage position = farmingPositions[token];
        position.supplied += amount;
        position.timestamp = block.timestamp;

        emit YieldFarmed(token, amount, position.supplied);
    }

    // ================== Depeg Arbitrage ==================

    function executeDepegArbitrage(
        address peggedToken,
        address collateralToken,
        uint256 amount,
        address routerToCollateral,
        address routerToPegged,
        uint256 minCollateralOut,
        uint256 minPeggedOut,
        uint256 deadline
    ) external onlyKeeper nonReentrant mevGuard whenNotPaused returns (uint256 profit, uint256 profitUsd) {
        require(peggedToken != collateralToken, "FlashArb: identical tokens");
        require(amount > 0, "FlashArb: zero amount");

        _approveIfNeeded(peggedToken, routerToCollateral, amount);
        address[] memory pathForward = new address[](2);
        pathForward[0] = peggedToken;
        pathForward[1] = collateralToken;

        uint256[] memory forwardResult = IV2Router(routerToCollateral).swapExactTokensForTokens(
            amount,
            minCollateralOut,
            pathForward,
            address(this),
            deadline
        );

        uint256 collateralReceived = forwardResult[forwardResult.length - 1];
        _validatePriceInvariant(peggedToken, collateralToken, amount, collateralReceived);

        _approveIfNeeded(collateralToken, routerToPegged, collateralReceived);
        address[] memory pathBackward = new address[](2);
        pathBackward[0] = collateralToken;
        pathBackward[1] = peggedToken;

        uint256[] memory backwardResult = IV2Router(routerToPegged).swapExactTokensForTokens(
            collateralReceived,
            minPeggedOut,
            pathBackward,
            address(this),
            deadline
        );

        uint256 peggedReceived = backwardResult[backwardResult.length - 1];
        require(peggedReceived >= amount, "FlashArb: no profit");

        profit = peggedReceived - amount;
        profitUsd = _toUsdValue(peggedToken, profit);
        emit DepegArbitrage(peggedToken, collateralToken, profit, profitUsd);
    }

    // ================== Price Guard logic ==================

    function _validatePriceInvariant(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut
    ) internal view {
        uint256 usdIn = _toUsdValue(tokenIn, amountIn);
        uint256 usdOut = _toUsdValue(tokenOut, amountOut);
        require(usdOut * MAX_BPS >= usdIn * (MAX_BPS - maxPriceDeviationBps), "FlashArb: price deviation");
    }

    function setMaxPriceDeviationBps(uint256 newDeviation) external onlyOwner {
        require(newDeviation <= 500, "FlashArb: deviation too high");
        maxPriceDeviationBps = newDeviation;
        emit MaxPriceDeviationUpdated(newDeviation);
    }

    function setKeeper(address keeper, bool allowed) external onlyOwner {
        keepers[keeper] = allowed;
        emit KeeperSet(keeper, allowed);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function updatePriceFeed(address token, address feed) external onlyOwner {
        priceFeeds[token] = AggregatorV3Interface(feed);
        emit PriceFeedUpdated(token, feed);
    }

    function requestFlashLoan(
        address asset,
        uint256 amount,
        FlashLoanParams calldata params
    ) external onlyKeeper nonReentrant whenNotPaused mevGuard {
        require(asset != address(0), "FlashArb: invalid asset");
        bytes memory encoded = _encodeParams(params);
        aavePool.flashLoanSimple(address(this), asset, amount, encoded, 0);
    }

    function sweep(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (token == address(0)) {
            (bool success, ) = to.call{value: amount}("");
            require(success, "FlashArb: sweep failed");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    // ================== Internal utilities ==================

    function _approveIfNeeded(address token, address spender, uint256 amount) internal {
        uint256 allowance = IERC20(token).allowance(address(this), spender);
        if (allowance < amount) {
            IERC20(token).safeApprove(spender, 0);
            IERC20(token).safeApprove(spender, type(uint256).max);
        }
    }

    function _encodeParams(FlashLoanParams calldata params) internal pure returns (bytes memory) {
        return abi.encode(params);
    }

    function _decodeParams(bytes calldata data) internal pure returns (FlashLoanParams memory) {
        return abi.decode(data, (FlashLoanParams));
    }

    function _toUsdValue(address token, uint256 amount) internal view returns (uint256) {
        AggregatorV3Interface feed = priceFeeds[token];
        require(address(feed) != address(0), "FlashArb: feed missing");
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "FlashArb: invalid price");

        uint8 feedDecimals = feed.decimals();
        uint8 tokenDecimals = IERC20Metadata(token).decimals();
        uint256 adjustedAmount = amount * (10 ** 18) / (10 ** tokenDecimals);
        return adjustedAmount * uint256(price) / (10 ** feedDecimals);
    }

    receive() external payable {}
}
