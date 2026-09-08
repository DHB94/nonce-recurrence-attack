# Polygon QuickSwap scanner

`polygon_flash_sandwich_bot.js` was upgraded from the original flash-loan implementation.

## The important correctness fix

A Balancer flash loan must be repaid before its transaction returns. The old program performed the front swap and back swap inside the same flash-loan callback, while its profitability model assumed that a victim transaction would execute between them. That ordering is impossible on-chain, so the old program could not perform the sandwich it modeled.

The replacement uses an **owner-funded executor** and a private bundle:

```text
startSandwich -> victim transaction -> finishSandwich
```

The executor pulls the configured input token from the owner, performs the front swap, and stores the output. The back-run transaction swaps that output back and returns the result to the owner. The two bot transactions and the victim transaction are signed/serialized in that order and sent to `BUNDLE_RELAY_URL` using `eth_sendBundle`.

This requires a relay that supports Polygon raw bundles and accepts a fully serialized victim transaction. Relay APIs differ; the standard JSON-RPC method is the only interface implemented here.

## Modes

- `MODE=scan` (default): reads pending QuickSwap swaps, evaluates them, and only logs candidates.
- `MODE=paper`: same behavior as scan, useful for an explicit paper-trading configuration.
- `MODE=execute`: requires a private key, an executor contract, execution capital, token allowance, and a private bundle relay. It never falls back to public `sendTransaction`.

The program does not deploy or trade by default.

## Install and check

```bash
npm install
npm run check
npm run test:polygon
```

## Configuration

At minimum, a scanner needs a websocket Polygon endpoint:

```dotenv
POLYGON_WS_URL=wss://your-polygon-websocket-endpoint
MODE=scan
```

For execution, use a separate wallet and configure all of the following:

```dotenv
MODE=execute
POLYGON_WS_URL=wss://your-polygon-websocket-endpoint
PRIVATE_KEY=0x...
BUNDLE_RELAY_URL=https://your-relay.example/rpc
SANDWICH_CONTRACT_ADDRESS=0x...
TRADE_AMOUNT=12
MIN_PROFIT_AMOUNT=0.35
# This is denominated in the input token, not in MATIC.
# Set it to a conservative reserve for both bot transactions.
ESTIMATED_GAS_COST_ASSET=0
```

The executor must first be deployed from this source, and the wallet must approve the executor for the input token. `MODE=execute` verifies both the token balance and allowance before creating a bundle. To deploy from the configured wallet, use `AUTO_DEPLOY=true`; deployment is intentionally disabled by default. Set `ALLOW_NON_POLYGON=true` only when intentionally testing against another chain.

Useful tuning variables include:

- `QUICKSWAP_ROUTER`, `QUICKSWAP_FACTORY`
- `MIN_POOL_BASE`, `MAX_TRADE_BPS`, `SLIPPAGE_BPS`
- `GAS_LIMIT`, `FIXED_GAS_PRICE_GWEI`
- `PRIORITY_FEE_FLOOR_GWEI`, `PRIORITY_FEE_MULTIPLIER`
- `MAX_PENDING_QUEUE`, `MAX_CONCURRENT_EVALUATIONS`, `MAX_CANDIDATES`

`ESTIMATED_GAS_COST_ASSET` cannot be inferred safely for arbitrary input tokens without a price oracle. Leaving it at zero means the profitability filter does not reserve a token-denominated gas cost; configure it before execution.

## Operational limitations

- Only `swapExactTokensForTokens` transactions with exactly one QuickSwap pair are evaluated.
- The model uses the Uniswap V2 0.3% fee formula and current reserves. It rejects candidates whose predicted victim output is below the victim's `amountOutMin`.
- A public mempool listener cannot guarantee ordering. Execution therefore requires a private relay and a bundle target block.
- Fee-on-transfer and non-standard tokens are not supported by the model.
- Pending transaction contents can be unavailable from some websocket providers. The scanner skips transactions it cannot retrieve instead of guessing.
- This is not investment advice. Test with a fork and a disposable wallet before enabling execution.
