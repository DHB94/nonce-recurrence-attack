"""Enhanced twist attack implementation for secp256k1 keys.

This module encapsulates an "enhanced" twist attack that attempts to
recover ECDSA private keys by exploring twists of the secp256k1 elliptic
curve.  The implementation is intentionally self-contained so that it can
be imported as a module or executed directly.

The core functionality lives inside :class:`EnhancedTwistAttack`, which
offers helpers for loading public keys, generating quadratic twists, and
attempting to recover partial private keys from small subgroups on those
twists.  Results are cached in ``curve_cache.json`` to speed up
subsequent runs.
"""

from __future__ import annotations

import base58
import hashlib
import json
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from sage.all import (
    EllipticCurve,
    GF,
    ZZ,
    crt,
    discrete_log,
    factor,
    kronecker,
    power_mod,
)


class EnhancedTwistAttack:
    """Carry out a twist-based attack against secp256k1 public keys."""

    def __init__(
        self,
        pubx: Optional[int] = None,
        puby: Optional[int] = None,
        compressed_pubkey: Optional[str] = None,
        bitcoin_address: Optional[str] = None,
        threshold: int = 10**4,
        max_twists: int = 50,
        max_workers: int = 4,
    ) -> None:
        # SECP256k1 parameters
        self.p = int(2**256 - 2**32 - 977)
        self.n = int(
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        )
        self.a = 0
        self.b = 7
        self.Fp = GF(self.p)
        self.max_twists = max_twists
        self.max_workers = max_workers
        self.curves: Dict[str, EllipticCurve] = {}
        self._cache: Dict[str, Dict[str, int]] = {}

        # Initialize curves
        self.initialize_curves()

        # Set public key or Bitcoin address
        self.public_key: Optional[Tuple[int, int]] = None
        self.bitcoin_address = bitcoin_address
        if compressed_pubkey:
            self.set_public_key_from_compressed(compressed_pubkey)
        elif pubx is not None and puby is not None:
            self.set_public_key(pubx, puby)

        # Attack parameters
        self.threshold = threshold
        self.results: Dict[str, Dict[str, object]] = {}
        self.runtime_stats: Dict[str, float] = {}
        self.partial_keys: List[Tuple[int, int]] = []
        self.valid_curves: List[str] = []

    def _convert_to_python(self, obj):
        """Recursively convert Sage types to Python native types."""

        if isinstance(obj, (list, tuple)):
            return [self._convert_to_python(x) for x in obj]
        if isinstance(obj, dict):
            return {str(k): self._convert_to_python(v) for k, v in obj.items()}
        if hasattr(obj, "python"):
            return obj.python()
        return obj

    def initialize_curves(self) -> None:
        """Initialize secp256k1 and generate twist curves with caching."""

        cache_file = "curve_cache.json"

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                self._cache = json.load(f)
                print(f"Loaded {len(self._cache)} curves from cache")
        except (FileNotFoundError, json.JSONDecodeError):
            self._cache = {}

        # Create secp256k1 curve
        if "secp256k1" not in self._cache:
            self.curves["secp256k1"] = EllipticCurve(self.Fp, [self.a, self.b])
            self._cache["secp256k1"] = {"a": 0, "b": 7}
        else:
            self.curves["secp256k1"] = EllipticCurve(self.Fp, [0, 7])

        # Generate twists
        D = 2
        while kronecker(D, self.p) != -1:
            D += 1
        self.D = int(D)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for k in range(1, self.max_twists + 1):
                curve_name = f"Twist_k{k}"
                if curve_name in self._cache:
                    curve_data = self._cache[curve_name]
                    b_val = int(curve_data["b"])
                    self.curves[curve_name] = EllipticCurve(self.Fp, [0, b_val])
                else:
                    futures.append(executor.submit(self._create_twist_curve, k))

            for future in as_completed(futures):
                try:
                    curve_name, curve = future.result()
                    if curve:
                        self.curves[curve_name] = curve
                except Exception as exc:  # pragma: no cover - defensive logging
                    print(f"Error creating twist curve: {exc}")

        with open(cache_file, "w", encoding="utf-8") as f:
            cache_to_save = self._convert_to_python(self._cache)
            json.dump(cache_to_save, f)

    def _create_twist_curve(self, k: int) -> Tuple[str, Optional[EllipticCurve]]:
        """Helper method to create a single twist curve."""

        curve_name = f"Twist_k{k}"
        try:
            b_twist = int((self.b * pow(self.D, 2, self.p) * pow(k, 2, self.p)) % self.p)
            if b_twist == self.b:
                return curve_name, None

            curve = EllipticCurve(self.Fp, [0, b_twist])
            self._cache[curve_name] = {"a": 0, "b": b_twist}
            return curve_name, curve
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Error creating {curve_name}: {exc}")
            return curve_name, None

    def set_public_key(self, pubx: int | str, puby: int | str) -> None:
        """Set and validate the public key."""

        if isinstance(pubx, str):
            pubx = ZZ(pubx, 16)
        if isinstance(puby, str):
            puby = ZZ(puby, 16)

        self.public_key = (int(pubx), int(puby))

        if not self.curves["secp256k1"].is_on_curve(pubx, puby):
            raise ValueError("The provided public key is not valid on the secp256k1 curve.")

        point = self.curves["secp256k1"]((pubx, puby))
        if point.is_zero():
            raise ValueError("Public key point is the point at infinity.")
        if not (self.n * point).is_zero():
            raise ValueError("Public key point does not have the correct order.")

        print(f"Public key validated on SECP256k1: ({hex(int(pubx))}, {hex(int(puby))})")

    def set_public_key_from_compressed(self, compressed_pubkey: str) -> None:
        """Set the public key from a compressed public key."""

        if not compressed_pubkey.startswith(("02", "03")):
            raise ValueError("Invalid compressed public key format.")

        prefix = compressed_pubkey[:2]
        x_hex = compressed_pubkey[2:]
        x = ZZ(x_hex, 16)

        y_sq = (x**3 + 7) % self.p
        y = self.tonelli_shanks(y_sq)
        if (prefix == "02" and y % 2 == 1) or (prefix == "03" and y % 2 == 0):
            y = self.p - y

        self.set_public_key(x, y)

    def tonelli_shanks(self, n: int, p: Optional[int] = None) -> int:
        """Tonelli-Shanks algorithm for finding square roots modulo a prime."""

        if p is None:
            p = self.p

        if self.legendre_symbol(n, p) != 1:
            raise ValueError("n is not a quadratic residue modulo p.")

        if p % 4 == 3:
            return int(power_mod(n, (p + 1) // 4, p))

        q = p - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1

        z = 2
        while self.legendre_symbol(z, p) != -1:
            z += 1

        m = s
        c = int(power_mod(z, q, p))
        t = int(power_mod(n, q, p))
        r = int(power_mod(n, (q + 1) // 2, p))

        while t not in (0, 1):
            t2i = t
            for i in range(1, m):
                t2i = (t2i * t2i) % p
                if t2i == 1:
                    break

            b = int(power_mod(c, 1 << (m - i - 1), p))
            m = i
            c = (b * b) % p
            t = (t * c) % p
            r = (r * b) % p

        return r

    def legendre_symbol(self, a: int, p: Optional[int] = None) -> int:
        """Compute the Legendre symbol (a|p)."""

        if p is None:
            p = self.p
        if a == 0:
            return 0
        ls = int(power_mod(a, (p - 1) // 2, p))
        return -1 if ls == p - 1 else ls

    def analyze_curve_batch(
        self, curve_batch: List[Tuple[str, EllipticCurve]]
    ) -> Dict[str, Dict[str, object]]:
        """Analyze a batch of curves in parallel."""

        results = {}
        for curve_name, curve in curve_batch:
            try:
                start_time = time.time()
                result = self.analyze_curve(curve_name, curve)
                results[curve_name] = {"result": result, "time": time.time() - start_time}
            except Exception as exc:  # pragma: no cover - defensive logging
                print(f"Error analyzing {curve_name}: {exc}")
                results[curve_name] = {"error": str(exc)}
        return results

    def analyze_curve(self, curve_name: str, curve: EllipticCurve) -> Dict[str, object]:
        """Analyze a single curve with optimized performance."""

        analysis: Dict[str, object] = {
            "valid": False,
            "order": None,
            "factors": [],
            "small_subgroups": [],
            "partial_keys": [],
            "error": None,
        }

        try:
            cache_key = f"{curve_name}_analysis"
            if cache_key in self._cache:
                return self._convert_to_python(self._cache[cache_key])

            print(f"  Computing order for {curve_name}...")
            order = int(curve.order())
            factors = factor(ZZ(order))

            factors_list = [(int(p), int(e)) for p, e in factors]
            small_subgroups = [int(p) for p, _ in factors if p < self.threshold]

            analysis.update({
                "order": order,
                "factors": factors_list,
                "small_subgroups": small_subgroups,
            })

            if not self.public_key:
                self._cache[cache_key] = analysis
                return analysis

            pubx, puby = self.public_key
            Qy = self.find_valid_y_on_twist(pubx, curve)

            if Qy is None:
                self._cache[cache_key] = analysis
                return analysis

            analysis["valid"] = True
            self.valid_curves.append(curve_name)

            Q = (pubx, Qy)
            partial_keys = []
            for dlog, subgroup_order in self.find_partial_keys(curve, Q, small_subgroups):
                if self.verify_partial_key(curve, Q, dlog, subgroup_order):
                    partial_keys.append((int(dlog), int(subgroup_order)))

            analysis["partial_keys"] = partial_keys
            self.partial_keys.extend(partial_keys)
            self._cache[cache_key] = analysis

        except Exception as exc:  # pragma: no cover - defensive logging
            analysis["error"] = str(exc)
            print(f"Error analyzing {curve_name}: {exc}")

        return analysis

    def find_valid_y_on_twist(self, x: int, curve: EllipticCurve) -> Optional[int]:
        """Find a valid y-coordinate for x on the given curve."""

        try:
            rhs = (x**3 + curve.a4() * x + curve.a6()) % self.p
            if self.legendre_symbol(rhs, self.p) == 1:
                y = self.tonelli_shanks(rhs, self.p)
                if curve.is_on_curve(x, y):
                    return y
                y_alt = self.p - y
                if curve.is_on_curve(x, y_alt):
                    return y_alt
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Error finding y-coordinate: {exc}")
        return None

    def find_partial_keys(
        self, curve: EllipticCurve, Q, small_subgroups: List[int]
    ) -> List[Tuple[int, int]]:
        """Find partial private keys for small subgroups."""

        partial_keys = []
        EQ = curve(Q)

        for subgroup_order in small_subgroups:
            try:
                h = curve.order() // subgroup_order
                hQ = h * EQ
                hg = h * curve.gens()[0]

                if hQ.is_zero():
                    continue

                if not (subgroup_order * hg).is_zero():
                    continue

                dlog = discrete_log(hQ, hg, operation="+")

                if hQ == dlog * hg:
                    partial_keys.append((int(dlog), int(subgroup_order)))
                    print(f"  Found valid partial key: {dlog} mod {subgroup_order}")

            except Exception as exc:  # pragma: no cover - defensive logging
                print(f"  Error in subgroup {subgroup_order}: {exc}")
                continue

        return partial_keys

    def verify_partial_key(self, curve: EllipticCurve, Q, dlog: int, order: int) -> bool:
        """Verify that a partial key is correct for the given point."""

        try:
            EQ = curve(Q)
            h = curve.order() // order
            hQ = h * EQ
            hg = h * curve.gens()[0]
            return hQ == dlog * hg
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Error verifying partial key {dlog} mod {order}: {exc}")
            return False

    def combine_partial_keys(self) -> Optional[int]:
        """Combine partial keys using CRT, with better handling of inconsistencies."""

        if not self.partial_keys:
            return None

        order_dict = defaultdict(list)
        for dlog, order in self.partial_keys:
            order_dict[order].append(dlog % order)

        consistent_keys = []
        for order, residues in order_dict.items():
            residue_counts = Counter(residues)
            if len(residue_counts) == 1:
                consistent_keys.append((residues[0], order))
            else:
                most_common = residue_counts.most_common(1)[0]
                if most_common[1] > 1:
                    consistent_keys.append((most_common[0], order))
                    print(
                        "Using most common residue "
                        f"{most_common[0]} for order {order} "
                        f"(appeared {most_common[1]} times)"
                    )

        if not consistent_keys:
            print("No consistent partial keys found")
            return None

        consistent_keys.sort(key=lambda x: x[1])

        try:
            residues, moduli = zip(*consistent_keys)
            private_key = crt(residues, moduli)

            if self.verify_private_key(private_key):
                print(
                    "Successfully recovered private key using "
                    f"{len(consistent_keys)} consistent partial keys"
                )
                return private_key
            print("CRT result failed verification against original curve")
            return None
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"CRT failed: {exc}")
            return None

    def verify_private_key(self, private_key: int) -> bool:
        """Verify the derived private key against the original public key."""

        if not self.public_key:
            return False

        try:
            derived_pub = private_key * self.curves["secp256k1"].gens()[0]
            target_pub = self.curves["secp256k1"](self.public_key)
            return derived_pub == target_pub
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Verification error: {exc}")
            return False

    def verify_private_key_against_bitcoin_address(self, private_key: int) -> bool:
        """Verify the derived private key against the Bitcoin address."""

        if not self.bitcoin_address:
            return False

        G = self.curves["secp256k1"].gens()[0]
        Q = private_key * G
        pubx, puby = Q.xy()

        prefix = b"\x02" if puby % 2 == 0 else b"\x03"
        compressed_pubkey = prefix + int(pubx).to_bytes(32, byteorder="big")

        sha256 = hashlib.sha256(compressed_pubkey).digest()
        ripemd160 = hashlib.new("ripemd160", sha256).digest()
        address = base58.b58encode_check(b"\x00" + ripemd160)

        return address.decode("utf-8") == self.bitcoin_address

    def save_results(self, filename: str) -> None:
        """Save results to a JSON file with proper integer serialization."""

        results = {
            "public_key": tuple(self._convert_to_python(x) for x in self.public_key)
            if self.public_key
            else None,
            "bitcoin_address": self.bitcoin_address,
            "parameters": {
                "threshold": self._convert_to_python(self.threshold),
                "max_twists": self.max_twists,
                "num_curves": len(self.curves),
            },
            "results": self._convert_to_python(self.results),
            "runtime_stats": self._convert_to_python(self.runtime_stats),
            "partial_keys": self._convert_to_python(self.partial_keys),
            "valid_curves": self.valid_curves,
            "success": self.results.get("verification", False),
            "bitcoin_success": self.results.get("bitcoin_verification", False),
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)

    def print_summary(self) -> None:
        """Print a summary of the attack results."""

        print("\n=== ENHANCED TWIST ATTACK SUMMARY ===")
        if self.public_key:
            print(
                "Public Key: "
                f"({hex(self.public_key[0])}, {hex(self.public_key[1])})"
            )
        if self.bitcoin_address:
            print(f"Bitcoin Address: {self.bitcoin_address}")
        print(f"Analyzed {len(self.curves)} curves")
        print(f"Found {len(self.valid_curves)} valid twist curves")
        print(f"Found {len(self.partial_keys)} partial private keys")

        if "combined_key" in self.results:
            print(f"\nCombined Private Key: {self.results['combined_key']}")
            print(
                "Verification Status: "
                f"{'SUCCESS' if self.results.get('verification', False) else 'FAILED'}"
            )
            if self.bitcoin_address:
                print(
                    "Bitcoin Address Verification: "
                    f"{'SUCCESS' if self.results.get('bitcoin_verification', False) else 'FAILED'}"
                )

        print("\nValid Twist Curves:")
        for curve_name in self.valid_curves:
            result = self.results.get(curve_name, {})
            print(f"\n{curve_name}:")
            print(f"  Order: {result.get('order', 'N/A')}")
            print(f"  Small subgroups: {result.get('small_subgroups', [])}")
            if "partial_keys" in result:
                print(f"  Found {len(result['partial_keys'])} partial keys")

        print(f"\nTotal runtime: {self.runtime_stats.get('total', 0):.2f} seconds")

    def run_attack(self) -> Dict[str, object]:
        """Run the complete twist attack with progress tracking and timeout handling."""

        if not self.public_key:
            raise ValueError("No public key set for attack.")

        start_time = time.time()

        try:
            total_curves = len(self.curves)
            print(
                f"Starting attack on {total_curves} curves with threshold {self.threshold}"
            )

            batch_size = max(1, total_curves // (self.max_workers * 2))
            curves_list = list(self.curves.items())

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for i in range(0, len(curves_list), batch_size):
                    batch = curves_list[i : i + batch_size]
                    futures.append(executor.submit(self.analyze_curve_batch, batch))

                for future in as_completed(futures):
                    try:
                        batch_results = future.result()
                        for curve_name, result in batch_results.items():
                            if "error" in result:
                                self.results[curve_name] = {"error": result["error"]}
                            else:
                                self.results[curve_name] = result["result"]
                                self.runtime_stats[curve_name] = result["time"]
                    except Exception as exc:  # pragma: no cover - defensive logging
                        print(f"Error processing batch: {exc}")

            print("\nAttempting to combine partial keys...")
            combined_key = self.combine_partial_keys()

            if combined_key:
                self.results["combined_key"] = hex(combined_key)
                self.results["verification"] = self.verify_private_key(combined_key)
                if self.bitcoin_address:
                    self.results["bitcoin_verification"] = self.verify_private_key_against_bitcoin_address(
                        combined_key
                    )

            total_time = time.time() - start_time
            self.runtime_stats["total"] = total_time
            print(f"\nAttack completed in {total_time:.2f} seconds")
            return self.results

        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Error during attack: {exc}")
            raise


if __name__ == "__main__":
    compressed_pubkey = "033bb421d32a069f078cfdfd56cdc1391fbd87e4183ca94458e3f5c4c8945782be"
    bitcoin_address = "1Pzaqw98PeRfyHypfqyEgg5yycJRsENrE7"

    attack = EnhancedTwistAttack(
        compressed_pubkey=compressed_pubkey,
        bitcoin_address=bitcoin_address,
        threshold=10**4,
        max_twists=160,
        max_workers=4,
    )

    results = attack.run_attack()
    attack.print_summary()

    output_file = "enhanced_twist_attack_results.json"
    attack.save_results(output_file)
    print(f"\nResults saved to {output_file}")
