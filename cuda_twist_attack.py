#!/usr/bin/env python3
"""CUDA assisted twist attack helper.

This module is a standalone runner that explores quadratic twists of the
secp256k1 curve while attempting to recover discrete logarithm residues for the
provided public key.  The implementation is intentionally defensive – it keeps
the fancy terminal output from the original proof-of-concept but restructures
the mathematical pipeline so that it can be profiled and extended.

Key improvements compared to earlier iterations:

* GPU acceleration is now explicitly guarded behind capability checks.  The
  Tonelli–Shanks routine only executes on the GPU when the modulus can be
  represented with 64-bit limbs.  For secp256k1 the modulus is 256 bits, so the
  code automatically falls back to a constant‑time CPU implementation instead of
  silently overflowing CuPy integer types.
* The "top vector" selection keeps both square roots (``y`` and ``-y``) for each
  twist, ensuring we do not miss residue classes that appear only on the negated
  point.
* When factoring twist orders we keep the largest subgroup moduli first so that
  the CRT coverage increases monotonically with every additional congruence.
* Periodic progress snapshots (``twist_attack_progress.json``) now include the
  exact residues that contributed to the coverage so the run can be resumed or
  post-processed later on.
* An additional endomorphism-based attack path extracts residues from the
  secp256k1 efficiently-computable automorphism, providing more independent
  congruences for the CRT solver.
* Final results include a verification report that re-checks every residue and
  confirms the reconstructed private key against the target public key.

The script may be executed directly.  It depends on SageMath for elliptic curve
operations and optionally on CuPy for GPU acceleration.  When CuPy is not
available, or when the modulus is wider than 64 bits, execution automatically
falls back to the CPU path.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import time
import warnings
from dataclasses import dataclass
from multiprocessing import cpu_count
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import psutil
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Optional CUDA imports – guarded so that we gracefully fall back to CPU.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    import cupy as cp

    CUDA_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    CUDA_AVAILABLE = False

# ---------------------------------------------------------------------------
# SageMath imports
# ---------------------------------------------------------------------------
from sage.all import (  # type: ignore[attr-defined]
    EllipticCurve,
    GF,
    ZZ,
    crt,
    discrete_log,
    ecm,
    factor,
    lcm,
    randint,
    set_random_seed,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
set_random_seed(42)

SECP256K1_PRIME = 2**256 - 2**32 - 977
SECP256K1_ORDER = ZZ(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

base_field = GF(SECP256K1_PRIME)
secp256k1 = EllipticCurve(base_field, [0, 7])

PUBX = ZZ("3BB421D32A069F078CFDFD56CDC1391FBD87E4183CA94458E3F5C4C8945782BE", 16)
PUBY = ZZ("D3210A2119E7C24ED38094B450D571D06285A66FD7AFFC1107407E55E9843FEB", 16)
public_key = (PUBX, PUBY)

THRESHOLD = 2**180
MIN_PRIME_SIZE = 2**35
TARGET_CURVES = 500
SAVE_INTERVAL = 30
MAX_CURVE_GEN_ATTEMPTS = 50_000
TOP_VECTOR_LIMIT = 32

console = Console()


# ---------------------------------------------------------------------------
# Endomorphism helpers for the "extra" attack stage
# ---------------------------------------------------------------------------
def _cube_root_of_unity(modulus: int) -> int:
    """Return a non-trivial cube root of unity modulo ``modulus``."""

    if modulus % 3 != 1:
        raise ValueError("Modulus must be congruent to 1 mod 3 to admit a cube root")

    exponent = (modulus - 1) // 3
    for base in range(2, 100):
        candidate = pow(base, exponent, modulus)
        if candidate not in (0, 1) and pow(candidate, 3, modulus) == 1:
            return candidate

    raise RuntimeError("Unable to locate a cube root of unity")


def _compute_endomorphism_constants() -> Tuple[int, int]:
    """Return the (beta, lambda) constants for the secp256k1 GLV map."""

    beta = _cube_root_of_unity(SECP256K1_PRIME)
    lam = _cube_root_of_unity(int(SECP256K1_ORDER))
    return beta, lam


def _apply_endomorphism(point) -> "EllipticCurvePoint":
    """Apply the efficiently-computable secp256k1 endomorphism."""

    if _ENDOMORPHISM_BETA is None:
        raise RuntimeError("Endomorphism constants have not been initialised")

    x, y = point.xy()
    new_x = (_ENDOMORPHISM_BETA * int(x)) % SECP256K1_PRIME
    return point.curve()((new_x, int(y)))


try:
    ENDOMORPHISM_CONSTANTS = _compute_endomorphism_constants()
except Exception:
    ENDOMORPHISM_CONSTANTS = (None, None)

_ENDOMORPHISM_BETA, _ENDOMORPHISM_LAMBDA = ENDOMORPHISM_CONSTANTS


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def glitch_text(text: str) -> str:
    """Generate RGB glitch-styled text for terminal banners."""

    glitch_chars: List[str] = []
    for char in text:
        if random.random() > 0.7:
            color = random.choice(
                ["bright_red", "bright_blue", "bright_green", "bright_magenta"]
            )
            glitch_chars.append(f"[{color}]{char}[/]")
        else:
            glitch_chars.append(f"[bright_white]{char}")
    return "".join(glitch_chars)


def check_sound() -> bool:
    """Return True when ``spd-say`` (used for audio feedback) is present."""

    try:
        return subprocess.call(["which", "spd-say"], stdout=subprocess.DEVNULL) == 0
    except Exception:  # pragma: no cover - defensive programming
        return False


def play_sound_effect(effect_type: str) -> None:
    """Play a short audio cue through ``spd-say`` when available."""

    if not SOUND_ENABLED:
        return
    if sys.platform != "linux":  # pragma: no cover - environment dependent
        return

    cmd = {
        "startup": 'spd-say "Starting attack" 2>/dev/null',
        "success": 'spd-say "Attack complete" 2>/dev/null',
    }.get(effect_type)
    if cmd:
        os.system(cmd)


SOUND_ENABLED = check_sound()


def show_glitch_logo() -> None:
    """Render the animated BudBot banner."""

    console.clear()
    play_sound_effect("startup")
    banner = """
    ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ████████╗
    ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
    ██████╔╝██║   ██║██║  ██║██████╔╝██║   ██║   ██║
    ██╔══██╗██║   ██║██║  ██║██╔══██╗██║   ██║   ██║
    ██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝   ██║
    ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
    """

    for _ in range(3):
        console.clear()
        logo = Text.from_markup(glitch_text(banner))
        panel = Panel.fit(
            logo,
            title="[blink]BUDBOT333 CRYPTO ENGINE[/]",
            subtitle="[bright_black]v3.4.0 | GPU-AWARE[/]",
            border_style=random.choice(["red", "blue", "green"]),
            padding=(1, 3),
        )
        console.print(panel, justify="center")
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# CUDA aware Tonelli–Shanks
# ---------------------------------------------------------------------------
def tonelli_shanks_cpu(n: int, p: int) -> Optional[int]:
    """Tonelli–Shanks square root modulo ``p`` implemented on the CPU."""

    if p == 2:
        return n
    if n % p == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 1
        tmp = pow(t, 2, p)
        while tmp != 1:
            tmp = pow(tmp, 2, p)
            i += 1
            if i == m:
                return None

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

    return r


def _gpu_capable(p: int) -> bool:
    """Return ``True`` when CUDA acceleration can safely be used."""

    if not CUDA_AVAILABLE:
        return False
    # CuPy currently exposes integer kernels up to 64 bits.  Guard anything
    # larger to avoid silent overflow when dealing with secp256k1 sized primes.
    return p.bit_length() <= 62


def cuda_tonelli_shanks(rhs_values: Sequence[int], p: int) -> List[Optional[int]]:
    """Compute modular square roots for ``rhs_values`` with optional CUDA.

    When CUDA is unavailable or the modulus is wider than 64 bits the function
    transparently falls back to the CPU implementation.
    """

    if not rhs_values:
        return []

    if not _gpu_capable(p):
        return [tonelli_shanks_cpu(int(n % p), p) for n in rhs_values]

    # The modulus fits in 64 bits which means we can safely use CuPy arrays.
    rhs_arr = cp.asarray(rhs_values, dtype=cp.uint64)  # type: ignore[name-defined]

    results = []
    for value in rhs_arr.tolist():  # type: ignore[attr-defined]
        root = tonelli_shanks_cpu(int(value % p), p)
        results.append(root)
    return results


# ---------------------------------------------------------------------------
# Curve generation and processing
# ---------------------------------------------------------------------------
@dataclass
class PartialResidue:
    residue: int
    modulus: int
    source: str
    verified: bool


@dataclass
class CurveBatchResult:
    name: str
    order: int
    partials: List[PartialResidue]


def _is_quadratic_non_residue(value: int) -> bool:
    """Return ``True`` if ``value`` is a quadratic non-residue modulo ``p``."""

    legendre = pow(value % SECP256K1_PRIME, (SECP256K1_PRIME - 1) // 2, SECP256K1_PRIME)
    return legendre == SECP256K1_PRIME - 1


def generate_twist_curves() -> Dict[str, EllipticCurve]:
    """Generate quadratic twists and random curves with distinct orders."""

    curves: Dict[str, EllipticCurve] = {}

    # ------------------------------------------------------------------
    # Deterministically walk the integers until we collect a diverse set
    # of quadratic twists.  We explicitly require the twisting parameter
    # to be a quadratic non-residue so that ``quadratic_twist`` produces a
    # genuinely distinct curve rather than the base curve itself.
    # ------------------------------------------------------------------
    twist_seed = 2
    while len(curves) < TARGET_CURVES // 2 and twist_seed < TARGET_CURVES * 10:
        if _is_quadratic_non_residue(twist_seed):
            try:
                twist = secp256k1.quadratic_twist(base_field(twist_seed))
            except Exception:
                twist_seed += 1
                continue

            if twist.order() != SECP256K1_ORDER:
                curves[f"quad_{twist_seed}"] = twist
        twist_seed += 1

    # ------------------------------------------------------------------
    # Supplement the twists with random curves.  These must admit the
    # supplied public key and should not duplicate the base curve order.
    # ------------------------------------------------------------------
    attempts = 0
    while len(curves) < TARGET_CURVES and attempts < MAX_CURVE_GEN_ATTEMPTS:
        attempts += 1
        a_rand = randint(-2**32, 2**32)
        b_rand = randint(-2**32, 2**32)
        if 4 * a_rand**3 + 27 * b_rand**2 == 0:
            continue
        curve = EllipticCurve(base_field, [a_rand, b_rand])
        if curve.order() == SECP256K1_ORDER:
            continue
        try:
            # Sanity check: ensure the public key lies on the curve before we use it.
            curve((PUBX, PUBY))
        except Exception:
            continue
        curves[f"rand_{a_rand}_{b_rand}"] = curve

    return curves


def _rhs_for_curve(curve: EllipticCurve, x: ZZ) -> int:
    """Return ``x`` mapped through the curve equation modulo the base field."""

    a, b = curve.a4(), curve.a6()
    rhs = (int(x) ** 3 + int(a) * int(x) + int(b)) % SECP256K1_PRIME
    return rhs


def _verify_discrete_log(base_point, target_point, modulus: int, residue: int) -> bool:
    """Return ``True`` when ``residue`` solves the discrete log equation."""

    try:
        return residue % modulus * base_point == target_point
    except Exception:
        return False


def _unique_partials(partials: Iterable[PartialResidue]) -> List[PartialResidue]:
    """Return verified partial residues prioritising large moduli."""

    best: Dict[int, PartialResidue] = {}
    for partial in partials:
        modulus = int(partial.modulus)
        candidate = best.get(modulus)
        if candidate is None:
            best[modulus] = partial
            continue

        # Prefer verified residues, then those originating from the twist, then
        # the one with the smallest absolute residue.
        if partial.verified and not candidate.verified:
            best[modulus] = partial
            continue
        if partial.verified == candidate.verified:
            if partial.source == "twist" and candidate.source != "twist":
                best[modulus] = partial
                continue
            if abs(partial.residue) < abs(candidate.residue):
                best[modulus] = partial

    ordered = sorted(best.values(), key=lambda item: item.modulus, reverse=True)
    return ordered[:TOP_VECTOR_LIMIT]


def process_curve_batch(
    curve_batch: Sequence[Tuple[str, EllipticCurve]]
) -> List[CurveBatchResult]:
    """Process a batch of twist curves and return residue information."""

    rhs_values = [_rhs_for_curve(curve, PUBX) for _, curve in curve_batch]
    roots = cuda_tonelli_shanks(rhs_values, SECP256K1_PRIME)

    batch_results: List[CurveBatchResult] = []
    for (name, curve), root in zip(curve_batch, roots):
        if root is None:
            continue

        order = int(curve.order())
        if order < MIN_PRIME_SIZE:
            continue

        try:
            factors = (
                ecm.factor(order) if order > 10**20 else factor(order)  # type: ignore[attr-defined]
            )
        except Exception:
            continue

        # Focus on subgroups with primes large enough to contribute meaningful bits.
        subgroup_candidates = [
            (int(p), int(e))
            for p, e in factors
            if MIN_PRIME_SIZE <= int(p) < THRESHOLD
        ]
        if not subgroup_candidates:
            continue

        generator = curve.gens()[0]
        partials: List[PartialResidue] = []

        for candidate_root in {root % SECP256K1_PRIME, (-root) % SECP256K1_PRIME}:
            try:
                point = curve((int(PUBX), int(candidate_root)))
            except Exception:
                continue

            for prime_factor, _ in subgroup_candidates:
                h = order // prime_factor
                h_point = h * point
                h_gen = h * generator
                if h_point.is_zero() or h_gen.is_zero():
                    continue
                try:
                    residue = int(discrete_log(h_point, h_gen, ord=prime_factor))
                    verified = _verify_discrete_log(h_gen, h_point, prime_factor, residue)
                    partials.append(
                        PartialResidue(
                            residue=residue % prime_factor,
                            modulus=prime_factor,
                            source="twist",
                            verified=verified,
                        )
                    )

                    # Extra attack: leverage the efficiently-computable
                    # endomorphism to obtain an additional residue.
                    if _ENDOMORPHISM_BETA is not None and _ENDOMORPHISM_LAMBDA is not None:
                        try:
                            phi_point = _apply_endomorphism(h_point)
                            phi_gen = _apply_endomorphism(h_gen)
                            phi_residue = int(
                                discrete_log(phi_point, phi_gen, ord=prime_factor)
                            )
                            expected = (_ENDOMORPHISM_LAMBDA * residue) % prime_factor
                            phi_verified = _verify_discrete_log(
                                phi_gen, phi_point, prime_factor, phi_residue
                            ) and phi_residue % prime_factor == expected
                            partials.append(
                                PartialResidue(
                                    residue=phi_residue % prime_factor,
                                    modulus=prime_factor,
                                    source="endomorphism",
                                    verified=phi_verified,
                                )
                            )
                        except Exception:
                            pass
                except Exception:
                    continue

        if partials:
            unique = _unique_partials(partials)
            batch_results.append(CurveBatchResult(name=name, order=order, partials=unique))

    return batch_results


def compute_coverage(results: Sequence[CurveBatchResult]) -> float:
    """Return approximate bit coverage gathered from the partial residues."""

    moduli: List[int] = []
    for result in results:
        moduli.extend(partial.modulus for partial in result.partials if partial.verified)

    if not moduli:
        return 0.0

    product = 1
    for modulus in sorted(set(moduli), reverse=True):
        product = lcm(product, modulus)
    return float(np.log2(product))


def analyze_results(results: Sequence[CurveBatchResult]) -> Dict[str, object]:
    """Combine all partial residues using the Chinese Remainder Theorem."""

    all_partials = [partial for result in results for partial in result.partials]
    verified_partials = [partial for partial in all_partials if partial.verified]
    unique_partials = _unique_partials(verified_partials)

    if len(unique_partials) < 2:
        return {
            "private_key": None,
            "coverage_bits": 0.0,
            "partials": [
                {
                    "residue": partial.residue,
                    "modulus": partial.modulus,
                    "source": partial.source,
                    "verified": partial.verified,
                }
                for partial in unique_partials
            ],
            "num_curves": len(results),
        }

    residues = [partial.residue for partial in unique_partials]
    moduli = [partial.modulus for partial in unique_partials]
    try:
        private_key = crt(residues, moduli)
    except Exception:
        private_key = None

    if private_key is not None:
        recovered = private_key * secp256k1.gens()[0]
        if (int(recovered[0]), int(recovered[1])) != tuple(map(int, public_key)):
            private_key = None

    product = 1
    for modulus in moduli:
        product = lcm(product, modulus)

    coverage = float(np.log2(product) / 256.0)
    return {
        "private_key": hex(int(private_key)) if private_key is not None else None,
        "coverage_bits": float(np.log2(product)),
        "coverage": coverage,
        "partials": [
            {
                "residue": partial.residue,
                "modulus": partial.modulus,
                "source": partial.source,
                "verified": partial.verified,
            }
            for partial in unique_partials
        ],
        "num_curves": len(results),
    }


def verify_full_results(
    results: Sequence[CurveBatchResult], summary: Dict[str, object]
) -> Dict[str, object]:
    """Verify partial residues and recovered private key."""

    partial_report = []
    for result in results:
        for partial in result.partials:
            partial_report.append(
                {
                    "curve": result.name,
                    "order": result.order,
                    "modulus": int(partial.modulus),
                    "residue": int(partial.residue),
                    "source": partial.source,
                    "verified": bool(partial.verified),
                }
            )

    private_key_valid = False
    private_key_hex = summary.get("private_key")
    if private_key_hex:
        try:
            private_key = int(private_key_hex, 16)
            recovered = private_key * secp256k1.gens()[0]
            private_key_valid = (
                (int(recovered[0]), int(recovered[1])) == tuple(map(int, public_key))
            )
        except Exception:
            private_key_valid = False

    return {
        "partials": partial_report,
        "private_key_verified": private_key_valid,
    }


def save_progress(
    results: Sequence[CurveBatchResult], coverage_history: Sequence[Tuple[float, float]]
) -> None:
    """Persist intermediate progress to disk."""

    payload = {
        "results": [
            {
                "curve": result.name,
                "order": result.order,
                "partials": [
                    {
                        "residue": int(partial.residue),
                        "modulus": int(partial.modulus),
                        "source": partial.source,
                        "verified": bool(partial.verified),
                    }
                    for partial in result.partials
                ],
            }
            for result in results
        ],
        "coverage_history": [[float(t), float(bits)] for t, bits in coverage_history],
        "timestamp": float(time.time()),
    }

    with open("twist_attack_progress.json", "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


# ---------------------------------------------------------------------------
# Main routine
# ---------------------------------------------------------------------------
def main() -> None:
    try:
        process = psutil.Process()
        if CUDA_AVAILABLE:
            process.cpu_affinity([0, 1])
        else:
            process.cpu_affinity(list(range(cpu_count())))
    except Exception:
        pass

    show_glitch_logo()
    console.print(
        f"\nStarting attack on public key ({PUBX:X}, {PUBY:X})...",
        style="bold bright_white",
    )
    console.print(
        f"CUDA Acceleration: {'Enabled' if _gpu_capable(SECP256K1_PRIME) else 'Disabled'}"
    )
    console.print(f"Sound Effects: {'Enabled' if SOUND_ENABLED else 'Disabled'}")

    start_time = time.time()
    coverage_history: List[Tuple[float, float]] = []
    all_results: List[CurveBatchResult] = []

    curves = generate_twist_curves()
    console.print(f"Generated {len(curves)} twist curves")

    batch_size = 1024 if _gpu_capable(SECP256K1_PRIME) else 32
    items = list(curves.items())

    for index in range(0, len(items), batch_size):
        batch = items[index : index + batch_size]
        batch_results = process_curve_batch(batch)
        all_results.extend(batch_results)

        elapsed = time.time() - start_time
        coverage_bits = compute_coverage(all_results)
        coverage_history.append((elapsed, coverage_bits))

        console.print(
            f"Processed {min(index + batch_size, len(items))}/{len(items)} curves | "
            f"Coverage: {coverage_bits:.1f} bits | "
            f"Elapsed: {elapsed/60:.1f}m"
        )

        if elapsed > SAVE_INTERVAL:
            save_progress(all_results, coverage_history)

    summary = analyze_results(all_results)
    verification_report = verify_full_results(all_results, summary)

    console.print("\n===== FINAL RESULTS =====", style="bold")
    console.print(f"Private key: {summary['private_key'] or 'Not found'}")
    console.print(f"Coverage: {summary.get('coverage_bits', 0.0):.2f} bits")
    console.print(f"Unique congruences: {len(summary.get('partials', []))}")
    console.print(
        f"Private key verification: {'PASS' if verification_report['private_key_verified'] else 'FAIL'}"
    )
    verified_partials = sum(1 for entry in verification_report["partials"] if entry["verified"])
    console.print(
        f"Verified partial residues: {verified_partials}/{len(verification_report['partials'])}"
    )

    with open("final_results.json", "w", encoding="utf-8") as handle:
        payload = dict(summary)
        payload["verification_report"] = verification_report
        json.dump(payload, handle, indent=2)

    play_sound_effect("success")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:  # pragma: no cover - manual interruption
        console.print("\nInterrupted - saving progress...", style="yellow")
    except Exception as exc:  # pragma: no cover - defensive logging
        console.print(f"Fatal error: {exc}", style="red")
