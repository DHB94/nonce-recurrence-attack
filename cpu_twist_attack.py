#!/usr/bin/env python3
"""CPU optimised twist attack helper.

This script is a CPU-focused edition of the CUDA aware twist attack driver.  It
keeps the same mathematical pipeline but removes the GPU specific plumbing so
that multi-core hosts can be saturated efficiently.  Curve processing happens in
parallel using ``ProcessPoolExecutor`` which allows the expensive Sage
operations (Tonelli–Shanks, order factorisation and discrete logarithms) to run
across all available cores.

Key differences compared to ``cuda_twist_attack.py``:

* The Tonelli–Shanks routine is always executed on the CPU and is exposed as a
  batch helper that works well with Python's process pools.
* Curve batches are processed in parallel processes to overlap discrete log
  computation and factorisation work.
* Progress reporting is adapted for asynchronous processing and remains
  deterministic regardless of worker scheduling.

The script requires SageMath but has no optional dependencies such as CuPy.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from multiprocessing import cpu_count
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import psutil
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.text import Text

warnings.filterwarnings("ignore")

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


def _compute_endomorphism_constants() -> Tuple[Optional[int], Optional[int]]:
    """Return the (beta, lambda) constants for the secp256k1 GLV map."""

    try:
        beta = _cube_root_of_unity(SECP256K1_PRIME)
        lam = _cube_root_of_unity(int(SECP256K1_ORDER))
    except Exception:
        return None, None
    return beta, lam


def _apply_endomorphism(point) -> "EllipticCurvePoint":
    """Apply the efficiently-computable secp256k1 endomorphism."""

    if _ENDOMORPHISM_BETA is None:
        raise RuntimeError("Endomorphism constants have not been initialised")

    x, y = point.xy()
    new_x = (_ENDOMORPHISM_BETA * int(x)) % SECP256K1_PRIME
    return point.curve()((new_x, int(y)))


_ENDOMORPHISM_BETA, _ENDOMORPHISM_LAMBDA = _compute_endomorphism_constants()


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
            subtitle="[bright_black]v3.4.0 | CPU EDITION[/]",
            border_style=random.choice(["red", "blue", "green"]),
            padding=(1, 3),
        )
        console.print(panel, justify="center")
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# CPU Tonelli–Shanks helpers
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


def tonelli_shanks_batch(rhs_values: Sequence[int], p: int) -> List[Optional[int]]:
    """Compute modular square roots for ``rhs_values`` on the CPU."""

    return [tonelli_shanks_cpu(int(value % p), p) for value in rhs_values]


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


def generate_twist_curves() -> Dict[str, Tuple[int, int]]:
    """Generate quadratic twists and random curves with distinct orders.

    The return type stores integer ``(a4, a6)`` coefficients for later
    reconstruction inside worker processes.
    """

    curves: Dict[str, Tuple[int, int]] = {}

    twist_seed = 2
    while len(curves) < TARGET_CURVES // 2 and twist_seed < TARGET_CURVES * 10:
        if _is_quadratic_non_residue(twist_seed):
            try:
                twist = secp256k1.quadratic_twist(base_field(twist_seed))
            except Exception:
                twist_seed += 1
                continue

            if twist.order() != SECP256K1_ORDER:
                a4, a6 = int(twist.a4()), int(twist.a6())
                curves[f"quad_{twist_seed}"] = (a4, a6)
        twist_seed += 1

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
            curve((PUBX, PUBY))
        except Exception:
            continue
        curves[f"rand_{a_rand}_{b_rand}"] = (int(curve.a4()), int(curve.a6()))

    return curves


def _rhs_for_curve(a4: int, a6: int, x: ZZ) -> int:
    """Return ``x`` mapped through the curve equation modulo the base field."""

    rhs = (int(x) ** 3 + int(a4) * int(x) + int(a6)) % SECP256K1_PRIME
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


def _process_curve_worker(task: Tuple[str, int, int]) -> Optional[CurveBatchResult]:
    """Worker entry point executed inside a process pool."""

    name, a4, a6 = task
    curve = EllipticCurve(base_field, [a4, a6])
    rhs = _rhs_for_curve(a4, a6, PUBX)
    root = tonelli_shanks_batch([rhs], SECP256K1_PRIME)[0]
    if root is None:
        return None

    order = int(curve.order())
    if order < MIN_PRIME_SIZE:
        return None

    try:
        factors = (
            ecm.factor(order) if order > 10**20 else factor(order)  # type: ignore[attr-defined]
        )
    except Exception:
        return None

    subgroup_candidates = [
        (int(p), int(e))
        for p, e in factors
        if MIN_PRIME_SIZE <= int(p) < THRESHOLD
    ]
    if not subgroup_candidates:
        return None

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

                if (
                    _ENDOMORPHISM_BETA is not None
                    and _ENDOMORPHISM_LAMBDA is not None
                ):
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

    if not partials:
        return None

    unique = _unique_partials(partials)
    if not unique:
        return None

    return CurveBatchResult(name=name, order=order, partials=unique)


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
        process.cpu_affinity(list(range(cpu_count())))
    except Exception:
        pass

    show_glitch_logo()
    console.print(
        f"\nStarting attack on public key ({PUBX:X}, {PUBY:X})...",
        style="bold bright_white",
    )
    console.print("CUDA Acceleration: Disabled (CPU edition)")
    console.print(f"Sound Effects: {'Enabled' if SOUND_ENABLED else 'Disabled'}")

    start_time = time.time()
    coverage_history: List[Tuple[float, float]] = []
    all_results: List[CurveBatchResult] = []

    curves = generate_twist_curves()
    console.print(f"Generated {len(curves)} twist curves")

    tasks = list(curves.items())
    last_save = start_time

    with Progress(transient=True) as progress:
        task_id = progress.add_task("Processing curves", total=len(tasks))

        with ProcessPoolExecutor(max_workers=cpu_count()) as executor:
            future_to_name = {
                executor.submit(_process_curve_worker, (name, a4, a6)): name
                for name, (a4, a6) in tasks
            }

            for future in as_completed(future_to_name):
                progress.advance(task_id, 1)
                name = future_to_name[future]
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive logging
                    console.print(f"[red]Worker failure on {name}: {exc}")
                    continue

                if result is not None:
                    all_results.append(result)

                elapsed = time.time() - start_time
                coverage_bits = compute_coverage(all_results)
                coverage_history.append((elapsed, coverage_bits))

                if time.time() - last_save > SAVE_INTERVAL:
                    save_progress(all_results, coverage_history)
                    last_save = time.time()

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
