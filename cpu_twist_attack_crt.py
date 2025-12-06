#!/usr/bin/env python3
"""CPU optimised twist attack with CRT recovery - IMPROVED RESIDUE DETECTION AND POWER"""
from __future__ import annotations
import json
import os
import random
import sys
import time
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from functools import reduce
from math import gcd
from multiprocessing import cpu_count
from typing import Dict, List, Optional, Sequence, Tuple

# Rich imports for visual effects
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.table import Table

# SageMath imports
try:
    from sage.all import (
        EllipticCurve,
        GF,
        ZZ,
        discrete_log,
        randint,
        set_random_seed,
        kronecker_symbol,
    )
    SAGE_AVAILABLE = True
except ImportError:
    SAGE_AVAILABLE = False

# Configuration
set_random_seed(int(time.time()))

# Default parameters
SECP256K1_PRIME = ZZ(2**256 - 2**32 - 977)
SECP256K1_ORDER = ZZ(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
PUBX = ZZ("3BB421D32A069F078CFDFD56CDC1391FBD87E4183CA94458E3F5C4C8945782BE", 16)
PUBY = ZZ("D3210A2119E7C24ED38094B450D571D06285A66FD7AFFC1107407E55E9843FEB", 16)
public_key = (int(PUBX), int(PUBY))
base_field = GF(SECP256K1_PRIME)
secp256k1 = EllipticCurve(base_field, [0, 7])

# Attack parameters - INCREASED RANGES AND POWERS
THRESHOLD = ZZ(2**50)          # Increased threshold for larger subgroups
MIN_PRIME_SIZE = ZZ(2**12)     # Increased minimum prime size
TARGET_CURVES = 1000           # More curves for better coverage
BATCH_SIZE = 50                # Larger batches for parallel processing
WORKERS = min(16, cpu_count()) # More workers for faster processing
MIN_CURVE_ORDER = 50           # Lowered minimum curve order for more candidates
MAX_SUBGROUP_PRIME = 5000      # Upper bound for subgroup search

# Console for rich output
console = Console()

# --- Enhanced Visual Effects ---
def glitch_text(text: str) -> str:
    """Generate RGB glitch-styled text"""
    glitch_chars: List[str] = []
    color_palette = ["bright_red", "bright_blue", "bright_green", "bright_magenta"]

    for char in text:
        if random.random() > 0.8:
            color = random.choice(color_palette)
            glitch_chars.append(f"[{color}]{char}[/]")
        else:
            glitch_chars.append(f"[bright_white]{char}[/]")
    return "".join(glitch_chars)

def animated_banner():
    """Show animated glitch banner"""
    console.clear()

    banner = """
    ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ████████╗
    ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
    ██████╔╝██║   ██║██║  ██║██████╔╝██║   ██║   ██║
    ██╔══██╗██║   ██║██║  ██║██╔══██╗██║   ██║   ██║
    ██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝   ██║
    ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
    """

    for _ in range(2):
        console.clear()
        glitched = Text.from_markup(glitch_text(banner))
        panel = Panel.fit(
            glitched,
            title="[blink bright_green]BUDBOT333 TWIST ATTACK ENGINE[/]",
            subtitle="[bright_black]v4.0.0 | ENHANCED RESIDUE DETECTION & POWER[/]",
            border_style="bright_green",
            padding=(1, 3),
        )
        console.print(panel, justify="center")
        time.sleep(0.1)

    console.print()

# --- CRT Recovery Functions ---
def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a, m):
    """Modular inverse"""
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

def chinese_remainder_theorem(remainders, moduli):
    """Chinese Remainder Theorem implementation"""
    if not remainders:
        return 0

    result = remainders[0] % moduli[0]
    current_mod = moduli[0]

    for i in range(1, len(remainders)):
        r = remainders[i] % moduli[i]
        m = moduli[i]

        if gcd(current_mod, m) != 1:
            console.print(f"[yellow]Skipping non-coprime moduli: {current_mod} and {m}[/]")
            continue

        inv = mod_inverse(current_mod, m)
        result = result + (r - result) * inv % m * current_mod
        current_mod = current_mod * m

    return result % current_mod

def save_remainders_to_file(remainders, moduli, filename="crt_remainders.txt"):
    """Save residues to file"""
    with open(filename, "w") as f:
        f.write("# Residues from enhanced twist attack\n")
        f.write("# Format: residue,modulus\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for r, m in zip(remainders, moduli):
            f.write(f"{r},{m}\n")

def save_detailed_results(all_results, filename="detailed_results.json"):
    """Save detailed results to JSON"""
    with open(filename, "w") as f:
        json.dump(
            {
                "curves_analyzed": len(all_results),
                "residues_found": sum(len(result.partials) for result in all_results),
                "results": [
                    {
                        "curve": result.name,
                        "order": result.order,
                        "residues": [
                            {
                                "residue": p.residue,
                                "modulus": p.modulus,
                                "source": p.source,
                                "verified": p.verified,
                            }
                            for p in result.partials
                        ],
                    }
                    for result in all_results
                ],
            },
            f,
            indent=2,
        )

# --- Core Attack Functions ---
@dataclass
class PartialResidue:
    residue: int
    modulus: int
    source: str
    verified: bool

@dataclass
class CurveResult:
    name: str
    order: int
    partials: List[PartialResidue]


def find_small_prime_factors(n: int, limit: int) -> List[int]:
    """Find small prime factors of ``n`` up to ``limit`` using trial division.

    This avoids full integer factorization (which is often infeasible for large
    twist orders) while still surfacing the small subgroup candidates we care
    about for discrete-log residue extraction.
    """

    factors: List[int] = []
    candidate = 2

    while candidate * candidate <= n and candidate <= limit:
        if n % candidate == 0:
            factors.append(candidate)
            while n % candidate == 0:
                n //= candidate
        candidate = 3 if candidate == 2 else candidate + 2

    if n > 1 and n <= limit:
        factors.append(int(n))

    return factors


def derive_subgroup_generator(curve, cofactor: int, subgroup_order: int):
    """Derive a generator for the subgroup of order ``subgroup_order``.

    We repeatedly sample random points, scale by the cofactor, and keep the
    first non-zero point that has the desired order. This is more resilient
    than relying on ``curve.gens()[0]`` directly belonging to the subgroup.
    """

    for _ in range(16):
        candidate = cofactor * curve.random_point()
        if candidate.is_zero():
            continue

        order = candidate.order()
        if order == subgroup_order:
            return candidate

        # If the order divides the subgroup order, attempt to scale up.
        if subgroup_order % order == 0:
            scaled = (subgroup_order // order) * candidate
            if not scaled.is_zero() and scaled.order() == subgroup_order:
                return scaled

    return None

def tonelli_shanks(n: int, p: int) -> Optional[int]:
    """Tonelli-Shanks algorithm for modular square roots"""
    if p == 2:
        return n % 2

    n = n % p
    if n == 0:
        return 0

    if pow(n, (p - 1) // 2, p) != 1:
        return None

    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)

    while t != 1:
        i = 1
        while pow(t, 2**i, p) != 1:
            i += 1

        b = pow(c, 2**(M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p

    return R

def generate_twist_curves(num_curves: int) -> Dict[str, Tuple[int, int]]:
    """Generate twist curves - IMPROVED for better variety and power"""
    console.print("[bright_cyan]»[/] [white]Generating diverse twist curves...[/]")

    curves: Dict[str, Tuple[int, int]] = {}
    seeds_to_try = set()

    # Strategy 1: Small integers
    seeds_to_try.update(range(2, min(2000, num_curves * 10)))

    # Strategy 2: Random seeds in a larger range
    seeds_to_try.update(random.sample(range(-50000, 50000), min(1000, num_curves)))

    # Strategy 3: Small primes and their negatives
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    seeds_to_try.update(small_primes + [-p for p in small_primes])

    # Strategy 4: Prime powers (e.g., 2^3, 3^2, etc.)
    seeds_to_try.update([p**2 for p in small_primes if p**2 < 5000])
    seeds_to_try.update([p**3 for p in small_primes if p**3 < 5000])

    # Strategy 5: Random large primes
    seeds_to_try.update([randint(1000, 50000) for _ in range(min(200, num_curves))])

    console.print(f"[grey]Using {len(seeds_to_try)} unique seeds[/]")

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_yellow"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Twisting curves...", total=num_curves)

        for seed in seeds_to_try:
            if len(curves) >= num_curves:
                break

            try:
                twist = secp256k1.quadratic_twist(seed)
                twist_order = int(twist.order())

                if twist_order != int(SECP256K1_ORDER):
                    a4 = int(twist.a4())
                    a6 = int(twist.a6())

                    x_val = int(PUBX)
                    rhs = (x_val**3 + a4 * x_val + a6) % int(SECP256K1_PRIME)

                    legendre = pow(rhs, (int(SECP256K1_PRIME) - 1) // 2, int(SECP256K1_PRIME))
                    if legendre == 1:
                        name = f"twist_{seed}"
                        curves[name] = (a4, a6)
                        progress.advance(task)

            except Exception as e:
                console.print(f"[red]Error generating curve for seed {seed}: {e}[/]")

    console.print(f"[bold green]✓[/] Generated [white]{len(curves)}[/] twist curves")
    return curves

def analyze_curve_for_subgroups(name: str, a4: int, a6: int) -> Optional[CurveResult]:
    """Analyze a single curve for small subgroups - IMPROVED VERSION with increased power"""
    try:
        curve = EllipticCurve(base_field, [a4, a6])
        order = int(curve.order())

        if order < MIN_CURVE_ORDER:
            console.print(f"[grey]Skipping {name}: order {order} < {MIN_CURVE_ORDER}[/]")
            return None

        x_val = int(PUBX)
        rhs = (x_val**3 + a4 * x_val + a6) % int(SECP256K1_PRIME)

        y_candidate = tonelli_shanks(rhs, int(SECP256K1_PRIME))
        if y_candidate is None:
            return None

        partials = []

        for y_val in [y_candidate, (-y_candidate) % int(SECP256K1_PRIME)]:
            try:
                point = curve((x_val, y_val))

                factors = find_small_prime_factors(order, MAX_SUBGROUP_PRIME)

                for p_int in factors:
                    if p_int < 10:
                        continue

                    try:
                        cofactor = order // p_int
                        if cofactor == 0:
                            continue

                        subgroup_point = cofactor * point
                        if subgroup_point.is_zero():
                            continue

                        subgroup_gen = derive_subgroup_generator(curve, cofactor, p_int)
                        if subgroup_gen is None:
                            console.print(
                                f"[yellow]Unable to derive subgroup generator of order {p_int} for {name}[/]"
                            )
                            continue

                        dl = discrete_log(
                            subgroup_point,
                            subgroup_gen,
                            ord=p_int,
                            operation='+'
                        )

                        residue = int(dl) % p_int

                        if residue * subgroup_gen == subgroup_point:
                            partials.append(
                                PartialResidue(
                                    residue=residue,
                                    modulus=p_int,
                                    source=name,
                                    verified=True
                                )
                            )

                    except Exception as e:
                        console.print(f"[red]Error in discrete log for {name}: {e}[/]")

            except Exception as e:
                console.print(f"[red]Error analyzing curve {name}: {e}[/]")

        if partials:
            return CurveResult(name=name, order=order, partials=partials)

    except Exception as e:
        console.print(f"[red]Error in analyze_curve_for_subgroups for {name}: {e}[/]")

    return None

def process_batch_simple(batch: List[Tuple[str, int, int]]) -> List[CurveResult]:
    """Process a batch of curves - SIMPLIFIED for reliability"""
    results = []

    for name, a4, a6 in batch:
        result = analyze_curve_for_subgroups(name, a4, a6)
        if result:
            results.append(result)

    return results

def validate_private_key(d: int, pubx: int, puby: int) -> bool:
    """Validate a private key against the public key"""
    P = d * secp256k1.gens()[0]
    return int(P[0]) == pubx and int(P[1]) == puby

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Twist Attack with CRT Recovery")
    parser.add_argument("--pubx", type=str, help="Public key x-coordinate (hex)")
    parser.add_argument("--puby", type=str, help="Public key y-coordinate (hex)")
    parser.add_argument("--target-curves", type=int, default=TARGET_CURVES, help="Number of twist curves to generate")
    parser.add_argument("--workers", type=int, default=WORKERS, help="Number of worker processes")
    parser.add_argument("--min-curve-order", type=int, default=MIN_CURVE_ORDER, help="Minimum curve order to consider")
    return parser.parse_args()

def main():
    """Main attack routine - SIMPLIFIED AND MORE RELIABLE"""
    args = parse_args()

    global PUBX, PUBY, TARGET_CURVES, WORKERS, MIN_CURVE_ORDER
    PUBX = ZZ(args.pubx, 16) if args.pubx else ZZ("3BB421D32A069F078CFDFD56CDC1391FBD87E4183CA94458E3F5C4C8945782BE", 16)
    PUBY = ZZ(args.puby, 16) if args.puby else ZZ("D3210A2119E7C24ED38094B450D571D06285A66FD7AFFC1107407E55E9843FEB", 16)
    TARGET_CURVES = args.target_curves
    WORKERS = args.workers
    MIN_CURVE_ORDER = args.min_curve_order

    animated_banner()

    # Show attack parameters
    console.print("[bright_cyan]»[/] [white]Attack Configuration:[/]")
    console.print(f"  [cyan]Target Public Key:[/]")
    console.print(f"    [grey]x =[/] {hex(int(PUBX))}")
    console.print(f"    [grey]y =[/] {hex(int(PUBY))}")
    console.print(f"  [cyan]Attack Parameters:[/]")
    console.print(f"    [grey]Target curves:[/] {TARGET_CURVES}")
    console.print(f"    [grey]Min subgroup:[/] 10")
    console.print(f"    [grey]Max subgroup:[/] 5000")
    console.print(f"    [grey]Workers:[/] {WORKERS}")
    console.print(f"    [grey]Min curve order:[/] {MIN_CURVE_ORDER}")
    console.print()

    start_time = time.time()

    # Generate curves
    console.print("[bright_cyan]»[/] [white]Phase 1: Curve Generation[/]")
    curves = generate_twist_curves(TARGET_CURVES)

    if not curves or len(curves) < 10:
        console.print("[bold red]✗[/] Not enough curves generated!")
        console.print("[yellow]Try running again or adjust parameters[/]")
        return

    # Prepare batches
    items = list(curves.items())
    batches = []
    for i in range(0, len(items), BATCH_SIZE):
        batch = [(name, a4, a6) for name, (a4, a6) in items[i:i+BATCH_SIZE]]
        batches.append(batch)

    # Process curves
    console.print("\n[bright_cyan]»[/] [white]Phase 2: Subgroup Analysis[/]")

    all_results = []
    residues = []
    moduli = []
    found_count = 0

    with Progress(
        SpinnerColumn(spinner_name="bouncingBall", style="bright_magenta"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[grey]{task.fields[found]}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[green]Searching for small subgroups...",
            total=len(batches),
            found="Found: 0 residues"
        )

        with ProcessPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(process_batch_simple, batch) for batch in batches]

            for future in as_completed(futures, timeout=60):
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)

                    for result in batch_results:
                        found_count += len(result.partials)
                        for partial in result.partials:
                            if partial.verified:
                                residues.append(partial.residue)
                                moduli.append(partial.modulus)

                    progress.update(
                        task,
                        advance=1,
                        found=f"Found: {found_count} residues"
                    )

                except Exception as e:
                    progress.update(task, advance=1)
                    console.print(f"[red]Batch failed: {e}[/]")

    # Remove duplicates
    unique_data = {}
    for r, m in zip(residues, moduli):
        if m not in unique_data:
            unique_data[m] = r

    residues = list(unique_data.values())
    moduli = list(unique_data.keys())

    # Show results
    elapsed = time.time() - start_time

    console.print("\n" + "═" * 60)
    console.print("[bold bright_green]» RESULTS SUMMARY[/]")
    console.print("═" * 60)

    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="bright_white")

    table.add_row("Curves Generated", f"{len(curves)}")
    table.add_row("Curves with Residues", f"{len(all_results)}")
    table.add_row("Unique Residues", f"{len(residues)}")
    table.add_row("Time", f"{elapsed:.2f}s")

    if residues:
        table.add_row("Residues/sec", f"{len(residues)/elapsed:.2f}")
        if len(residues) <= 10:
            table.add_row("Sample Residues", ", ".join(str(r) for r in residues[:5]))

    console.print(table)

    if not residues:
        console.print("\n[bold yellow]⚠ No residues found[/]")
        console.print("[yellow]This could mean:[/]")
        console.print("  1. The curves don't have suitable small subgroups")
        console.print("  2. The public key doesn't map to those subgroups")
        console.print("  3. The discrete log computation failed")
        console.print("\n[yellow]Suggestions:[/]")
        console.print("  • Increase TARGET_CURVES (try 1000+)")
        console.print("  • Try different seed values")
        console.print("  • Adjust MIN/MAX subgroup sizes")
        return

    # Save results
    console.print("\n[bright_cyan]»[/] [white]Saving results...[/]")
    save_remainders_to_file(residues, moduli)
    save_detailed_results(all_results)
    console.print(f"[bold green]✓[/] Saved to [white]crt_remainders.txt[/] and [white]detailed_results.json[/]")

    # Try CRT if we have enough residues
    if len(residues) >= 3:
        console.print("\n[bright_cyan]»[/] [white]Phase 3: CRT Recovery Attempt[/]")

        try:
            recovered = chinese_remainder_theorem(residues, moduli)
            recovered_hex = hex(recovered)[2:].upper()

            console.print("[green]CRT Recovery:[/]")
            console.print(f"  [grey]Result:[/] {recovered_hex[:64]}..." if len(recovered_hex) > 64 else f"  [grey]Result:[/] {recovered_hex}")
            console.print(f"  [grey]Using:[/] {len(residues)} congruences")

            if recovered < 2**256:
                console.print(f"  [grey]Size:[/] {recovered.bit_length()} bits")

                if validate_private_key(recovered, int(PUBX), int(PUBY)):
                    console.print("\n[bold green]████████████████████████████████████████[/]")
                    console.print("[bold green]█     PRIVATE KEY RECOVERED!      █[/]")
                    console.print("[bold green]████████████████████████████████████████[/]")

                    with open("PRIVATE_KEY_FOUND.txt", "w") as f:
                        f.write(f"Private Key: {recovered_hex}\n")

                    console.print(f"[green]Saved to PRIVATE_KEY_FOUND.txt[/]")
                else:
                    console.print("\n[yellow]Recovered value doesn't match public key[/]")
                    console.print("[yellow]This is expected - we need more residues[/]")

                    with open("partial_recovery.txt", "w") as f:
                        f.write(f"Partial recovery: {recovered_hex}\n")
                        f.write(f"Using {len(residues)} residues\n")

            else:
                console.print("\n[yellow]Recovered value too large[/]")

        except Exception as e:
            console.print(f"[red]CRT failed: {e}[/]")

    # Coverage analysis
    if moduli:
        console.print("\n" + "═" * 60)
        console.print("[bold bright_cyan]» COVERAGE ANALYSIS[/]")
        console.print("═" * 60)

        product = 1
        for m in moduli:
            product = product * m // gcd(product, m)

        bits = product.bit_length()
        percent = (bits / 256) * 100

        coverage_table = Table(show_header=False, box=None)
        coverage_table.add_column("", style="cyan")
        coverage_table.add_column("", style="white")

        coverage_table.add_row("Bits Covered", f"{bits}")
        coverage_table.add_row("Percentage", f"{percent:.1f}%")
        coverage_table.add_row("Remaining", f"{256 - bits}")

        if percent >= 100:
            coverage_table.add_row("Status", "[green]✓ Sufficient[/]")
        elif percent >= 50:
            coverage_table.add_row("Status", "[yellow]° Getting there[/]")
        else:
            coverage_table.add_row("Status", "[red]⚠ More needed[/]")

        console.print(coverage_table)

    console.print("\n" + "=" * 60)
    console.print("[bold green]» ATTACK COMPLETE[/]")
    console.print("=" * 60)

if __name__ == "__main__":
    if not SAGE_AVAILABLE:
        console = Console()
        console.print("[red]ERROR: SageMath is required for this attack.[/]")
        sys.exit(1)

    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted[/]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")
        import traceback
        traceback.print_exc()
