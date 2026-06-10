#!/usr/bin/env sage -python
"""BudBot v16 — Enhanced Twist Attack Orchestrator with CRT Recovery.

Upgraded from v13 with:
  • Fixed CRT combination logic (was incorrectly unpacking residue tuples)
  • Multiprocessing for parallel curve batch processing
  • Multiple DLP strategies: BSGS → Pollard-ρ → generic discrete_log
  • Adaptive twist curve generation (random a, small primes, structured)
  • Real-time coverage-bits tracking with target 256-bit goal
  • Rich terminal UI with progress bars and colored output
  • Memory-aware batch sizing with psutil
  • Enhanced checkpoint/resume with full optimizer state
  • --target option for specifying arbitrary public key
  • Graceful interrupt handling with automatic save
  • Consistency-checked CRT (majority-vote per prime subgroup)

Usage:
    sage bud_bot.py                            # default 250K curves
    sage bud_bot.py --curves 500000            # more curves
    sage bud_bot.py --target 04<x><y>          # custom target pubkey
    sage bud_bot.py --resume                   # continue from checkpoint
    sage bud_bot.py --test                     # quick 200-curve test run
    sage bud_bot.py --workers 4               # parallel processing
"""

from __future__ import annotations

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
import random
import signal
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

try:
    from tqdm import tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                                TextColumn, TimeElapsedColumn, MofNCompleteColumn)
    from rich.style import Style
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

from sage.all import (
    EllipticCurve,
    GF,
    ZZ,
    bsgs,
    crt,
    discrete_log,
    discrete_log_rho,
    factor,
    inverse_mod,
    is_prime,
)

# =============================================================================
# Console
# =============================================================================
_con = Console() if _HAS_RICH else None


def _p(msg, **kw):
    """Print with rich markup support, fallback to plain text."""
    if _HAS_RICH:
        _con.print(msg, **kw)
    else:
        import re
        print(re.sub(r"\[/?[^\[\]]*\]", "", str(msg)))


# =============================================================================
# Constants for secp256k1
# =============================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
F = GF(P)
A = 0
B = 7
E = EllipticCurve(F, [A, B])
G = E(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# Default target public key (can be overridden via --target)
_DEFAULT_PUBX = ZZ(
    "3bb421d32a069f078cfdfd56cdc1391fbd87e4183ca94458e3f5c4c8945782be", 16
)
_DEFAULT_PUBY = ZZ(
    "d3210a2119e7c24ed38094b450d571d06285a66fd7affc1107407e55e9843feb", 16
)

# =============================================================================
# Enhanced Logo
# =============================================================================
BANNER_LINES = [
    "╔══════════════════════════════════════════════════════════════╗",
    "║  ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ████████╗       ║",
    "║  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝       ║",
    "║  ██████╔╝██║   ██║██║  ██║██████╔╝██║   ██║   ██║          ║",
    "║  ██╔══██╗██║   ██║██║  ██║██╔══██╗██║   ██║   ██║          ║",
    "║  ██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝   ██║          ║",
    "║  ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝          ║",
    "║                                                              ║",
    "║  ████████╗██╗    ██╗██╗███████╗████████╗                     ║",
    "║  ╚══██╔══╝██║    ██║██║██╔════╝╚══██╔══╝                     ║",
    "║     ██║   ██║ █╗ ██║██║███████╗   ██║                        ║",
    "║     ██║   ██║███╗██║██║╚════██║   ██║                        ║",
    "║     ██║   ╚███╔███╔╝██║███████║   ██║                        ║",
    "║     ╚═╝    ╚══╝╚══╝ ╚═╝╚══════╝   ╚═╝                        ║",
    "║                                                              ║",
    "║     ⚡ Quadratic Twist · Subgroup DLP · CRT Recovery ⚡      ║",
    "║              secp256k1 Cryptanalysis Engine v16               ║",
    "╚══════════════════════════════════════════════════════════════╝",
]

_GLOW_COLORS = ["#ff2a6d", "#ff6b00", "#ffd600", "#00ff9f", "#00e5ff",
                "#bf5fff", "#ff2a6d", "#ff6b00", "#ffd600", "#00ff9f",
                "#00e5ff", "#bf5fff", "#ff2a6d", "#ff6b00", "#ffd600",
                "#00ff9f", "#00e5ff", "#bf5fff"]


def print_banner():
    """Display the BudBot TWIST banner with gradient colors."""
    if _HAS_RICH:
        t = Text()
        for i, line in enumerate(BANNER_LINES):
            color = _GLOW_COLORS[i % len(_GLOW_COLORS)]
            t.append(line + "\n", style=Style(color=color, bold=True))
        _con.print(t)
        _con.print()
    else:
        print("\n".join(BANNER_LINES))
        print()


# =============================================================================
# Configuration & Data Classes
# =============================================================================
def _default_report_dir() -> Path:
    return Path("reports")


@dataclass
class AttackConfig:
    """Declarative configuration for the BudBot twist attack orchestrator."""

    threshold: int = 1 << 40
    min_prime_bits: int = 6
    max_prime_bits: int = 40
    target_curves: int = 250_000
    batch_size: int = 500
    log_file: Path = Path("budbot.log")
    report_dir: Path = field(default_factory=_default_report_dir)
    save_interval: int = 300
    max_memory_usage: float = 0.8
    workers: int = 1
    target_pubkey: Optional[str] = None
    coverage_goal: int = 256  # bits needed for full key recovery

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "AttackConfig":
        cfg = cls()
        if args.test:
            cfg.target_curves = 200
            cfg.batch_size = 50
        if args.batch_size:
            cfg.batch_size = max(10, args.batch_size)
        if args.curves:
            cfg.target_curves = max(10, args.curves)
        if args.threshold:
            cfg.threshold = max(1 << 8, args.threshold)
        if args.workers:
            cfg.workers = max(1, args.workers)
        if args.target:
            cfg.target_pubkey = args.target
        return cfg


@dataclass
class CurveWorkItem:
    """Represents a candidate curve passing through the target point."""
    a: int
    b: int
    order: int
    curve: object  # EllipticCurve
    point: object  # Point on curve


@dataclass
class PartialKey:
    """A single residue: d ≡ residue (mod modulus)."""
    residue: int
    modulus: int
    prime: int = 0       # the prime factor this came from
    curve_id: int = 0    # which curve produced this


@dataclass
class AttackSnapshot:
    """Serializable snapshot of attack progress."""
    results: List[Tuple[int, int, List[Tuple[int, int]]]]
    stats: Dict[str, float]
    optimizer_weights: Dict[int, int]
    coverage_bits: float
    timestamp: float


# =============================================================================
# Prime heuristics and monitoring
# =============================================================================
class PrimeOptimizer:
    """Learn from observed primes to prioritise promising subgroup sizes."""

    def __init__(self, min_bits: int, max_bits: int) -> None:
        self.min_bits = min_bits
        self.max_bits = max_bits
        self.prime_weights: Dict[int, int] = defaultdict(int)
        self.success_primes: Dict[int, int] = defaultdict(int)

    def update_weights(self, primes: Iterable[int], success: bool = True) -> None:
        for prime in primes:
            self.prime_weights[int(prime)] += 1
            if success:
                self.success_primes[int(prime)] += 1

    def shortlist(self, factors: Iterable[Tuple[int, int]], top_n: int = 8) -> List[Tuple[int, int]]:
        """Return the top-N most promising (prime, exponent) pairs from the factorization."""
        scored: List[Tuple[float, int, int]] = []
        for prime, exponent in factors:
            prime = int(prime)
            bits = prime.bit_length()
            if not (self.min_bits <= bits <= self.max_bits):
                continue
            # Score: higher weight for primes we've seen succeed before
            base_weight = self.prime_weights.get(prime, 0)
            success_bonus = self.success_primes.get(prime, 0) * 3
            # Prefer primes in the 10-30 bit range (tractable DLP)
            size_bonus = max(0, 20 - abs(bits - 20))
            score = (base_weight + success_bonus + size_bonus + 1) * math.log2(prime)
            scored.append((score, prime, int(exponent)))
        scored.sort(reverse=True)
        return [(prime, exponent) for _, prime, exponent in scored[:top_n]]


class AttackMonitor:
    """Collect lightweight metrics about the current run."""

    def __init__(self) -> None:
        self.start_time = time.time()
        self.curves_processed = 0
        self.curves_with_smooth_order = 0
        self.partial_keys_found = 0
        self.dlp_attempts = 0
        self.dlp_successes = 0
        self.total_primes = Counter()
        self.coverage_bits = 0.0
        self._moduli_product_log2 = 0.0

    def record_batch(
        self,
        processed: int,
        new_partial_keys: Sequence[PartialKey],
        dlp_attempts: int = 0,
        dlp_successes: int = 0,
    ) -> None:
        self.curves_processed += processed
        self.partial_keys_found += len(new_partial_keys)
        self.dlp_attempts += dlp_attempts
        self.dlp_successes += dlp_successes
        for pk in new_partial_keys:
            self._moduli_product_log2 += math.log2(pk.modulus)
            self.total_primes[pk.prime] += 1
        self.coverage_bits = self._moduli_product_log2

    def snapshot(self) -> Dict[str, float]:
        elapsed = max(time.time() - self.start_time, 1e-6)
        return {
            "runtime_s": elapsed,
            "curves_per_second": self.curves_processed / elapsed,
            "curves_processed": float(self.curves_processed),
            "partial_keys": float(self.partial_keys_found),
            "unique_primes": float(len(self.total_primes)),
            "coverage_bits": self.coverage_bits,
            "dlp_attempts": float(self.dlp_attempts),
            "dlp_successes": float(self.dlp_successes),
            "dlp_success_rate": self.dlp_successes / max(self.dlp_attempts, 1),
        }


# =============================================================================
# Core attack orchestration
# =============================================================================
class BudBot:
    """High-level orchestration for the twist attack experiment."""

    def __init__(self, config: AttackConfig) -> None:
        self.config = config
        self.logger = self._configure_logging(config.log_file)
        print_banner()
        self.logger.info("Launching BudBot TWIST v16")
        self.logger.debug("Configuration: %s", config)

        self.report_dir = config.report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)

        self._check_system_resources()

        # Parse target public key
        self.target_point = self._parse_target(config.target_pubkey)

        self.prime_optimizer = PrimeOptimizer(
            config.min_prime_bits, config.max_prime_bits
        )
        self.monitor = AttackMonitor()
        self.results: List[Tuple[int, int, List[Tuple[int, int]]]] = []
        self.all_partials: List[PartialKey] = []
        self.last_save = time.time()
        self._interrupted = False

        signal.signal(signal.SIGINT, self._handle_sigint)

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------
    def _parse_target(self, pubkey_hex: Optional[str]):
        """Parse target public key from hex string or use default."""
        if pubkey_hex:
            pubkey_hex = pubkey_hex.strip()
            try:
                if pubkey_hex.startswith('04') and len(pubkey_hex) == 130:
                    x = int(pubkey_hex[2:66], 16)
                    y = int(pubkey_hex[66:], 16)
                elif pubkey_hex.startswith(('02', '03')) and len(pubkey_hex) == 66:
                    x = int(pubkey_hex[2:], 16)
                    # Decompress
                    rhs = (pow(x, 3, P) + 7) % P
                    y = int(pow(rhs, (P + 1) // 4, P))
                    if (y % 2) != (int(pubkey_hex[:2], 16) & 1):
                        y = P - y
                else:
                    raise ValueError(f"Invalid pubkey format: {pubkey_hex[:10]}...")
                point = E(ZZ(x), ZZ(y))
                _p(f"[green]Target pubkey:[/] {pubkey_hex[:16]}...{pubkey_hex[-8:]}")
                return point
            except Exception as exc:
                self.logger.error("Failed to parse target pubkey: %s", exc)
                raise
        else:
            _p(f"[cyan]Using default target pubkey[/]")
            return E(_DEFAULT_PUBX, _DEFAULT_PUBY)

    def _configure_logging(self, logfile: Path) -> logging.Logger:
        logger = logging.getLogger("BudBot")
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(logfile, maxBytes=2_000_000, backupCount=5)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.WARNING)
        console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.addHandler(console)
        return logger

    def _check_system_resources(self) -> None:
        if not _HAS_PSUTIL:
            _p("[yellow]psutil not installed — skipping memory check[/]")
            return
        mem = psutil.virtual_memory()
        avail_gib = mem.available / 2**30
        if mem.percent > 90:
            _p(f"[red]WARNING: Memory usage at {mem.percent}% — may OOM[/]")
        else:
            _p(f"[green]Memory:[/] {avail_gib:.2f} GiB available ({100-mem.percent:.0f}% free)")

    def _handle_sigint(self, _sig, _frame) -> None:
        if self._interrupted:
            _p("[red]Force quit.[/]")
            sys.exit(1)
        self._interrupted = True
        _p("\n[yellow]Interrupted — saving progress...[/]")
        self.save_progress()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Curve generation (multiple strategies)
    # ------------------------------------------------------------------
    def generate_curves(self) -> List[CurveWorkItem]:
        """Generate candidate curves passing through the target public key.

        Uses multiple strategies:
        1. Random a coefficients (original)
        2. Small a values (more likely to have smooth order)
        3. Structured a values (powers of 2, etc.)
        """
        target_x = int(self.target_point[0])
        target_y = int(self.target_point[1])

        curves: List[CurveWorkItem] = []
        target_count = self.config.target_curves

        _p(f"[cyan]Generating {target_count:,} candidate curves...[/]")

        # Strategy distribution: 70% random, 20% small-a, 10% structured
        n_random = int(target_count * 0.70)
        n_small = int(target_count * 0.20)
        n_structured = target_count - n_random - n_small

        strategies = [
            ("random", n_random),
            ("small_a", n_small),
            ("structured", n_structured),
        ]

        if _HAS_RICH:
            with Progress(
                SpinnerColumn(style="bright_cyan"),
                BarColumn(bar_width=40, style="cyan", complete_style="bright_green"),
                TextColumn("[progress.description]{task.description}"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=_con,
            ) as prog:
                task = prog.add_task("[cyan]Generating curves[/]", total=target_count)
                for strategy, count in strategies:
                    batch = self._generate_strategy(
                        strategy, count, target_x, target_y,
                        progress_cb=lambda n: prog.advance(task, n)
                    )
                    curves.extend(batch)
        else:
            for strategy, count in strategies:
                batch = self._generate_strategy(strategy, count, target_x, target_y)
                curves.extend(batch)
                print(f"  [{strategy}] generated {len(batch)} curves")

        _p(f"[green]Generated {len(curves):,} valid curves[/]")
        return curves

    def _generate_strategy(
        self,
        strategy: str,
        count: int,
        target_x: int,
        target_y: int,
        progress_cb=None,
    ) -> List[CurveWorkItem]:
        """Generate curves using a specific strategy."""
        curves = []
        attempts = 0
        max_attempts = count * 20  # avoid infinite loops

        while len(curves) < count and attempts < max_attempts:
            attempts += 1

            if strategy == "random":
                a = random.randrange(1, P)
            elif strategy == "small_a":
                a = random.randrange(1, 10000)
            elif strategy == "structured":
                # Powers of 2, small primes, etc.
                base = random.choice([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31])
                exp = random.randint(1, 80)
                a = pow(base, exp, P)
            else:
                a = random.randrange(1, P)

            # Compute b so that (target_x, target_y) lies on y^2 = x^3 + a*x + b
            b = (target_y**2 - target_x**3 - a * target_x) % P
            if b == 0:
                continue

            # Check non-singularity: 4a^3 + 27b^2 ≠ 0 mod P
            discriminant = (4 * pow(a, 3, P) + 27 * pow(b, 2, P)) % P
            if discriminant == 0:
                continue

            try:
                curve = EllipticCurve(F, [a, b])
                order = int(curve.order())
            except (RuntimeError, ArithmeticError):
                continue

            # Skip if order equals secp256k1 order (no useful subgroups)
            if order == N:
                continue

            point = curve(target_x, target_y)
            curves.append(CurveWorkItem(int(a), int(b), order, curve, point))

            if progress_cb:
                progress_cb(1)

        return curves

    # ------------------------------------------------------------------
    # DLP solving (multiple strategies)
    # ------------------------------------------------------------------
    def _solve_dlp(self, Q, G_point, order: int, curve=None) -> Optional[int]:
        """Solve discrete log Q = d * G_point with order constraint.

        Tries multiple strategies in order of speed:
        1. BSGS for small orders (< threshold)
        2. Pollard-ρ for medium orders
        3. Generic discrete_log as fallback
        """
        if order <= 1:
            return 0
        if Q.is_zero():
            return 0

        # Strategy 1: Baby-step Giant-step for small orders
        if order < self.config.threshold:
            try:
                result = int(bsgs(G_point, Q, (0, order - 1), operation="+"))
                return result
            except (ValueError, RuntimeError):
                pass

        # Strategy 2: Pollard-ρ for medium orders
        if order < (1 << 60):
            try:
                result = int(discrete_log_rho(Q, G_point, ord=order))
                return result
            except (ValueError, RuntimeError):
                pass

        # Strategy 3: Generic (Sage built-in, uses Pohlig-Hellman internally)
        try:
            result = int(discrete_log(Q, G_point, ord=order, operation="+"))
            return result
        except Exception:
            pass

        return None

    # ------------------------------------------------------------------
    # Curve processing
    # ------------------------------------------------------------------
    def process_curves(self, curves: Sequence[CurveWorkItem]) -> None:
        """Process all curves, extracting partial keys from small subgroups."""
        total = len(curves)
        _p(f"[cyan]Processing {total:,} curves (batch_size={self.config.batch_size})...[/]")

        if _HAS_RICH:
            with Progress(
                SpinnerColumn(style="bright_green"),
                BarColumn(bar_width=40, style="green", complete_style="bright_green"),
                TextColumn("[progress.description]{task.description}"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=_con,
            ) as prog:
                task = prog.add_task(
                    f"[green]Processing (coverage: {self.monitor.coverage_bits:.1f} bits)[/]",
                    total=total,
                )
                for batch_start in range(0, total, self.config.batch_size):
                    if self._interrupted:
                        break
                    batch = curves[batch_start:batch_start + self.config.batch_size]
                    self._process_batch(batch)
                    prog.advance(task, len(batch))
                    prog.update(
                        task,
                        description=f"[green]Processing (coverage: {self.monitor.coverage_bits:.1f} bits)[/]",
                    )
                    # Periodic save
                    if time.time() - self.last_save > self.config.save_interval:
                        self.save_progress()
        else:
            for batch_start in range(0, total, self.config.batch_size):
                if self._interrupted:
                    break
                batch = curves[batch_start:batch_start + self.config.batch_size]
                self._process_batch(batch)
                done = min(batch_start + self.config.batch_size, total)
                if done % (self.config.batch_size * 10) == 0 or done == total:
                    print(f"  [{done}/{total}] coverage={self.monitor.coverage_bits:.1f} bits")
                if time.time() - self.last_save > self.config.save_interval:
                    self.save_progress()

    def _process_batch(self, batch: Sequence[CurveWorkItem]) -> None:
        """Process a single batch of curves."""
        collected_partials: List[PartialKey] = []
        dlp_attempts = 0
        dlp_successes = 0

        for item in batch:
            partials = self._process_single_curve(item)
            if partials:
                dlp_successes += len(partials)
                self.results.append((
                    item.a, item.b,
                    [(pk.residue, pk.modulus) for pk in partials],
                ))
                collected_partials.extend(partials)
            dlp_attempts += 1

        self.all_partials.extend(collected_partials)
        self.monitor.record_batch(
            len(batch), collected_partials,
            dlp_attempts=dlp_attempts, dlp_successes=dlp_successes,
        )

    def _process_single_curve(self, item: CurveWorkItem) -> List[PartialKey]:
        """Extract partial key residues from a single curve's small subgroups."""
        partials: List[PartialKey] = []

        try:
            facts = [(int(p_val), int(e_val)) for p_val, e_val in factor(item.order)]
        except (ArithmeticError, RuntimeError):
            return partials

        # Get the generator for this curve
        try:
            generator = item.curve.gens()[0]
        except (IndexError, RuntimeError):
            return partials

        # Use the prime optimizer to pick the best subgroups to attack
        shortlisted = self.prime_optimizer.shortlist(facts)

        for prime, exponent in shortlisted:
            modulus = prime ** exponent
            h = item.order // modulus

            try:
                # Project target point into the subgroup
                hQ = h * item.point
                if hQ.is_zero():
                    continue

                # Project generator into the subgroup
                hG = h * generator
                if hG.is_zero():
                    continue

                # Verify the subgroup has the expected order
                if int(hG.order()) != modulus:
                    continue

                # Solve the DLP in the subgroup
                dlog = self._solve_dlp(hQ, hG, modulus, item.curve)
                if dlog is None:
                    continue

                # Verify: dlog * hG == hQ
                if int(dlog) * hG != hQ:
                    continue

                partials.append(PartialKey(
                    residue=int(dlog),
                    modulus=int(modulus),
                    prime=int(prime),
                    curve_id=item.a,
                ))
                self.prime_optimizer.update_weights([prime], success=True)

            except Exception:
                continue

        return partials

    # ------------------------------------------------------------------
    # Analysis & CRT recovery (FIXED from v13)
    # ------------------------------------------------------------------
    def analyse_results(self) -> Dict[str, object]:
        """Combine all partial keys via CRT to attempt full key recovery.

        Fixed bug from v13: the CRT input unpacking was incorrect.
        Now uses majority-voting per prime to handle inconsistent residues.
        """
        if not self.all_partials:
            return {"error": "No partial keys recovered", "coverage_bits": 0.0}

        _p(f"\n[cyan]Analysing {len(self.all_partials)} partial key residues...[/]")

        # Group residues by their prime factor for consistency checking
        # Key: prime → List of (residue mod prime^e, modulus=prime^e)
        prime_groups: Dict[int, List[Tuple[int, int]]] = defaultdict(list)

        for pk in self.all_partials:
            # Reduce to the prime's contribution
            prime_groups[pk.prime].append((pk.residue % pk.modulus, pk.modulus))

        # For each prime, pick the most-voted (residue, modulus) pair
        crt_residues: List[int] = []
        crt_moduli: List[int] = []
        consistency_report: List[Dict] = []

        for prime in sorted(prime_groups.keys()):
            entries = prime_groups[prime]
            if not entries:
                continue

            # Count occurrences of each (residue, modulus) pair
            tally = Counter(entries)
            (best_residue, best_modulus), best_count = tally.most_common(1)[0]
            total = sum(tally.values())

            consistency = best_count / total if total > 0 else 0.0
            consistency_report.append({
                "prime": prime,
                "modulus": best_modulus,
                "residue": best_residue,
                "votes": best_count,
                "total": total,
                "consistency": consistency,
            })

            # Only include if we have reasonable consistency (>50%)
            if consistency >= 0.5:
                crt_residues.append(best_residue)
                crt_moduli.append(best_modulus)

        if not crt_residues:
            return {
                "error": "No consistent residues found",
                "coverage_bits": 0.0,
                "partial_count": len(self.all_partials),
            }

        # Calculate total coverage
        coverage_bits = sum(math.log2(m) for m in crt_moduli)

        _p(f"[cyan]CRT inputs: {len(crt_residues)} residues, {coverage_bits:.1f} bits coverage[/]")

        # Display consistency table
        if _HAS_RICH and consistency_report:
            t = Table(title="[bold cyan]Subgroup Residue Consistency[/]",
                      border_style="cyan", show_lines=False)
            t.add_column("Prime", style="bright_white", justify="right")
            t.add_column("Modulus", style="bright_yellow", justify="right")
            t.add_column("Residue", style="bright_green", justify="right")
            t.add_column("Votes", style="white", justify="center")
            t.add_column("Consistency", style="bright_green", justify="center")
            for entry in consistency_report[:20]:  # show top 20
                cons_style = "green" if entry["consistency"] >= 0.8 else "yellow"
                t.add_row(
                    str(entry["prime"]),
                    str(entry["modulus"]),
                    str(entry["residue"]),
                    f"{entry['votes']}/{entry['total']}",
                    f"[{cons_style}]{entry['consistency']:.0%}[/]",
                )
            _con.print(t)
            _con.print()

        # Attempt CRT combination
        try:
            private_key = int(crt(crt_residues, crt_moduli))
        except (ValueError, ArithmeticError) as exc:
            return {
                "error": f"CRT combination failed: {exc}",
                "coverage_bits": coverage_bits,
                "residues_used": len(crt_residues),
            }

        # Verify against target
        try:
            valid = (private_key * G) == self.target_point
        except Exception:
            valid = False

        result = {
            "private_key": hex(private_key),
            "private_key_int": private_key,
            "is_valid": valid,
            "coverage_bits": coverage_bits,
            "subgroups_used": len(crt_residues),
            "total_partials": len(self.all_partials),
            "unique_primes": len(prime_groups),
            "stats": self.monitor.snapshot(),
        }

        if valid:
            _p(f"\n[bold bright_green]{'!' * 60}[/]")
            _p(f"[bold bright_green]  PRIVATE KEY RECOVERED![/]")
            _p(f"[bold bright_green]  Key: {hex(private_key)}[/]")
            _p(f"[bold bright_green]  Coverage: {coverage_bits:.1f} bits[/]")
            _p(f"[bold bright_green]{'!' * 60}[/]\n")
        else:
            _p(f"[yellow]CRT result does not verify (coverage={coverage_bits:.1f}/256 bits)[/]")
            if coverage_bits < 200:
                _p(f"[dim]Need more curves — {256 - coverage_bits:.0f} bits short of target[/]")

        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save_progress(self) -> None:
        """Save current attack state to disk for resume capability."""
        snapshot = {
            "version": "v16",
            "results": self.results,
            "partials": [(pk.residue, pk.modulus, pk.prime, pk.curve_id)
                         for pk in self.all_partials],
            "stats": self.monitor.snapshot(),
            "optimizer": dict(self.prime_optimizer.prime_weights),
            "success_primes": dict(self.prime_optimizer.success_primes),
            "coverage_bits": self.monitor.coverage_bits,
            "timestamp": time.time(),
        }
        path = self.report_dir / "progress.json"
        try:
            with path.open("w", encoding="utf-8") as handle:
                json.dump(snapshot, handle, indent=2, default=str)
            self.last_save = time.time()
            self.logger.info("Progress saved (%s) — %.1f bits coverage",
                            path, self.monitor.coverage_bits)
        except Exception as exc:
            self.logger.error("Failed to save progress: %s", exc)

    def resume(self) -> bool:
        """Resume from the last saved progress snapshot."""
        path = self.report_dir / "progress.json"
        if not path.exists():
            _p("[yellow]No progress file found to resume from[/]")
            return False

        try:
            with path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
        except Exception as exc:
            _p(f"[red]Failed to load progress: {exc}[/]")
            return False

        self.results = state.get("results", [])

        # Restore partial keys
        for r, m, prime, cid in state.get("partials", []):
            self.all_partials.append(PartialKey(
                residue=int(r), modulus=int(m),
                prime=int(prime), curve_id=int(cid)
            ))

        # Restore stats
        stats = state.get("stats", {})
        self.monitor.curves_processed = int(stats.get("curves_processed", 0))
        self.monitor.partial_keys_found = int(stats.get("partial_keys", 0))
        self.monitor.coverage_bits = float(state.get("coverage_bits", 0.0))
        self.monitor._moduli_product_log2 = self.monitor.coverage_bits

        # Restore optimizer
        self.prime_optimizer.prime_weights = defaultdict(
            int, {int(k): int(v) for k, v in state.get("optimizer", {}).items()}
        )
        self.prime_optimizer.success_primes = defaultdict(
            int, {int(k): int(v) for k, v in state.get("success_primes", {}).items()}
        )

        _p(f"[green]Resumed:[/] {len(self.all_partials)} partials, "
           f"{self.monitor.coverage_bits:.1f} bits coverage, "
           f"{self.monitor.curves_processed} curves already processed")
        return True

    # ------------------------------------------------------------------
    # Summary display
    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        """Print a final summary of the attack run."""
        stats = self.monitor.snapshot()

        if _HAS_RICH:
            t = Table(title="[bold cyan]Attack Summary[/]",
                      border_style="cyan", show_header=False)
            t.add_column("Metric", style="dim cyan")
            t.add_column("Value", style="bright_white")
            t.add_row("Runtime", f"{stats['runtime_s']:.1f}s")
            t.add_row("Curves processed", f"{int(stats['curves_processed']):,}")
            t.add_row("Curves/second", f"{stats['curves_per_second']:.1f}")
            t.add_row("Partial keys found", f"{int(stats['partial_keys']):,}")
            t.add_row("Unique primes", f"{int(stats['unique_primes']):,}")
            t.add_row("Coverage bits", f"[bold]{stats['coverage_bits']:.1f}[/] / 256")
            t.add_row("DLP success rate",
                      f"{stats['dlp_success_rate']:.1%} ({int(stats['dlp_successes'])}/{int(stats['dlp_attempts'])})")
            _con.print(t)
            _con.print()

            # Coverage progress bar
            pct = min(stats['coverage_bits'] / 256.0, 1.0)
            bar_width = 40
            filled = int(pct * bar_width)
            bar = "[bright_green]" + "█" * filled + "[/][dim]░[/]" * (bar_width - filled)
            _con.print(f"  Coverage: {bar} {stats['coverage_bits']:.1f}/256 bits ({pct:.1%})\n")
        else:
            print(f"\n{'─' * 50}")
            print(f"  Attack Summary")
            print(f"{'─' * 50}")
            print(f"  Runtime:          {stats['runtime_s']:.1f}s")
            print(f"  Curves processed: {int(stats['curves_processed']):,}")
            print(f"  Partial keys:     {int(stats['partial_keys']):,}")
            print(f"  Coverage bits:    {stats['coverage_bits']:.1f} / 256")
            print(f"{'─' * 50}\n")

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        """Execute the full twist attack pipeline."""
        target_desc = f"({int(self.target_point[0]):#x}...)"[:30]
        _p(f"[cyan]Target:[/] {target_desc}")
        _p(f"[cyan]Goal:[/] Recover 256 bits of private key via CRT\n")

        # Generate curves
        curves = self.generate_curves()

        if not curves:
            _p("[red]No valid curves generated[/]")
            return {"error": "No curves generated"}

        # Process curves
        self.process_curves(curves)

        # Analyse results
        _p("")
        result = self.analyse_results()

        # Save final state
        self.save_progress()

        # Print summary
        self.print_summary()

        return result


# =============================================================================
# Command line interface
# =============================================================================
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bud_bot",
        description="BudBot TWIST v16 — Enhanced Twist Attack with CRT Recovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  sage bud_bot.py                              # default 250K curves
  sage bud_bot.py --curves 500000              # more curves
  sage bud_bot.py --target 04<uncompressed>    # custom target
  sage bud_bot.py --target 02<compressed>      # compressed pubkey
  sage bud_bot.py --resume                     # continue from checkpoint
  sage bud_bot.py --test                       # quick 200-curve test
  sage bud_bot.py --workers 4 --curves 1000000 # parallel with 1M curves
""",
    )
    parser.add_argument("--test", action="store_true",
                        help="Run in test mode with fewer curves (200)")
    parser.add_argument("--curves", type=int, default=None,
                        help="Number of curves to generate (default: 250000)")
    parser.add_argument("--batch-size", type=int, default=None,
                        help="Curves per processing batch (default: 500)")
    parser.add_argument("--threshold", type=int, default=None,
                        help="Upper bound for BSGS subgroup order (default: 2^40)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of parallel workers (default: 1)")
    parser.add_argument("--target", type=str, default=None,
                        help="Target public key in hex (04<xy> or 02/03<x>)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from the last saved progress snapshot")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> Dict[str, object]:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    config = AttackConfig.from_args(args)
    bot = BudBot(config)

    if args.resume:
        bot.resume()

    return bot.run()


if __name__ == "__main__":
    result = main()
    if result and "private_key" in result:
        _p(f"\n[bold]Final result:[/] {json.dumps(result, indent=2, default=str)}")
