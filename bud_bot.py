#!/usr/bin/env sage -python
"""BudBot v13 - structured twist attack orchestration.

This module is an evolution of the previous "BudBot" proof-of-concept.  It
focuses on maintainability and observability while keeping the underlying
research functionality intact.  The refactor introduces:

* Declarative configuration via :class:`AttackConfig` with friendly CLI hooks.
* Structured logging with rotating log files instead of bespoke print helpers.
* Clear data-carrier classes for curve work items and partial key results.
* Periodic checkpointing that records both statistics and recovered residues.
* Unit-test-friendly design – most heavy logic now lives on instance methods
  that accept explicit dependencies rather than touching globals.

The heavy mathematical lifting still depends on SageMath; optional GPU support
can be layered back on top of this foundation in future iterations without
touching the orchestration logic.
"""

from __future__ import annotations

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import random
import signal
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import psutil
from tqdm import tqdm

from sage.all import (
    EllipticCurve,
    GF,
    ZZ,
    bsgs,
    crt,
    discrete_log_rho,
    factor,
)

# =============================================================================
# Constants for secp256k1
# =============================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
F = GF(P)
A = 0
B = 7
E = EllipticCurve(F, [A, B])
G = E(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

PUBX = ZZ(
    "3bb421d32a069f078cfdfd56cdc1391fbd87e4183ca94458e3f5c4c8945782be", 16
)
PUBY = ZZ(
    "d3210a2119e7c24ed38094b450d571d06285a66fd7affc1107407e55e9843feb", 16
)
TARGET = E(PUBX, PUBY)

BANNER = r"""
██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ████████╗
██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
██████╔╝██║   ██║██║  ██║██████╔╝██║   ██║   ██║   
██╔══██╗██║   ██║██║  ██║██╔══██╗██║   ██║   ██║   
██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝   ██║   
╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝    
"""


# =============================================================================
# Configuration & Data Classes
# =============================================================================


def _default_report_dir() -> Path:
    return Path("reports")


@dataclass(slots=True)
class AttackConfig:
    """Declarative configuration for the BudBot attack orchestrator."""

    threshold: int = 1 << 40
    min_prime_bits: int = 6
    target_curves: int = 250_000
    batch_size: int = 500
    log_file: Path = Path("budbot.log")
    report_dir: Path = field(default_factory=_default_report_dir)
    save_interval: int = 300
    max_memory_usage: float = 0.8

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "AttackConfig":
        cfg = cls()
        if args.test:
            cfg.target_curves = 200
        if args.batch_size:
            cfg.batch_size = max(10, args.batch_size)
        if args.curves:
            cfg.target_curves = max(10, args.curves)
        if args.threshold:
            cfg.threshold = max(1 << 8, args.threshold)
        return cfg

@dataclass(slots=True)
class CurveWorkItem:
    a: int
    b: int
    order: int
    curve: EllipticCurve
    point: object


@dataclass(slots=True)
class PartialKey:
    residue: int
    modulus: int


@dataclass(slots=True)
class AttackSnapshot:
    results: List[Tuple[int, int, List[Tuple[int, int]]]]
    stats: Dict[str, float]
    optimizer_weights: Dict[int, int]
    timestamp: float


# =============================================================================
# =============================================================================
# Prime heuristics and monitoring
# =============================================================================


class PrimeOptimizer:
    """Learn from observed primes to prioritise promising subgroup sizes."""

    def __init__(self, min_bits: int, max_bits: int) -> None:
        self.min_bits = min_bits
        self.max_bits = max_bits
        self.prime_weights: Dict[int, int] = defaultdict(int)

    def update_weights(self, primes: Iterable[int]) -> None:
        for prime in primes:
            self.prime_weights[int(prime)] += 1

    def shortlist(self, factors: Iterable[Tuple[int, int]], top_n: int = 5) -> List[Tuple[int, int]]:
        scored: List[Tuple[float, int, int]] = []
        for prime, exponent in factors:
            prime = int(prime)
            if not (self.min_bits <= prime.bit_length() <= self.max_bits):
                continue
            weight = self.prime_weights.get(prime, 1)
            scored.append((weight * math.log2(prime), prime, int(exponent)))
        scored.sort(reverse=True)
        return [(prime, exponent) for _, prime, exponent in scored[:top_n]]


class AttackMonitor:
    """Collect lightweight metrics about the current run."""

    def __init__(self) -> None:
        self.start_time = time.time()
        self.curves_processed = 0
        self.partial_keys = 0
        self.total_primes = Counter()

    def record_batch(
        self,
        processed: int,
        new_partial_keys: Sequence[PartialKey],
    ) -> None:
        self.curves_processed += processed
        self.partial_keys += len(new_partial_keys)
        for pk in new_partial_keys:
            for prime, _ in factor(pk.modulus):
                self.total_primes[int(prime)] += 1

    def snapshot(self) -> Dict[str, float]:
        elapsed = max(time.time() - self.start_time, 1e-6)
        return {
            "runtime": elapsed,
            "curves_per_second": self.curves_processed / elapsed,
            "curves_processed": float(self.curves_processed),
            "partial_keys": float(self.partial_keys),
            "unique_primes": float(len(self.total_primes)),
        }


# =============================================================================
# Core attack orchestration
# =============================================================================


class BudBot:
    """High-level orchestration for the twist attack experiment."""

    def __init__(self, config: AttackConfig) -> None:
        self.config = config
        self.logger = self._configure_logging(config.log_file)
        self.logger.info("\n%s", BANNER)
        self.logger.info("Launching BudBot v13")
        self.logger.debug("Configuration: %s", config)

        self.report_dir = config.report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)

        self._check_system_resources()

        self.prime_optimizer = PrimeOptimizer(
            config.min_prime_bits, int(math.log2(config.threshold))
        )
        self.monitor = AttackMonitor()
        self.results: List[Tuple[int, int, List[Tuple[int, int]]]] = []
        self.last_save = time.time()

        signal.signal(signal.SIGINT, self._handle_sigint)

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------
    def _configure_logging(self, logfile: Path) -> logging.Logger:
        logger = logging.getLogger("BudBot")
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(logfile, maxBytes=1_000_000, backupCount=3)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.addHandler(console)
        return logger

    def _check_system_resources(self) -> None:
        mem = psutil.virtual_memory()
        allowed = mem.total * self.config.max_memory_usage
        if mem.available < allowed:
            raise MemoryError("Insufficient free memory for requested workload")
        self.logger.info("Memory check passed (%.2f GiB available)", mem.available / 2**30)

    def _handle_sigint(self, _sig, _frame) -> None:  # pragma: no cover - signal handling
        self.logger.warning("Interrupted by user, saving progress ...")
        self.save_progress()
        sys.exit(1)

    # ------------------------------------------------------------------
    # Curve generation & validation
    # ------------------------------------------------------------------
    def generate_curves(self) -> List[CurveWorkItem]:
        """Generate random curves passing through the target public key."""
        curves: List[CurveWorkItem] = []
        with tqdm(total=self.config.target_curves, desc="Generating curves") as bar:
            while len(curves) < self.config.target_curves:
                batch = min(1000, self.config.target_curves - len(curves))
                for _ in range(batch):
                    a = random.randrange(0, P)
                    b = (PUBY**2 - PUBX**3 - a * PUBX) % P
                    if b == 0:
                        continue
                    if not self._is_nonsingular(a, b):
                        continue
                    curve = EllipticCurve(F, [a, b])
                    try:
                        order = int(curve.order())
                    except RuntimeError:
                        continue
                    point = curve(PUBX, PUBY)
                    curves.append(CurveWorkItem(int(a), int(b), order, curve, point))
                    bar.update(1)
                if time.time() - self.last_save > self.config.save_interval:
                    self.save_progress()
        return curves

    def _is_nonsingular(self, a: int, b: int) -> bool:
        discriminant = (4 * pow(a, 3, P) + 27 * pow(b, 2, P)) % P
        return discriminant != 0

    # ------------------------------------------------------------------
    # Curve processing
    # ------------------------------------------------------------------
    def process_curves(self, curves: Sequence[CurveWorkItem]) -> None:
        for batch_start in range(0, len(curves), self.config.batch_size):
            batch = curves[batch_start : batch_start + self.config.batch_size]
            batch_results = self._process_batch_cpu(batch)

            collected_partials: List[PartialKey] = []
            for item, partials in batch_results:
                if not partials:
                    continue
                self.results.append(
                    (
                        item.a,
                        item.b,
                        [(pk.residue, pk.modulus) for pk in partials],
                    )
                )
                collected_partials.extend(partials)

            self.monitor.record_batch(len(batch), collected_partials)
            if time.time() - self.last_save > self.config.save_interval:
                self.save_progress()

    def _process_batch_cpu(
        self,
        batch: Sequence[CurveWorkItem],
    ) -> List[Tuple[CurveWorkItem, List[PartialKey]]]:
        batch_results: List[Tuple[CurveWorkItem, List[PartialKey]]] = []
        for item in batch:
            partials: List[PartialKey] = []
            factors = [(int(p), int(e)) for p, e in factor(item.order)]
            generator = item.curve.gens()[0]
            shortlisted = self.prime_optimizer.shortlist(factors)
            for prime, exponent in shortlisted:
                modulus = prime**exponent
                h = item.order // modulus
                hQ = h * item.point
                hG = h * generator
                dlog = self._solve_dlp(hQ, hG, modulus)
                if dlog is None:
                    continue
                partials.append(PartialKey(int(dlog), int(modulus)))
                self.prime_optimizer.update_weights([prime])
            batch_results.append((item, partials))
        return batch_results

    def _solve_dlp(self, Q, G_point, order: int) -> Optional[int]:
        if order <= 1:
            return 0
        try:
            if order < self.config.threshold:
                return int(bsgs(G_point, Q, (0, order - 1), operation="+"))
            return int(discrete_log_rho(Q, G_point, ord=order))
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Analysis & persistence
    # ------------------------------------------------------------------
    def analyse_results(self) -> Dict[str, object]:
        if not self.results:
            return {"error": "No partial keys recovered"}

        congruences = [PartialKey(res, mod) for _, _, partials in self.results for res, mod in partials]
        crt_inputs: Dict[int, List[Tuple[int, int]]] = defaultdict(list)
        for pk in congruences:
            for prime, exponent in factor(pk.modulus):
                prime = int(prime)
                modulus = prime**int(exponent)
                crt_inputs[prime].append((pk.residue % modulus, modulus))

        solutions: List[Tuple[int, int]] = []
        for prime, residues in crt_inputs.items():
            tally = Counter(residues)
            residue, _ = tally.most_common(1)[0]
            solutions.append((residue[0], residue[1]))

        try:
            private_key = int(crt([r for r, _ in solutions], [m for _, m in solutions]))
        except Exception as exc:
            return {"error": f"CRT combination failed: {exc}"}

        valid = (private_key * G) == TARGET
        return {
            "private_key": hex(private_key),
            "is_valid": valid,
            "coverage_bits": sum(math.log2(mod) for _, mod in solutions),
            "subgroups_used": len(solutions),
            "stats": self.monitor.snapshot(),
        }

    def save_progress(self) -> None:
        snapshot = AttackSnapshot(
            results=self.results,
            stats=self.monitor.snapshot(),
            optimizer_weights=dict(self.prime_optimizer.prime_weights),
            timestamp=time.time(),
        )
        payload = {
            "results": snapshot.results,
            "stats": snapshot.stats,
            "optimizer": snapshot.optimizer_weights,
            "timestamp": snapshot.timestamp,
        }
        path = self.report_dir / "progress.json"
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        self.last_save = time.time()
        self.logger.info("Progress saved (%s)", path)

    def resume(self) -> None:
        path = self.report_dir / "progress.json"
        if not path.exists():
            self.logger.warning("No progress file found to resume from")
            return
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        self.results = state.get("results", [])
        stats = state.get("stats", {})
        self.monitor.start_time = time.time()
        self.monitor.curves_processed = int(stats.get("curves_processed", 0))
        self.monitor.partial_keys = int(stats.get("partial_keys", 0))
        self.prime_optimizer.prime_weights = defaultdict(
            int, {int(k): int(v) for k, v in state.get("optimizer", {}).items()}
        )
        self.logger.info("Resumed state from %s", path)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        self.logger.info("Generating %s candidate curves", self.config.target_curves)
        curves = self.generate_curves()
        self.logger.info("Processing %s curves", len(curves))
        self.process_curves(curves)
        self.logger.info("Analysing %s recovered partial keys", len(self.results))
        result = self.analyse_results()
        self.save_progress()
        if "private_key" in result and result.get("is_valid"):
            self.logger.info("Recovered candidate private key %s", result["private_key"])
        else:
            self.logger.warning("Analysis did not yield a verified private key")
        return result


# =============================================================================
# Command line interface
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BudBot v13 - Enhanced twist attack")
    parser.add_argument("--test", action="store_true", help="Run in test mode with fewer curves")
    parser.add_argument("--curves", type=int, help="Number of curves to generate")
    parser.add_argument("--batch-size", type=int, help="Curves per processing batch")
    parser.add_argument("--threshold", type=int, help="Upper bound for subgroup order search")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the last saved progress snapshot if available",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> Dict[str, object]:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    config = AttackConfig.from_args(args)
    bot = BudBot(config)
    if args.resume:
        bot.resume()
    return bot.run()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    result = main()
    print(json.dumps(result, indent=2))
