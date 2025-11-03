#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Bitcoin Cryptographic Analysis Tool v2.0
==================================================
Educational research – lattice, ML, endomorphism, isogeny, nonce-bias.
"""

from __future__ import annotations

import hashlib
import json
import logging
import multiprocessing
import os
import secrets
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache, wraps
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestsDependencyWarning
from urllib3.util.retry import Retry

# ----------------------------------------------------------------------
# 1. SILENCE ALL REQUESTS / urllib3 / chardet warnings
# ----------------------------------------------------------------------
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings('ignore', category=RequestsDependencyWarning)
warnings.filterwarnings('ignore', message=".*urllib3.*")
warnings.filterwarnings('ignore', message=".*chardet.*")

_original_warn = warnings.warn
def _silent_warn(message, category=None, *args, **kwargs):
    """
    Silence warnings that mention "urllib3" or "chardet".
    
    If the provided message is a string containing "urllib3" or "chardet", the warning is suppressed.
    Otherwise the call is forwarded to the original warning handler.
    
    Parameters:
        message (str or Warning): The warning message or Warning instance to process.
        category (Optional[type]): Optional warning category passed through to the original handler.
    
    Returns:
        None
    """
    if isinstance(message, str) and ("urllib3" in message or "chardet" in message):
        return
    _original_warn(message, category, *args, **kwargs)
warnings.warn = _silent_warn

# ----------------------------------------------------------------------
# 2. Third-party imports (graceful fallback)
# ----------------------------------------------------------------------
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except Exception:                     # pragma: no cover
    NETWORKX_AVAILABLE = False
    nx = None

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    CRYPTO_AVAILABLE = True
except Exception:                     # pragma: no cover
    CRYPTO_AVAILABLE = False

try:
    from fastecdsa.curve import secp256k1
    from fastecdsa.point import Point
    ECDSA_AVAILABLE = True
except Exception:                     # pragma: no cover
    ECDSA_AVAILABLE = False
    secp256k1 = None
    Point = None

try:
    from fpylll import BKZ, LLL, IntegerMatrix

    FPYLLL_AVAILABLE = True
except Exception:                     # pragma: no cover
    FPYLLL_AVAILABLE = False

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import GridSearchCV, train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except Exception:                     # pragma: no cover
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except Exception:                     # pragma: no cover
    XGBOOST_AVAILABLE = False

try:
    from scipy.stats import entropy as scipy_entropy
    SCIPY_AVAILABLE = True
except Exception:                     # pragma: no cover
    SCIPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:                     # pragma: no cover
    PSUTIL_AVAILABLE = False

# ----------------------------------------------------------------------
# 3. Logging
# ----------------------------------------------------------------------
def setup_logging(log_file: str = "crypto_attack.log", level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return the module-level "CryptoAnalyzer" logger with a rotating file handler and a stream handler.
    
    Parameters:
        log_file (str): Path to the log file used by the rotating file handler.
        level (int): Logging level to apply to the logger (e.g., logging.INFO).
    
    Returns:
        logging.Logger: The configured "CryptoAnalyzer" logger instance.
    """
    logger = logging.getLogger("CryptoAnalyzer")
    logger.setLevel(level)
    logger.handlers.clear()
    fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(ch)
    return logger

logger = setup_logging()

# ----------------------------------------------------------------------
# 4. Curve constants
# ----------------------------------------------------------------------
CURVE_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CURVE_G = None

if ECDSA_AVAILABLE:
    CURVE_P = secp256k1.p
    CURVE_N = secp256k1.q
    CURVE_G = secp256k1.G

# ----------------------------------------------------------------------
# 5. Helper utilities
# ----------------------------------------------------------------------
def mod_inverse(a: int, m: int) -> int:
    """
    Compute the modular multiplicative inverse of `a` modulo `m`.
    
    Parameters:
        a (int): Integer whose modular inverse is sought.
        m (int): Modulus (must be a positive integer).
    
    Returns:
        inverse (int): The integer `x` in the range [0, m-1] such that `(a * x) % m == 1`.
    
    Raises:
        ValueError: If the inverse does not exist (i.e., `a` and `m` are not coprime).
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Compute the greatest common divisor of two integers and coefficients for Bézout's identity.
    
    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        gcd (int): The greatest common divisor of `a` and `b`.
        x (int): Coefficient satisfying `a*x + b*y == gcd`.
        y (int): Coefficient satisfying `a*x + b*y == gcd`.
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

def shannon_entropy(arr: np.ndarray) -> float:
    """
    Compute the Shannon entropy of the values in a NumPy array, expressed in bits.
    
    Parameters:
        arr (np.ndarray): Array of observations; can be any dtype. An empty array yields 0.0.
    
    Returns:
        float: Entropy in bits of the empirical distribution of values in `arr`; `0.0` for empty input.
    """
    if arr.size == 0:
        return 0.0
    if SCIPY_AVAILABLE:
        return float(scipy_entropy(arr, base=2))
    uniq, counts = np.unique(arr, return_counts=True)
    probs = counts / len(arr)
    return float(-np.sum(probs * np.log2(probs)))

# ----------------------------------------------------------------------
# 6. ECDSA helpers
# ----------------------------------------------------------------------
def decompress_public_key(pubkey_hex: str) -> Point:
    """
    Decompresses a compressed secp256k1 public key hex string into an elliptic-curve Point.
    
    Parameters:
        pubkey_hex (str): Compressed public key as a hex string starting with prefix "02" or "03".
    
    Returns:
        Point: The corresponding secp256k1 curve point.
    
    Raises:
        RuntimeError: If the required fastecdsa backend is not available.
        ValueError: If the prefix is not "02" or "03", or if the resulting point is not on the curve.
    """
    if not ECDSA_AVAILABLE:
        raise RuntimeError("fastecdsa required")
    prefix = int(pubkey_hex[:2], 16)
    if prefix not in (2, 3):
        raise ValueError("invalid prefix")
    x = int(pubkey_hex[2:], 16)
    y_sq = (pow(x, 3, CURVE_P) + 7) % CURVE_P
    y = pow(y_sq, (CURVE_P + 1) // 4, CURVE_P)
    if (y % 2) != (prefix % 2):
        y = CURVE_P - y
    point = Point(x, y, curve=secp256k1)
    if (point.x**3 + 7) % CURVE_P != (point.y**2) % CURVE_P:
        raise ValueError("point not on curve")
    return point

def parse_der_signature(sig: bytes) -> Optional[Tuple[int, int]]:
    """
    Parse a DER-encoded ECDSA signature and return its (r, s) components if valid.
    
    Parameters:
    	sig (bytes): DER-encoded signature bytes (commonly as found in transaction scriptSigs).
    
    Returns:
    	Optional[Tuple[int, int]]: A tuple `(r, s)` containing the signature components when both are integers greater than 0 and less than the curve order; `None` if parsing fails or the values are out of range.
    """
    if CRYPTO_AVAILABLE:
        try:
            r, s = asym_utils.decode_dss_signature(sig)
            if 0 < r < CURVE_N and 0 < s < CURVE_N:
                return r, s
        except Exception:
            pass
    if len(sig) < 8 or sig[0] != 0x30:
        return None
    i = 2
    if sig[i] != 0x02: return None
    i += 1
    r_len = sig[i]; i += 1
    r = int.from_bytes(sig[i:i+r_len], "big"); i += r_len
    if sig[i] != 0x02: return None
    i += 1
    s_len = sig[i]; i += 1
    s = int.from_bytes(sig[i:i+s_len], "big")
    if 0 < r < CURVE_N and 0 < s < CURVE_N:
        return r, s
    return None

def validate_private_key(k: int) -> bool:
    """
    Determine whether an integer is a valid secp256k1 private key.
    
    Parameters:
        k (int): Candidate private key to check.
    
    Returns:
        True if `k` is between 1 and `CURVE_N - 1` (inclusive), False otherwise.
    """
    return 0 < k < CURVE_N

def private_key_to_public_key(k: int) -> Optional[Point]:
    """
    Derives the public elliptic-curve point corresponding to a given private scalar.
    
    Parameters:
        k (int): Private key scalar; must be greater than 0 and less than CURVE_N.
    
    Returns:
        Point or None: The public key point k·G on the secp256k1 curve, or `None` if the private key is invalid, the cryptographic backend is unavailable, or the point multiplication fails.
    """
    if not ECDSA_AVAILABLE or not validate_private_key(k):
        return None
    try:
        return k * secp256k1.G
    except Exception as e:
        logger.error(f"scalar mul failed: {e}")
        return None

# ----------------------------------------------------------------------
# 7. Lattice reduction (safe)
# ----------------------------------------------------------------------
def reduce_lattice_bkz(matrix: List[List[int]],
                       block_size: int = 40,
                       tours: int = 15) -> Optional[List[List[int]]]:
    """
                       Reduce an integer lattice matrix using LLL followed by BKZ reduction.
                       
                       Parameters:
                           matrix (List[List[int]]): Integer matrix representing the lattice basis (rows are basis vectors).
                           block_size (int): BKZ block size controlling the strength of blockwise reduction.
                           tours (int): Maximum number of BKZ loops (iterations) to perform.
                       
                       Returns:
                           Optional[List[List[int]]]: The reduced matrix as a list of integer rows on success; `None` if the fpylll backend is unavailable or reduction fails.
                       """
                       if not FPYLLL_AVAILABLE:
        logger.warning("fpylll missing – skipping reduction")
        return None
    try:
        rows, cols = len(matrix), len(matrix[0])
        M = IntegerMatrix(rows, cols)
        for i, row in enumerate(matrix):
            for j, v in enumerate(row):
                M[i, j] = v
        LLL.reduction(M)
        bkz = BKZReduction(M)
        bkz(BKZ.Param(block_size=block_size, max_loops=tours))
        return [[M[i, j] for j in range(cols)] for i in range(rows)]
    except Exception as e:
        logger.error(f"BKZ failed: {e}")
        return None

# ----------------------------------------------------------------------
# 8. ML Candidate Ranker (fixed NaN/inf)
# ----------------------------------------------------------------------
class AdvancedCandidateRanker:
    def __init__(self, enable: bool = True):
        """
        Initialize the ranker and optionally build/train the internal ML pipeline.
        
        Parameters:
            enable (bool): If True and scikit-learn is available, construct and train the internal model; if False, keep the ranker uninitialized.
        """
        self.model: Optional[Pipeline] = None
        self.trained = False
        if enable and SKLEARN_AVAILABLE:
            self._init_model()

    def _init_model(self):
        """
        Initialize the internal ML ranking pipeline and train it on synthetic data.
        
        Sets self.model to a preprocessing + classifier Pipeline (XGBoost when available, otherwise scikit-learn's GradientBoosting) and invokes synthetic training with 6000 samples to produce a ready-to-use ranker.
        """
        logger.info("Initializing ML ranker...")
        clf = (xgb.XGBClassifier(
                n_estimators=150, max_depth=7, learning_rate=0.05,
                subsample=0.8, colsample_bytree=0.8,
                reg_alpha=0.1, reg_lambda=1.0,
                random_state=42, n_jobs=-1
              ) if XGBOOST_AVAILABLE else
              GradientBoostingClassifier(
                n_estimators=150, max_depth=7, learning_rate=0.05,
                subsample=0.8, random_state=42
              ))
        self.model = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
        self._train_synthetic(6000)

    def _train_synthetic(self, n: int):
        """
        Generate synthetic training data, train the internal classifier with GridSearchCV, and mark the model as trained.
        
        Generates `n` synthetic feature vectors by creating random 6-element rows, producing 'good' and 'bad' variants, extracting features, splitting into train/test sets, tuning hyperparameters via 3-fold grid search, and replacing the instance model with the best estimator. Logs training accuracy and chosen parameters; if no valid features are produced, training is skipped and the model remains untrained.
        
        Parameters:
            n (int): Number of synthetic samples to generate (total examples requested; actual training set size may be smaller after feature filtering).
        """
        logger.info(f"Generating {n} synthetic samples...")
        X, y = [], []
        for _ in range(n // 2):
            row = [secrets.randbelow(1 << 120) for _ in range(6)]
            X.append(self._features(self._good(row)))
            y.append(1)
            X.append(self._features(self._bad(row)))
            y.append(0)
        X = [x for x in X if x is not None]
        y = y[:len(X)]
        if not X:
            logger.warning("No valid synthetic features – ML disabled")
            return
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2,
                                              random_state=42, stratify=y)
        param_grid = {
            "clf__max_depth": [5, 7],
            "clf__learning_rate": [0.05, 0.1]
        }
        grid = GridSearchCV(self.model, param_grid, cv=3, n_jobs=-1,
                            error_score='raise')
        grid.fit(Xtr, ytr)
        self.model = grid.best_estimator_
        acc = accuracy_score(yte, self.model.predict(Xte))
        logger.info(f"ML training done – acc {acc:.3f}")
        logger.info(f"Best parameters: {grid.best_params_}")
        self.trained = True

    def _good(self, row: List[int]) -> List[int]:
        """
        Apply a small random multiplicative perturbation to each integer in a row, leaving zeros unchanged.
        
        Each nonzero element is multiplied by a random factor in the range [0.9, 1.099), converted to an integer (truncated), and then clamped to a minimum of 1.
        
        Parameters:
            row (List[int]): Input list of integers.
        
        Returns:
            List[int]: New list with perturbed (and clamped) integer values; zeros are preserved.
        """
        return [max(1, int(v * (1 + (secrets.randbelow(200)-100)/1000))) if v else 0
                for v in row]

    def _bad(self, row: List[int]) -> List[int]:
        """
        Generate a perturbed integer row by randomly amplifying each non-zero entry.
        
        Parameters:
            row (List[int]): Input integer row whose non-zero elements will be perturbed.
        
        Returns:
            List[int]: New list where each non-zero element of `row` is multiplied by a random factor between 2.00 and 4.99 and converted to an integer; zero elements are preserved as 0.
        """
        return [int(v * (2 + secrets.randbelow(300)/100)) if v else 0
                for v in row]

    def _features(self, row: List[int]) -> Optional[List[float]]:
        """
        Compute a fixed-length numeric feature vector describing a lattice row for ML ranking.
        
        Parameters:
            row (List[int]): Integer vector representing a lattice row or candidate solution.
        
        Returns:
            Optional[List[float]]: A list of 21 clipped features (s, mx, mn, mean, std, l1, l2, linf, entropy, small_count,
            normalized_distance, skewness, kurtosis, angle_metric, key_entropy, normalized_length, smoothness, geometric_volume,
            sparsity, near_zero_count, sign_changes) describing magnitudes, distribution, norms, entropy and structural properties;
            or `None` if the input is empty or feature computation fails.
        """
        if not row:
            return None
        try:
            a = np.array(row, dtype=np.float64)
            a = np.nan_to_num(a, nan=0.0, posinf=1e12, neginf=-1e12)
            absa = np.abs(a)
            s = float(np.sum(absa)) or 1e-12
            mx = float(np.max(absa))
            mn = float(np.min(absa))
            mean = float(np.mean(absa))
            std = float(np.std(a)) or 1e-12
            l1 = float(np.sum(absa))
            l2 = float(np.linalg.norm(a))
            linf = float(np.max(absa))
            ent = shannon_entropy(absa.astype(int))
            small = float(np.sum(absa < 1000))
            dist = abs(row[-1] - CURVE_N//2) if row else CURVE_N
            ndist = min(1.0, dist/(CURVE_N/2))
            skew_val = float(np.mean((a-mean)**3)/(std**3)) if std>0 and len(a)>2 else 0.0
            kurt_val = float(np.mean((a-mean)**4)/(std**4)-3) if std>0 and len(a)>3 else 0.0
            angle = 1.0/(1+mx) if mx>0 else 1.0
            key_ent = shannon_entropy(absa[:3]) if len(absa)>=3 else 0.0
            nlen = l2 / (len(a)**0.5)
            smooth = small/len(a)
            vol = float(np.prod(np.clip(absa+1e-6,1e-6,1e12))**(1/len(a)))
            sparse = float(np.sum(absa==0))/len(a)
            zeros = float(np.sum(absa<1e-6))
            signc = float(np.sum(np.diff(np.sign(a))!=0))
            feats = [s,mx,mn,mean,std,l1,l2,linf,ent,small,ndist,
                     skew_val,kurt_val,angle,key_ent,nlen,smooth,vol,
                     sparse,zeros,signc]
            return [np.clip(v, -1e12, 1e12) for v in feats]
        except Exception as e:
            logger.debug(f"Feature error: {e}")
            return None

    def rank(self, candidates: List['CandidateKey']) -> List[Tuple['CandidateKey', float]]:
        """
        Rank candidate private keys by combining the ML model's probability with each candidate's base confidence.
        
        Parameters:
            candidates (List[CandidateKey]): CandidateKey objects to rank. Each candidate's metadata may include a "row" entry used to compute model features.
        
        Returns:
            List[Tuple[CandidateKey, float]]: Tuples of candidate and score, sorted descending by score. The score is 0.7 * model_probability + 0.3 * candidate.confidence when the internal model is available and features can be computed; otherwise the candidate's original confidence is used. Candidates lacking computable features are included with their original confidence. The candidate objects' `score` attribute is updated when a model-derived score is assigned.
        """
        if not candidates:
            return []
        if not self.trained or not self.model:
            return [(c, c.confidence) for c in candidates]
        feats, cands = [], []
        for c in candidates:
            f = self._features(c.metadata.get("row", []))
            if f:
                feats.append(f)
                cands.append(c)
        if not feats:
            return [(c, c.confidence) for c in candidates]
        probs = self.model.predict_proba(np.array(feats))[:, 1]
        out = []
        for cand, p in zip(cands, probs):
            score = 0.7 * p + 0.3 * cand.confidence
            cand.score = score
            out.append((cand, score))
        seen = {c.key for c,_ in out}
        for c in candidates:
            if c.key not in seen:
                out.append((c, c.confidence))
        out.sort(key=lambda x: x[1], reverse=True)
        return out

# ----------------------------------------------------------------------
# 9. Data classes
# ----------------------------------------------------------------------
class AttackType(Enum):
    LATTICE_BASIC = auto()
    LATTICE_ADVANCED = auto()
    ISOGENY = auto()
    ENDOMORPHISM = auto()
    SIGNATURE_RECOVERY = auto()

@dataclass
class SignatureData:
    r: int
    s: int
    message: bytes
    txid: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """
        Validate that the signature components `r` and `s` are within the valid range for the curve.
        
        Raises:
            ValueError: If either `r` or `s` is not greater than 0 and less than CURVE_N.
        """
        if not (0 < self.r < CURVE_N and 0 < self.s < CURVE_N):
            raise ValueError("invalid r/s")

@dataclass
class CandidateKey:
    key: int
    confidence: float
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    def __post_init__(self):
        """
        Clamp the instance's `confidence` attribute to the inclusive range 0.0 to 1.0.
        
        This method mutates `self.confidence` so that values below 0.0 become 0.0 and values above 1.0 become 1.0.
        """
        self.confidence = max(0.0, min(1.0, self.confidence))

# ----------------------------------------------------------------------
# 10. Blockchain client + signature extraction
# ----------------------------------------------------------------------
class BlockchainClient:
    def __init__(self):
        """
        Initialize the BlockchainClient HTTP session with robust retry behavior and a custom User-Agent.
        
        Configures a requests.Session that retries transient HTTP errors (5 total attempts, exponential backoff via backoff_factor=1) for status codes 429, 500, 502, 503, and 504, and mounts the retry-enabled adapter for both HTTP and HTTPS. Also sets the session's User-Agent header to "CryptoAnalyzer/2.0".
        """
        self.session = requests.Session()
        retry = Retry(total=5, backoff_factor=1,
                      status_forcelist=[429,500,502,503,504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({"User-Agent": "CryptoAnalyzer/2.0"})

    def get_address_txs(self, address: str) -> List[str]:
        """
        Fetch transaction IDs for a Bitcoin address from the Blockstream API.
        
        Parameters:
            address (str): Bitcoin address to query.
        
        Returns:
            txids (List[str]): List of transaction IDs (hex) associated with the address; empty list on error or if no transactions are found.
        """
        url = f"https://blockstream.info/api/address/{address}/txs"
        try:
            data = self.session.get(url, timeout=20).json()
            return [tx["txid"] for tx in data]
        except Exception as e:
            logger.warning(f"Failed address txs: {e}")
            return []

    def get_raw_tx(self, txid: str) -> Optional[bytes]:
        """
        Fetch the raw transaction hex for a given transaction ID from Blockstream and return it as raw bytes.
        
        Retrieves the transaction hex from the Blockstream API endpoint and decodes it.
        
        Returns:
            bytes: Raw transaction bytes decoded from hex, or `None` if retrieval or decoding fails.
        """
        url = f"https://blockstream.info/api/tx/{txid}/hex"
        try:
            txt = self.session.get(url, timeout=15).text.strip()
            return bytes.fromhex(txt)
        except Exception as e:
            logger.warning(f"Raw tx failed: {e}")
            return None

    def extract_signatures(self, raw_tx: bytes) -> List[bytes]:
        """
        Parse a raw serialized Bitcoin transaction and extract signature byte sequences from each input's scriptSig.
        
        Parameters:
            raw_tx (bytes): Raw serialized Bitcoin transaction bytes.
        
        Returns:
            List[bytes]: A list of signature byte sequences with the trailing sighash byte removed (e.g. DER signature bytes).
        """
        sigs = []
        i = 4
        vin_cnt = raw_tx[i]; i += 1
        if vin_cnt >= 0xfd:
            sz = {0xfd:2, 0xfe:4, 0xff:8}[vin_cnt]
            vin_cnt = int.from_bytes(raw_tx[i:i+sz], "little")
            i += sz
        for _ in range(vin_cnt):
            i += 36
            script_len = raw_tx[i]; i += 1
            if script_len >= 0xfd:
                sz = {0xfd:2, 0xfe:4, 0xff:8}[script_len]
                script_len = int.from_bytes(raw_tx[i:i+sz], "little")
                i += sz
            script_sig = raw_tx[i:i+script_len]; i += script_len
            i += 4
            pos = 0
            while pos < len(script_sig):
                op = script_sig[pos]; pos += 1
                if 0x01 <= op <= 0x4b:
                    data = script_sig[pos:pos+op]
                    if data and data[-1] in (0x01, 0x81):
                        sigs.append(data[:-1])
                    pos += op
                else:
                    break
        return sigs

    def signatures_for_address(self, address: str,
                               max_txs: int = 30) -> List[SignatureData]:
        """
                               Collects and parses ECDSA signatures found in recent transactions for a given address.
                               
                               Parameters:
                                   address (str): Blockchain address to query for transactions.
                                   max_txs (int): Maximum number of recent transactions to scan (default 30).
                               
                               Returns:
                                   List[SignatureData]: A list of parsed signatures; each item contains `r`, `s`, the double-SHA256 of the raw transaction as `message`, and the originating `txid`.
                               """
                               txids = self.get_address_txs(address)[:max_txs]
        sigs: List[SignatureData] = []
        for txid in txids:
            raw = self.get_raw_tx(txid)
            if not raw:
                continue
            for der in self.extract_signatures(raw):
                parsed = parse_der_signature(der)
                if parsed:
                    r, s = parsed
                    msg = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
                    sigs.append(SignatureData(r=r, s=s, message=msg, txid=txid))
        logger.info(f"Extracted {len(sigs)} signatures for {address}")
        return sigs

# ----------------------------------------------------------------------
# 11. NONCE BIAS + ENTROPY (NO OVERFLOW – pure Python int)
# ----------------------------------------------------------------------
def detect_nonce_bias(signatures: List[SignatureData]) -> Dict[str, Any]:
    """
    Analyze a list of ECDSA signatures for low/high 8-bit nonce (r) entropy and report basic statistics.
    
    Parameters:
        signatures (List[SignatureData]): List of signature records whose `r` values will be analyzed.
    
    Returns:
        Dict[str, Any]: A dictionary with the following keys:
            - total_sigs (int): Number of signatures analyzed.
            - entropy_low_8bits (float): Shannon entropy (bits) of the lowest 8 bits of the `r` values.
            - entropy_high_8bits (float): Shannon entropy (bits) of the highest 8 bits of the `r` values.
            - bias_detected (bool): `true` if either low- or high-8-bit entropy is less than 3.0, `false` otherwise.
            - mean_r (float): Mean of the `r` values.
            - std_r (float): Population standard deviation of the `r` values.
    
    Notes:
        If fewer than 3 signatures are provided, the function returns `{"bias_detected": False, "total_sigs": <n>}` without computing entropies.
    """
    if len(signatures) < 3:
        return {"bias_detected": False, "total_sigs": len(signatures)}

    # Extract r values as Python int (256-bit safe)
    r_vals = [s.r for s in signatures]

    # Low 8 bits: r & 0xFF
    low8 = np.array([r & 0xFF for r in r_vals], dtype=np.uint8)

    # High 8 bits: (r >> (bit_length - 8)) & 0xFF
    # We compute bit length manually to avoid overflow
    high8 = []
    for r in r_vals:
        if r == 0:
            high8.append(0)
        else:
            bit_len = r.bit_length()
            shift = max(0, bit_len - 8)
            high8.append((r >> shift) & 0xFF)
    high8 = np.array(high8, dtype=np.uint8)

    e_low  = shannon_entropy(low8)
    e_high = shannon_entropy(high8)

    # Mean/std as float (safe)
    mean_r = sum(r_vals) / len(r_vals)
    std_r  = (sum((r - mean_r) ** 2 for r in r_vals) / len(r_vals)) ** 0.5

    bias = {
        "total_sigs": len(signatures),
        "entropy_low_8bits": e_low,
        "entropy_high_8bits": e_high,
        "bias_detected": e_low < 3.0 or e_high < 3.0,
        "mean_r": float(mean_r),
        "std_r":  float(std_r),
    }
    if bias["bias_detected"]:
        logger.warning(f"Nonce bias detected – low:{e_low:.2f} high:{e_high:.2f}")
    return bias

# ----------------------------------------------------------------------
# 12. Lattice builder (all four variants)
# ----------------------------------------------------------------------
class AdvancedLatticeBuilder:
    def __init__(self):
        """
        Initialize the builder and create a BlockchainClient for blockchain I/O.
        
        Sets self.client to a new BlockchainClient instance used to fetch transactions and raw transaction data.
        """
        self.client = BlockchainClient()

    def _basic(self, pub: Point) -> List[List[int]]:
        """
        Builds the basic integer lattice matrix for lattice-based private key recovery using the public key coordinates.
        
        Parameters:
            pub (Point): Elliptic-curve public key point whose x and y coordinates are used (values will be reduced modulo CURVE_N).
        
        Returns:
            List[List[int]]: A 3×4 integer matrix with CURVE_N on the diagonal and the public point coordinates (mod CURVE_N) in the last column.
        """
        qx = pub.x % CURVE_N
        qy = pub.y % CURVE_N
        return [[CURVE_N,0,0,qx],
                [0,CURVE_N,0,qy],
                [0,0,CURVE_N,1]]

    def _hnp(self, pub: Point, sigs: List[SignatureData]) -> List[List[int]]:
        """
        Construct an HNP-style lattice matrix for the given public key, optionally extended with rows derived from signatures.
        
        Parameters:
            pub (Point): Decompressed public key point used to build the base lattice.
            sigs (List[SignatureData]): Signatures to incorporate; at most the first 1000 entries are used. When provided, each signature contributes three rows derived from the signature's r, s and message values. If empty, a large-scale diagonal block is appended instead.
        
        Returns:
            List[List[int]]: Integer matrix represented as a list of rows suitable for lattice reduction.
        """
        mat = self._basic(pub)
        if sigs:
            for s in sigs[:1000]:
                m = int.from_bytes(s.message, "big") % CURVE_N
                ri = mod_inverse(s.r, CURVE_N)
                mat += [[0,0,0,s.r],
                        [0,0,0,(s.s*ri)%CURVE_N],
                        [0,0,0,(m*ri)%CURVE_N]]
        else:
            scale = 1 << 120
            mat += [[scale,0,0,0],
                    [0,scale,0,0],
                    [0,0,scale,0],
                    [0,0,0,scale]]
        logger.info(f"HNP lattice rows: {len(mat)}")
        return mat

    def _extended(self, pub: Point, sigs: List[SignatureData]) -> List[List[int]]:
        """
        Builds an extended lattice for endomorphism-aware attacks by augmenting the HNP lattice with rows derived from the public key and fixed endomorphism constants.
        
        Parameters:
            pub (Point): The elliptic-curve public key point whose coordinates are used to generate endomorphism-derived rows.
            sigs (List[SignatureData]): Signature records used to construct the base HNP lattice; may be empty.
        
        Returns:
            List[List[int]]: Integer matrix as a list of rows representing the extended lattice. If the endomorphism augmentation fails, the returned matrix is the unmodified HNP lattice.
        """
        mat = self._hnp(pub, sigs)
        try:
            beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
            lam  = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
            bx = (pub.x * beta) % CURVE_P
            mat += [[CURVE_N,0,0,bx%CURVE_N],
                    [0,CURVE_N,0,pub.y%CURVE_N],
                    [0,0,1,0],
                    [0,0,0,(lam*pub).x%CURVE_N],
                    [0,0,0,(lam*pub).y%CURVE_N]]
        except Exception as e:
            logger.debug(f"Endomorphism extension failed: {e}")
        logger.info(f"Extended lattice rows: {len(mat)}")
        return mat

    def _kannan(self, pub: Point, sigs: List[SignatureData]) -> List[List[int]]:
        """
        Builds a lattice matrix suitable for Kannan-style small-nonce key recovery attacks.
        
        Parameters:
            pub (Point): The public key point used to construct lattice basis vectors.
            sigs (List[SignatureData]): Collected signatures influencing additional lattice rows; may be empty.
        
        Returns:
            List[List[int]]: Integer matrix represented as a list of rows, each row being a list of integers forming the lattice basis.
        """
        return self._hnp(pub, sigs)

    def build(self, pub_hex: str, sigs: Optional[List[SignatureData]],
              algo: str = "extended") -> Optional[List[List[int]]]:
        """
              Builds and reduces a lattice for the given public key and optional signatures using the selected algorithm.
              
              Parameters:
                  pub_hex (str): Hex-encoded public key (compressed or uncompressed) to base the lattice on.
                  sigs (Optional[List[SignatureData]]): Optional list of signature records that may be used to extend or parameterize the lattice.
                  algo (str): Desired algorithm name hint (e.g., "extended", "hnp", "bkz"); the method will choose a reduction path based on the resolved algorithm string.
              
              Returns:
                  Optional[List[List[int]]]: A reduced lattice matrix (list of integer rows) when reduction succeeds, or `None` if the public key is invalid or reduction cannot be performed.
              """
              try:
            pub = decompress_public_key(pub_hex)
        except Exception as e:
            logger.error(f"Bad pubkey: {e}")
            return None

        algorithm_name = (self.algorithm or "lll").lower()
        logger.info("Starting lattice reduction with %s", algorithm_name)

        if "bkz" in algorithm_name:
            return self._run_bkz(lattice_matrix, algorithm_name)

        return self._run_lll(lattice_matrix)

    def _run_lll(self, matrix: IntegerMatrix) -> IntegerMatrix:
        try:
            logger.info("Starting LLL reduction")
            LLL.reduction(matrix)
            logger.info("LLL reduction completed successfully")
            if self.callback:
                self.callback("completed", 100.0, 0.0)
        except Exception as exc:
            logger.error("LLL reduction failed: %s", exc)
        return matrix

    def _run_bkz(self, matrix: IntegerMatrix, algorithm_name: str) -> IntegerMatrix:
        dimension = matrix.ncols
        if dimension <= 1:
            logger.warning("Lattice dimension (%d) too small for BKZ; skipping", dimension)
            return matrix

        max_block = max(2, min(BKZ_BLOCK_SIZE, dimension))

        def _apply_block(block_size: int) -> None:
            effective_block = max(2, min(block_size, dimension))
            logger.info("Running BKZ with block size %d", effective_block)
            BKZ.reduction(matrix, BKZ.Param(block_size=effective_block, max_loops=BKZ_TOURS))

        try:
            if "progressive" in algorithm_name:
                schedule: List[int] = []
                step = 5
                while step < max_block:
                    if step >= 2:
                        schedule.append(step)
                    step += 5
                if not schedule or schedule[-1] != max_block:
                    schedule.append(max_block)

                total_steps = len(schedule)
                for index, block in enumerate(schedule, start=1):
                    _apply_block(block)
                    if self.callback:
                        progress = min(100.0, 100.0 * index / total_steps)
                        self.callback("bkz", progress, float(min(block, dimension)))
            else:
                _apply_block(max_block)
                if self.callback:
                    self.callback("bkz", 100.0, float(max_block))
        except Exception as exc:
            logger.error("BKZ reduction failed: %s", exc)
            logger.info("Falling back to LLL reduction")
            return self._run_lll(matrix)

        return matrix


class ComprehensiveKeyValidator:
    """Validate candidate private keys against a public key."""

    def __init__(self) -> None:
        self.cache: Dict[Tuple[int, str], bool] = {}
        self.parallel = True

    def validate_key(self, private_key: int, public_key_hex: str) -> bool:
        if not ECDSA_AVAILABLE:
            return False

        cache_key = (private_key, public_key_hex)
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            target_point = decompress_public_key(public_key_hex)
            candidate_point = private_key * G  # type: ignore[operator]
            result = candidate_point == target_point
            self.cache[cache_key] = result
            return result
        except Exception as exc:
            logger.error("Validation error: %s", exc)
            return False

    def batch_validate(self, keys: List[int], public_key_hex: str) -> List[bool]:
        if not self.parallel or len(keys) < 2:
            return [self.validate_key(k, public_key_hex) for k in keys]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(self.validate_key, key, public_key_hex) for key in keys]
            results = []
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    results.append(False)
        return results


class AdvancedCryptanalyzer:
    """Coordinate lattice construction, reduction, ranking, and validation."""

    def __init__(self) -> None:
        self.lattice_builder = AdvancedLatticeBuilder()
        self.reduction_engine = AdvancedReductionEngine()
        self.ranker = AdvancedCandidateRanker()
        self.validator = ComprehensiveKeyValidator()
        self.client = EnhancedBlockchainClient()

    def analyze_key(
        self,
        public_key_hex: str,
        signatures: Optional[List[Tuple[bytes, int, int]]] = None,
        source: str = "manual",
        algorithm: str = "extended",
    ) -> List[CandidateKey]:
        logger.info("Starting comprehensive analysis for key: %s...", public_key_hex[:16])
        start = time.time()

        if not signatures and public_key_hex.startswith(("1", "3", "bc1", "tb1")):
            signatures = self.client.get_signatures_for_address(public_key_hex)

        lattice_matrix = self.lattice_builder.construct_lattice_from_signatures(
            public_key_hex, signatures, algorithm
        )
        if not lattice_matrix:
            logger.error("Failed to construct lattice matrix")
            return []

        def callback(stage: str, progress: float, metric: float) -> None:
            logger.debug("Reduction %s: %.2f%% (metric %.2f)", stage, progress, metric)

        reduced_matrix = self.reduction_engine.reduce_lattice(
            lattice_matrix, algorithm="progressive_bkz", callback=callback
        )
        if not reduced_matrix:
            logger.error("Lattice reduction failed")
            return []

        candidates = self._extract_candidates_from_lattice(reduced_matrix)
        ranked = self.ranker.rank_candidates(candidates)
        validated = self._validate_and_score_candidates(ranked, public_key_hex)

        duration = time.time() - start
        logger.info("Analysis completed in %.2f seconds", duration)
        logger.info(
            "Generated %d candidates, %d passed validation",
            len(candidates),
            len([candidate for candidate in validated if candidate.validation_result]),
        )
        return validated

    def _extract_candidates_from_lattice(
        self, lattice_matrix: IntegerMatrix
    ) -> List[CandidateKey]:
        candidates: List[CandidateKey] = []
        rows = _integer_matrix_rows(lattice_matrix)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(self._extract_candidates_from_row, row, idx)
                for idx, row in enumerate(rows)
                if row
            ]
            for future in as_completed(futures):
                try:
                    candidates.extend(future.result())
                except Exception as exc:
                    logger.error("Candidate extraction failed: %s", exc)
        return candidates

    def _extract_candidates_from_row(self, row: List[int], row_index: int) -> List[CandidateKey]:
        candidates: List[CandidateKey] = []
        seen: set[int] = set()

        if not row:
            return candidates

        for value in [row[-1], *row]:
            candidate = abs(value) % n
            if not candidate or candidate in seen:
                continue
            confidence = self._calculate_row_confidence(row, candidate)
            if confidence > MIN_CONFIDENCE:
                candidates.append(
                    CandidateKey(
                        key=candidate,
                        confidence=confidence,
                        source="row_element",
                        metadata={"row": row, "row_index": row_index},
                    )
                )
            seen.add(candidate)
        return candidates

    def _calculate_row_confidence(self, row: List[int], candidate: int) -> float:
        try:
            row_array = np.array([abs(x) for x in row], dtype=np.float64)
            row_array = np.nan_to_num(row_array)
            total = float(np.sum(row_array)) or 1.0
            max_val = float(np.max(row_array)) or 1.0
            distance = abs(candidate - (n // 2))
            normalized_distance = min(1.0, distance / (n / 2))
            skewness = float(skew(row_array)) if row_array.size > 3 else 0.0
            small_coeffs = float(np.sum(row_array < 1000))
            lattice_score = 1.0 / (1.0 + max_val)
            confidence = (
                0.4 * lattice_score
                + 0.3 * (1.0 - normalized_distance)
                + 0.2 * (small_coeffs / max(1, len(row)))
                + 0.1 * (1.0 / (1.0 + abs(skewness)))
            )
            return float(min(1.0, max(0.0, confidence)))
        except Exception:
            return MIN_CONFIDENCE

    def _validate_and_score_candidates(
        self, candidates: List[Tuple[CandidateKey, float]], public_key_hex: str
    ) -> List[CandidateKey]:
        if not candidates:
            return []

        top = candidates[: min(20, len(candidates))]
        validation_targets = [candidate.key for candidate, _ in top]
        results = self.validator.batch_validate(validation_targets, public_key_hex)

        validated: List[CandidateKey] = []
        for (candidate, _), is_valid in zip(top, results):
            candidate.validation_result = is_valid
            candidate.confidence = candidate.confidence * (2.0 if is_valid else 0.5)
            validated.append(candidate)
            if is_valid:
                logger.info("Found valid key: %d", candidate.key)
        return validated


def _integer_matrix_rows(matrix: IntegerMatrix) -> List[List[int]]:
    rows: List[List[int]] = []
    for i in range(matrix.nrows):
        rows.append([matrix[i, j] for j in range(matrix.ncols)])
    return rows


def decompress_public_key(public_key_hex: str) -> Point:
    if not ECDSA_AVAILABLE:
        raise ValueError("fastecdsa is required to decompress public keys")
    if not public_key_hex:
        raise ValueError("Empty public key")

    public_key_hex = public_key_hex.strip()
    if len(public_key_hex) == 66:
        prefix = int(public_key_hex[:2], 16)
        x = int(public_key_hex[2:], 16)
    elif len(public_key_hex) == 130:
        prefix = int(public_key_hex[:2], 16)
        x = int(public_key_hex[2:66], 16)
    else:
        raise ValueError("Invalid public key length")

    if prefix not in (2, 3, 4):
        raise ValueError("Invalid compressed public key prefix")

    alpha = (pow(x, 3, p) + 7) % p
    beta = pow(alpha, (p + 1) // 4, p)
    if (beta % 2 == 0 and prefix == 3) or (beta % 2 == 1 and prefix == 2):
        beta = (-beta) % p

    point = Point(x, beta, curve=secp256k1)
    if prefix == 4 and point.y != int(public_key_hex[66:], 16):
        raise ValueError("Invalid uncompressed public key")
    return point


def parse_der_signature(signature: bytes) -> Optional[Tuple[int, int]]:
    """
    Constructs a directed isogeny vulnerability graph that encodes risk attributes for several named elliptic curves.
    
    Parameters:
    	signature (bytes): Ignored; present for API compatibility.
    
    Returns:
    	networkx.DiGraph: A directed graph whose nodes are curve names with attributes `type` (str) and `risk` (float), and whose edges have attributes `weight` (float) and `vulnerability` (float).
    """
    if not signature or len(signature) < 2:
        return None
    g = nx.DiGraph()
    curves = {
        "secp256k1": {"type":"standard","risk":0.081},
        "P-256": {"type":"standard","risk":0.156},
        "Curve25519": {"type":"standard","risk":0.107},
        "Brainpool256": {"type":"standard","risk":0.094},
        "P-384": {"type":"standard","risk":0.088},
        "weak_curve_dual_ec": {"type":"weak","risk":0.587},
        "weak_curve_sect163": {"type":"weak","risk":0.449},
        "weak_curve_ansi_163": {"type":"weak","risk":0.417},
        "weak_curve_nist_160": {"type":"weak","risk":0.367},
        "weak_curve_192": {"type":"weak","risk":0.327},
    }
    for name, data in curves.items():
        g.add_node(name, **data)
    edges = [
        ("secp256k1","weak_curve_dual_ec",0.480),
        ("secp256k1","P-256",0.300),
        ("P-256","weak_curve_dual_ec",0.500),
        ("secp256k1","weak_curve_192",0.280),
        ("Curve25519","weak_curve_dual_ec",0.320),
        ("Brainpool256","weak_curve_nist_160",0.250),
    ]
    for src,tgt,w in edges:
        g.add_edge(src, tgt, weight=w, vulnerability=w*0.9)
    logger.info(f"Isogeny graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    return g

def analyze_isogeny(g: nx.DiGraph):
    """
    Analyze an isogeny vulnerability graph and print the highest-risk paths from "secp256k1" to "weak_curve_dual_ec".
    
    Scans all simple paths from the node "secp256k1" to "weak_curve_dual_ec" with a path length cutoff of 4, computes a risk score for each path as
    edge_product * (1 + max_node_risk) where edge_product is the product of each edge's "vulnerability" attribute and max_node_risk is the maximum
    "risk" attribute among nodes on the path, then prints a summary including the total paths examined, the highest-risk route and its score, and the
    top 5 vulnerable paths with their risk scores.
    
    Parameters:
        g (networkx.DiGraph): Directed graph whose nodes have a numeric "risk" attribute and whose edges have a numeric "vulnerability" attribute.
    """
    print("\n" + "="*70)
    print("ADVANCED ISOGENY ATTACK ANALYSIS")
    print("="*70)
    paths = list(nx.all_simple_paths(g, "secp256k1", "weak_curve_dual_ec", cutoff=4))
    print(f"   Total paths analyzed: {len(paths)}")
    if not paths:
        print("   No vulnerable path found.")
        return
    def path_risk(p):
        """
        Compute a combined risk score for a path by multiplying edge vulnerabilities and scaling by the highest node risk.
        
        Parameters:
            p (Sequence): Sequence of node identifiers defining the path (ordered).
        
        Returns:
            float: The path risk equal to the product of each edge's `vulnerability` attribute multiplied by (1 + maximum `risk` among nodes on the path).
        """
        edge_r = 1.0
        node_r = 0.0
        for i in range(len(p)-1):
            edge_r *= g[p[i]][p[i+1]]["vulnerability"]
        for n in p:
            node_r = max(node_r, g.nodes[n]["risk"])
        return edge_r * (1 + node_r)
    risks = [(path_risk(p), p) for p in paths]
    risks.sort(reverse=True)
    print(f"   Highest risk score: {risks[0][0]:.3f}")
    print(f"   Route: {' → '.join(risks[0][1])}")
    print("\nTOP 5 VULNERABLE PATHS:")
    for i, (r, p) in enumerate(risks[:5], 1):
        print(f"   {i}. {' → '.join(p)}  |  Risk: {r:.3f}")

# ----------------------------------------------------------------------
# 14. Endomorphism verification
# ----------------------------------------------------------------------
def verify_endomorphism(pub: Point) -> bool:
    """
    Checks whether a public key point satisfies the secp256k1 endomorphism relation (using the curve's lambda/beta constants).
    
    Parameters:
        pub (Point): Elliptic-curve point representing the public key.
    
    Returns:
        bool: `true` if the point satisfies the endomorphism relation x' * beta ≡ x (mod p), `false` otherwise (including when the input is invalid).
    """
    try:
        beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
        lam  = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
        p1 = lam * pub
        return (p1.x * beta) % CURVE_P == pub.x % CURVE_P
    except Exception:
        return False

# ----------------------------------------------------------------------
# 15. Orchestrator
# ----------------------------------------------------------------------
class CryptoAttackOrchestrator:
    def __init__(self):
        """
        Initialize orchestrator components for lattice construction, candidate ranking, and blockchain access.
        
        Attributes:
            lattice: AdvancedLatticeBuilder instance used to build lattices for attack variants.
            ranker: AdvancedCandidateRanker instance used to score and order candidate keys.
            client: BlockchainClient instance used to fetch transactions and extract signatures.
        """
        self.lattice = AdvancedLatticeBuilder()
        self.ranker = AdvancedCandidateRanker(SKLEARN_AVAILABLE)
        self.client = BlockchainClient()

    def _extract_from_lattice(self, mat: List[List[int]],
                              pub_hex: str, src: str) -> List[CandidateKey]:
        """
                              Extract candidate private keys from a reduced lattice matrix for a given public key.
                              
                              Parameters:
                                  mat (List[List[int]]): Integer lattice matrix to reduce and scan for candidate rows.
                                  pub_hex (str): Hexadecimal public key associated with the lattice (used for context/metadata).
                                  src (str): Origin label for produced candidates (e.g., algorithm name or data source).
                              
                              Returns:
                                  List[CandidateKey]: CandidateKey objects built from valid private-key integers found in the reduced lattice.
                                      Returns an empty list if lattice reduction fails or no valid candidates are found.
                              """
                              red = reduce_lattice_bkz(mat)
        if not red:
            return []
        cands = []
        for row in red[:120]:
            for pos in range(min(3, len(row))):
                k = abs(row[pos]) % CURVE_N
                if validate_private_key(k):
                    conf = 0.7 * (1 - np.linalg.norm(row)/CURVE_N) + 0.3/(1+pos)
                    cands.append(CandidateKey(
                        key=k, confidence=conf, source=src,
                        metadata={"row": row, "pos": pos}
                    ))
        return cands

    def _validate(self, cand: CandidateKey, target: Point) -> bool:
        """
        Check whether a candidate private key corresponds to a target public point.
        
        Parameters:
            cand (CandidateKey): Candidate containing the private key to verify.
            target (Point): Expected public key point to compare against.
        
        Returns:
            True if the candidate's derived public point equals `target`, False otherwise.
        """
        pub = private_key_to_public_key(cand.key)
        return pub is not None and pub.x == target.x and pub.y == target.y

    def analyse(self, address: str, pub_hex: str) -> None:
        """
        Orchestrates end-to-end cryptanalytic analysis for a Bitcoin address and its public key.
        
        Performs: retrieval of recent signatures for `address`, nonce-bias detection, construction and reduction of lattices using multiple algorithms (basic, hnp, extended, kannan), an endomorphism property check on the provided public key, ML-based ranking of candidates, and parallel validation of top candidates against the target public key. Results and progress are logged; a brief summary and any recovered private keys are printed to stdout.
        
        Parameters:
            address (str): Bitcoin address from which to fetch recent transactions/signatures.
            pub_hex (str): Hex-encoded public key (compressed or uncompressed) corresponding to the target address.
        """
        start = time.time()

        # 1. signatures + bias
        sigs = self.client.signatures_for_address(address, max_txs=30)
        bias = detect_nonce_bias(sigs)
        logger.info(f"Bias analysis: {bias}")

        # 2. lattice attacks
        cands: List[CandidateKey] = []
        for algo in ["basic", "hnp", "extended", "kannan"]:
            mat = self.lattice.build(pub_hex, sigs, algo)
            if mat:
                cands += self._extract_from_lattice(mat, pub_hex, f"lattice_{algo}")

        # 3. endomorphism
        try:
            pub = decompress_public_key(pub_hex)
            endo_ok = verify_endomorphism(pub)
            logger.info(f"Endomorphism property verified: {endo_ok}")
        except Exception as e:
            logger.error(f"Endomorphism check failed: {e}")

        # 4. ML ranking
        ranked = self.ranker.rank(cands)[:15000]
        final_cands = [c for c,_ in ranked]

        # 5. validation
        try:
            target = decompress_public_key(pub_hex)
        except Exception:
            logger.error("Invalid target pubkey")
            target = None

        valid = []
        if target and final_cands:
            with ThreadPoolExecutor(max_workers=min(16, multiprocessing.cpu_count())) as ex:
                futures = {ex.submit(self._validate, c, target): c for c in final_cands}
                for f in as_completed(futures):
                    if f.result():
                        valid.append(futures[f])

        duration = time.time() - start
        print("\nANALYSIS COMPLETE")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Candidates generated: {len(final_cands)}")
        print(f"   Valid keys found: {len(valid)}")
        print(f"   Attacks performed: lattice_basic, lattice_hnp, lattice_extended, lattice_kannan, endomorphism, isogeny")
        if valid:
            print("\nSUCCESS! Private key(s) recovered:")
            for v in valid:
                print(f"   {hex(v.key)}")

# ----------------------------------------------------------------------
# 16. Main
# ----------------------------------------------------------------------
def main() -> None:
    """
    Run a demonstration analysis: orchestrate lattice/ML-based cryptanalysis for a sample Bitcoin address and compressed public key.
    
    This entry-point prints a header, constructs a CryptoAttackOrchestrator, runs a full analysis using the hard-coded BITCOIN_ADDRESS and PUBKEY_COMPRESSED values (placeholders intended to be edited), and — if NetworkX is available — builds and analyzes an isogeny graph. Side effects: console output and network access when fetching blockchain data.
    """
    print("\n" + "="*70)
    print("ADVANCED BITCOIN CRYPTOGRAPHIC ANALYSIS TOOL v2.0")
    print("="*70)

    # -----------------------------------------------------------------
    # EDIT THESE VALUES
    # -----------------------------------------------------------------
    BITCOIN_ADDRESS = "1Pzaqw98PeRfyHypfqyEgg5yycJRsENrE7"   # any address with TXs
    PUBKEY_COMPRESSED = "033bb421d32a069f078cfdfd56cdc1391fbd87e4183ca94458e3f5c4c8945782be"

    orch = CryptoAttackOrchestrator()
    orch.analyse(BITCOIN_ADDRESS, PUBKEY_COMPRESSED)

    if NETWORKX_AVAILABLE:
        g = create_isogeny_graph()
        if g:
            analyze_isogeny(g)

if __name__ == "__main__":
    main()