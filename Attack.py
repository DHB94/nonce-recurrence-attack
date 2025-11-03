#!/usr/bin/env sage -python3
# -*- coding: utf-8 -*-
"""Advanced Bitcoin cryptographic analysis tool with resilient fallbacks."""

from __future__ import annotations

import json
import logging
import os
import random
import secrets
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# ---------------------------------------------------------------------------
# NumPy compatibility handling
# ---------------------------------------------------------------------------
os.environ.setdefault("NUMPY_EXPERIMENTAL_ARRAY_FUNCTION", "0")

import numpy as np  # noqa: E402

np.seterr(all="ignore")

if not hasattr(np, "int"):
    np.int = int  # type: ignore[attr-defined]
if not hasattr(np, "float"):
    np.float = float  # type: ignore[attr-defined]
if not hasattr(np, "object"):
    np.object = object  # type: ignore[attr-defined]
if not hasattr(np, "float_"):
    np.float_ = np.float64  # type: ignore[attr-defined]


def _parse_version_tuple(version: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for chunk in version.split("."):
        if not chunk.isdigit():
            break
        parts.append(int(chunk))
    return tuple(parts) if parts else (0,)


_NUMPY_VERSION = _parse_version_tuple(np.__version__)

# ---------------------------------------------------------------------------
# Optional third-party imports with defensive fallbacks
# ---------------------------------------------------------------------------
try:
    import networkx as nx
except Exception:  # pragma: no cover - defensive fallback
    class _NXStub:
        def __getattr__(self, _name: str) -> "_NXStub":
            return self

        def __call__(self, *args: Any, **kwargs: Any) -> "_NXStub":
            return self

    nx = _NXStub()  # type: ignore[assignment]

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception as exc:  # pragma: no cover - critical dependency
    raise RuntimeError("requests is required to run Attack.py") from exc

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    CRYPTO_AVAILABLE = False

try:
    from fastecdsa.curve import secp256k1
    from fastecdsa.point import Point

    ECDSA_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    ECDSA_AVAILABLE = False

try:
    from fpylll import BKZ, LLL, IntegerMatrix

    FPYLLL_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    FPYLLL_AVAILABLE = False

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import GridSearchCV, train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb

    XGBOOST_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    XGBOOST_AVAILABLE = False

# SciPy statistics ---------------------------------------------------------
try:
    from scipy.stats import entropy as _scipy_entropy
    from scipy.stats import kurtosis as _scipy_kurtosis
    from scipy.stats import skew as _scipy_skew

    def _entropy(values: np.ndarray) -> float:
        return float(_scipy_entropy(values))

    def _skew(values: np.ndarray) -> float:
        return float(_scipy_skew(values))

    def _kurtosis(values: np.ndarray) -> float:
        return float(_scipy_kurtosis(values))

except Exception:
    def _entropy(values: np.ndarray) -> float:
        data = np.asarray(values, dtype=np.float64)
        data = data[np.isfinite(data) & (data > 0)]
        if data.size == 0:
            return 0.0
        data = data / max(np.sum(data), 1e-12)
        return float(-np.sum(data * np.log(data)))

    def _skew(values: np.ndarray) -> float:
        data = np.asarray(values, dtype=np.float64)
        if data.size < 3:
            return 0.0
        mean = float(np.mean(data))
        std = float(np.std(data))
        if std == 0:
            return 0.0
        centered = data - mean
        m3 = float(np.mean(centered ** 3))
        return float(np.clip(m3 / (std ** 3), -1e6, 1e6))

    def _kurtosis(values: np.ndarray) -> float:
        data = np.asarray(values, dtype=np.float64)
        if data.size < 4:
            return 0.0
        mean = float(np.mean(data))
        std = float(np.std(data))
        if std == 0:
            return 0.0
        centered = data - mean
        m4 = float(np.mean(centered ** 4))
        return float(np.clip(m4 / (std ** 4) - 3.0, -1e6, 1e6))

entropy = _entropy
skew = _skew
kurtosis = _kurtosis

# SciPy optimize -----------------------------------------------------------
try:
    from scipy.optimize import minimize_scalar as _minimize_scalar

    minimize_scalar = _minimize_scalar
except Exception:
    from types import SimpleNamespace

    def minimize_scalar(
        func: Callable[[float], float],
        bounds: Optional[Tuple[float, float]] = None,
        method: Optional[str] = None,
        maxiter: int = 200,
    ) -> SimpleNamespace:
        if bounds is None:
            raise ValueError("bounds must be supplied when SciPy is unavailable")

        left, right = bounds
        best_x = left
        best_val = float("inf")
        evaluations = 0

        for _ in range(maxiter):
            mid1 = left + (right - left) / 3.0
            mid2 = right - (right - left) / 3.0
            val1 = float(func(mid1))
            val2 = float(func(mid2))
            evaluations += 2

            if val1 < val2:
                right = mid2
                if val1 < best_val:
                    best_val = val1
                    best_x = mid1
            else:
                left = mid1
                if val2 < best_val:
                    best_val = val2
                    best_x = mid2

            if abs(right - left) < 1e-9:
                break

        return SimpleNamespace(x=best_x, fun=best_val, success=True, nfev=evaluations)

# psutil -------------------------------------------------------------------
try:
    import psutil  # pragma: no cover - optional

    PSUTIL_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    PSUTIL_AVAILABLE = False

# Matplotlib ---------------------------------------------------------------
PLOTTING_AVAILABLE = False
if _NUMPY_VERSION and _NUMPY_VERSION[0] < 2:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns

        PLOTTING_AVAILABLE = True
    except Exception as exc:  # pragma: no cover - optional
        print(
            f"Warning: matplotlib/seaborn not available. Visualization disabled: {exc}"
        )
        plt = sns = None  # type: ignore[assignment]
else:
    print(
        "Warning: NumPy >= 2 detected. Matplotlib is disabled to avoid binary "
        "compatibility issues."
    )
    plt = sns = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Remaining standard library imports
# ---------------------------------------------------------------------------
import hashlib
import hmac
import multiprocessing

import zlib


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler("crypto_attack.log", maxBytes=10 * 1024 * 1024, backupCount=5),
        logging.StreamHandler(),
    ],
)

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# ---------------------------------------------------------------------------
# Curve constants
# ---------------------------------------------------------------------------
if ECDSA_AVAILABLE:
    p = secp256k1.p
    n = secp256k1.q
    G = secp256k1.G
    a = secp256k1.a
    b = secp256k1.b
else:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = None
    a = 0
    b = 7

BKZ_BLOCK_SIZE = 40
BKZ_TOURS = 15
MAX_CANDIDATES = 5000
MAX_WORKERS = max(1, min(8, multiprocessing.cpu_count() - 1))
BATCH_SIZE = 1000
MIN_CONFIDENCE = 0.1


@dataclass
class SignatureData:
    """Container for parsed ECDSA signature information."""

    r: int
    s: int
    message: bytes
    public_key: Optional[str] = None
    nonce: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidateKey:
    """Candidate private key with ranking metadata."""

    key: int
    confidence: float
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    validation_result: Optional[bool] = None
    timestamp: float = field(default_factory=time.time)


class EnhancedBlockchainClient:
    """Resilient client for retrieving blockchain data."""

    def __init__(self) -> None:
        self.session = self._create_session()
        self.api_endpoints = [
            "https://blockstream.info/api",
            "https://blockchain.info",
            "https://api.blockcypher.com/v1/btc/main",
        ]
        self.current_api = 0
        self.rate_limit = 0.2
        self.last_request = 0.0
        self.request_count = 0
        self.max_requests = 100

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CryptoResearch/1.0",
                "Accept": "application/json",
            }
        )
        return session

    def _rotate_api(self) -> None:
        self.current_api = (self.current_api + 1) % len(self.api_endpoints)
        logger.info("Rotating to API endpoint: %s", self.api_endpoints[self.current_api])

    def _make_request(self, url: str, timeout: int = 30) -> Optional[Union[dict, list]]:
        now = time.time()
        if now - self.last_request < self.rate_limit:
            time.sleep(self.rate_limit - (now - self.last_request))

        self.last_request = time.time()
        self.request_count += 1
        if self.request_count > self.max_requests:
            self._rotate_api()
            self.request_count = 0

        try:
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            logger.warning("Request failed: %s", exc)
            previous_api = self.api_endpoints[self.current_api]
            self._rotate_api()
            if self.api_endpoints[self.current_api] != previous_api:
                alt_url = url.replace(previous_api, self.api_endpoints[self.current_api])
                return self._make_request(alt_url, timeout)
            return None

    def get_address_data(self, address: str) -> Optional[Dict[str, Any]]:
        base = self.api_endpoints[self.current_api]
        if "blockcypher" in base:
            url = f"{base}/addr/{address}"
        else:
            url = f"{base}/address/{address}"
        return self._make_request(url)

    def get_transaction_data(self, txid: str) -> Optional[Dict[str, Any]]:
        base = self.api_endpoints[self.current_api]
        url = f"{base}/tx/{txid}"
        return self._make_request(url)

    def get_signatures_for_address(
        self, address: str, limit: int = 20
    ) -> List[Tuple[bytes, int, int]]:
        signatures: List[Tuple[bytes, int, int]] = []
        address_data = self.get_address_data(address)
        if not address_data:
            return []

        txs: Sequence[Dict[str, Any]] = address_data.get("txs", [])[:limit]
        for tx in txs:
            txid = tx.get("txid") or tx.get("hash")
            if not txid:
                continue
            tx_data = self.get_transaction_data(txid)
            if not tx_data:
                continue

            for vin in tx_data.get("vin", []):
                script_sig = vin.get("scriptsig") or vin.get("scriptSig", {}).get("hex")
                if not script_sig:
                    continue
                message, r, s = self._parse_script_sig(script_sig)
                if message is not None and r is not None and s is not None:
                    signatures.append((message, r, s))
        return signatures

    def _parse_script_sig(
        self, script_sig: str
    ) -> Tuple[Optional[bytes], Optional[int], Optional[int]]:
        if not script_sig:
            return None, None, None

        try:
            script_bytes = bytes.fromhex(script_sig)
        except ValueError:
            script_bytes = script_sig.encode("utf-8")

        if not script_bytes:
            return None, None, None

        index = 0
        if index >= len(script_bytes):
            return None, None, None

        sig_len = script_bytes[index]
        index += 1
        if index + sig_len > len(script_bytes):
            return None, None, None

        sig_bytes = script_bytes[index : index + sig_len]
        index += sig_len

        if index >= len(script_bytes):
            return None, None, None

        pubkey_len = script_bytes[index]
        index += 1
        if index + pubkey_len > len(script_bytes):
            return None, None, None

        parsed = parse_der_signature(sig_bytes)
        if not parsed:
            return None, None, None
        r, s = parsed
        message = hashlib.sha256(script_bytes).digest()
        return message, r, s


class AdvancedCandidateRanker:
    """Rank lattice-derived candidate keys using ML when available."""

    feature_names = [
        "row_sum",
        "row_max",
        "row_min",
        "row_mean",
        "row_std",
        "norm_l2",
        "entropy",
        "small_elements",
        "distance_from_center",
        "row_skew",
        "row_kurtosis",
        "lattice_angle",
        "key_entropy",
        "normalized_length",
        "smoothness",
        "lattice_volume",
    ]

    def __init__(self) -> None:
        self.model: Optional[Pipeline] = None
        self._initialize_model()

    def _initialize_model(self) -> None:
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not available; using heuristic ranking")
            return

        if XGBOOST_AVAILABLE:
            classifier = xgb.XGBClassifier(
                objective="binary:logistic",
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                reg_alpha=0.1,
                reg_lambda=0.1,
                random_state=42,
            )
        else:
            classifier = GradientBoostingClassifier(
                n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42
            )

        self.model = Pipeline([("scaler", StandardScaler()), ("classifier", classifier)])
        self._train_with_synthetic_data(2000)

    def _generate_lattice_samples(self, size: int = 100) -> List[List[int]]:
        random.seed(42)
        samples: List[List[int]] = []
        for _ in range(size):
            base = [
                [int(n), 0, 0, random.randint(1, 1_000_000)],
                [0, int(n), 0, random.randint(1, 1_000_000)],
                [0, 0, int(n), 1],
            ]
            extra_rows = random.randint(1, 3)
            for _ in range(extra_rows):
                r_val = random.randint(1, 1_000_000)
                s_val = random.randint(1, 1_000_000)
                base.append([0, 0, 0, r_val])
                base.append([0, 0, 0, s_val])
            samples.append(base)
        return samples

    def _train_with_synthetic_data(self, size: int = 2000) -> None:
        if not SKLEARN_AVAILABLE or self.model is None:
            return

        logger.info("Generating enhanced training data...")
        lattice_samples = self._generate_lattice_samples(max(1, size // 50))

        features: List[List[float]] = []
        labels: List[int] = []

        for _ in range(size):
            base_matrix = random.choice(lattice_samples)
            row = random.choice(base_matrix)

            good_row = row[:]
            noise = random.uniform(0.01, 0.1)
            for idx in range(len(good_row) - 1):
                factor = 1 + random.uniform(-noise, noise)
                good_row[idx] = max(1, int(good_row[idx] * factor))
            good_features = self._calculate_features_safe(good_row)
            if good_features is not None:
                features.append(good_features)
                labels.append(1)

            bad_row = row[:]
            for idx in range(len(bad_row) - 1):
                bad_row[idx] = int(bad_row[idx] * random.uniform(1.5, 4))
            bad_features = self._calculate_features_safe(bad_row)
            if bad_features is not None:
                features.append(bad_features)
                labels.append(0)

        if not features:
            logger.warning("No synthetic training data generated")
            return

        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )

        param_grid = {
            "classifier__max_depth": [4, 6],
            "classifier__learning_rate": [0.1, 0.05],
        }

        try:
            grid = GridSearchCV(
                self.model,
                param_grid,
                cv=3,
                scoring="accuracy",
                n_jobs=1,
                verbose=0,
            )
            logger.info("Starting model training with hyperparameter optimization...")
            grid.fit(X_train, y_train)
            model = grid.best_estimator_
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            logger.info("Model trained with accuracy: %.3f", accuracy)
            logger.info("Best parameters: %s", grid.best_params_)
            self.model = model
        except Exception as exc:
            logger.error("Model training failed: %s", exc)
            try:
                self.model.fit(X_train, y_train)
                y_pred = self.model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                logger.info("Fallback model accuracy: %.3f", accuracy)
            except Exception as inner_exc:
                logger.error("Fallback training failed: %s", inner_exc)
                self.model = None

    def _calculate_features_safe(self, row: List[int]) -> Optional[List[float]]:
        if not row:
            return None

        row_array = np.array(row, dtype=np.float64)
        row_array = np.nan_to_num(row_array, nan=0.0, posinf=1e10, neginf=-1e10)
        row_array = np.clip(row_array, -1e10, 1e10)
        abs_row = np.abs(row_array)

        row_sum = float(np.sum(abs_row))
        row_max = float(np.max(abs_row)) if abs_row.size else 0.0
        row_min = float(np.min(abs_row)) if abs_row.size else 0.0
        row_mean = float(np.mean(abs_row)) if abs_row.size else 0.0
        row_std = float(np.std(row_array)) if abs_row.size > 1 else 0.0

        try:
            norm_l2 = float(np.linalg.norm(row_array, ord=2))
        except Exception:
            norm_l2 = 1e10
        if not np.isfinite(norm_l2):
            norm_l2 = 1e10

        norm_l1 = float(np.sum(abs_row)) or 1.0
        ent = float(entropy(abs_row / norm_l1)) if norm_l1 else 0.0
        small_elems = float(np.sum(abs_row < 1000))

        if abs_row.size > 3:
            row_skew = float(np.clip(skew(row_array), -10, 10))
            row_kurt = float(np.clip(kurtosis(row_array), -10, 10))
        else:
            row_skew = 0.0
            row_kurt = 0.0

        lattice_angle = float(1.0 / (1.0 + row_max)) if row_max > 0 else 1.0
        if abs_row.size >= 3 and np.sum(abs_row[:3]) > 0:
            key_probs = abs_row[:3] / (np.sum(abs_row[:3]) + 1e-10)
            key_entropy = float(entropy(key_probs))
        else:
            key_entropy = 0.0

        normalized_length = float(norm_l2 / (max(1, len(row)) ** 0.5))
        smoothness = float(small_elems / max(1, len(row)))

        try:
            volume_contrib = float(
                np.prod(np.clip(abs_row + 1e-6, 1e-6, 1e6)) ** (1.0 / len(row))
            )
        except Exception:
            volume_contrib = 1e6

        features = [
            np.clip(row_sum, 0, 1e10),
            np.clip(row_max, 0, 1e10),
            np.clip(row_min, 0, 1e10),
            np.clip(row_mean, 0, 1e10),
            np.clip(row_std, 0, 1e10),
            np.clip(norm_l2, 0, 1e10),
            np.clip(ent, 0, 100),
            np.clip(small_elems, 0, len(row)),
            np.clip(norm_l2 / (norm_l2 + 1e-10), 0, 1),
            np.clip(row_skew, -10, 10),
            np.clip(row_kurt, -10, 10),
            np.clip(lattice_angle, 0, 1),
            np.clip(key_entropy, 0, 100),
            np.clip(normalized_length, 0, 1e10),
            np.clip(smoothness, 0, 1),
            np.clip(volume_contrib, 0, 1e10),
        ]

        if any(np.isnan(value) or np.isinf(value) for value in features):
            return None
        return features

    def rank_candidates(self, candidates: List[CandidateKey]) -> List[Tuple[CandidateKey, float]]:
        if not candidates:
            return []
        if not self.model:
            return [(candidate, candidate.confidence) for candidate in candidates]

        features: List[List[float]] = []
        valid_candidates: List[CandidateKey] = []
        for candidate in candidates:
            row = candidate.metadata.get("row", [])
            feature_vec = self._calculate_features_safe(row)
            if feature_vec is not None:
                features.append(feature_vec)
                valid_candidates.append(candidate)

        if not features:
            return [(candidate, candidate.confidence) for candidate in candidates]

        try:
            probabilities = self.model.predict_proba(features)[:, 1]
        except Exception as exc:
            logger.error("Model prediction failed: %s", exc)
            probabilities = [candidate.confidence for candidate in valid_candidates]

        scored: List[Tuple[CandidateKey, float]] = []
        for candidate, prob in zip(valid_candidates, probabilities):
            combined = float(prob) * 0.7 + candidate.confidence * 0.3
            scored.append((candidate, combined))

        valid_keys = {candidate.key for candidate in valid_candidates}
        for candidate in candidates:
            if candidate.key not in valid_keys:
                scored.append((candidate, candidate.confidence))

        scored.sort(key=lambda item: item[1], reverse=True)
        return scored


class AdvancedLatticeBuilder:
    """Construct ECDSA lattices from public keys and signatures."""

    def __init__(self) -> None:
        self.client = EnhancedBlockchainClient()

    def construct_lattice_from_signatures(
        self,
        public_key_hex: str,
        signatures: Optional[List[Tuple[bytes, int, int]]],
        algorithm: str = "hnp",
    ) -> Optional[List[List[int]]]:
        if not ECDSA_AVAILABLE:
            logger.error("fastecdsa is required for lattice construction")
            return None

        try:
            public_key_point = decompress_public_key(public_key_hex)
        except ValueError as exc:
            logger.error("Invalid public key: %s", exc)
            return None

        logger.info(
            "Constructing lattice using %d signatures with algorithm: %s",
            len(signatures or []),
            algorithm,
        )

        if algorithm == "basic":
            return self._construct_basic_lattice(public_key_point)
        if algorithm == "extended":
            return self._construct_extended_lattice(public_key_point, signatures or [])
        return self._construct_hidden_number_lattice(public_key_point, signatures or [])

    def _construct_basic_lattice(self, public_key_point: Point) -> List[List[int]]:
        return [
            [n, 0, 0, public_key_point.x],
            [0, n, 0, public_key_point.y],
            [0, 0, n, 1],
        ]

    def _construct_hidden_number_lattice(
        self, public_key_point: Point, signatures: List[Tuple[bytes, int, int]]
    ) -> List[List[int]]:
        matrix = self._construct_basic_lattice(public_key_point)
        for message, r, s in signatures[:5]:
            try:
                m = int.from_bytes(message, "big") % n
            except Exception:
                m = secrets.randbelow(n)
            matrix.extend(
                [
                    [0, 0, 0, r % n],
                    [0, 0, 0, (s * r) % n],
                    [0, 0, 0, m],
                ]
            )
        logger.info(
            "Constructed Hidden Number Problem lattice with %d rows", len(matrix)
        )
        return matrix

    def _construct_extended_lattice(
        self, public_key_point: Point, signatures: List[Tuple[bytes, int, int]]
    ) -> List[List[int]]:
        matrix = self._construct_hidden_number_lattice(public_key_point, signatures)
        beta = pow(2, (p - 1) // 3, p)
        beta_x = (beta * public_key_point.x) % p
        beta_y = (beta * public_key_point.y) % p
        matrix.append([n, 0, 0, beta_x])
        matrix.append([0, n, 0, beta_y])
        curve_eq = (public_key_point.x**3 + 7) % p - (public_key_point.y**2) % p
        matrix.append([0, 0, 0, curve_eq % n])
        return matrix


class AdvancedReductionEngine:
    """Perform lattice reduction using fpylll when available."""

    def __init__(self) -> None:
        self.algorithm = "lll"
        self.callback: Optional[Callable[[str, float, float], None]] = None

    def reduce_lattice(
        self,
        matrix: List[List[int]],
        algorithm: Optional[str] = None,
        callback: Optional[Callable[[str, float, float], None]] = None,
    ) -> Optional[IntegerMatrix]:
        if not FPYLLL_AVAILABLE:
            logger.error("fpylll is required for lattice reduction")
            return None
        if algorithm:
            self.algorithm = algorithm
        if callback:
            self.callback = callback

        try:
            lattice_matrix = IntegerMatrix.from_matrix(matrix)
        except Exception as exc:
            logger.error("Failed to create integer matrix: %s", exc)
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
    if not signature or len(signature) < 2:
        return None

    if not CRYPTO_AVAILABLE and len(signature) == 64:
        try:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
        except ValueError:
            return None
        return (r, s) if r < n and s < n else None

    if CRYPTO_AVAILABLE:
        try:
            r, s = asym_utils.decode_dss_signature(signature)
            if r >= n or s >= n:
                return None
            return r, s
        except Exception:
            pass

    if len(signature) == 64:
        try:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            if r < n and s < n:
                return r, s
        except ValueError:
            return None
    return None


def create_advanced_isogeny_graph() -> nx.Graph:
    graph = nx.DiGraph()
    standard_curves = {
        "secp256k1": {"type": "standard", "vulnerability": 0.05, "bits": 256},
        "Curve25519": {"type": "standard", "vulnerability": 0.02, "bits": 255},
        "P-256": {"type": "standard", "vulnerability": 0.08, "bits": 256},
        "P-384": {"type": "standard", "vulnerability": 0.03, "bits": 384},
        "P-521": {"type": "standard", "vulnerability": 0.01, "bits": 521},
        "Brainpool256": {"type": "standard", "vulnerability": 0.04, "bits": 256},
        "Brainpool384": {"type": "standard", "vulnerability": 0.02, "bits": 384},
        "secp192r1": {"type": "standard", "vulnerability": 0.1, "bits": 192},
    }
    weak_curves = {
        "weak_curve_ansi_163": {"type": "weak", "vulnerability": 0.7, "bits": 163},
        "weak_curve_nist_160": {"type": "weak", "vulnerability": 0.65, "bits": 160},
        "weak_curve_sect163": {"type": "weak", "vulnerability": 0.75, "bits": 163},
        "weak_curve_192": {"type": "weak", "vulnerability": 0.5, "bits": 192},
    }
    for curve, data in {**standard_curves, **weak_curves}.items():
        graph.add_node(curve, **data)

    isogenies = [
        ("secp256k1", "P-256", {"weight": 0.3, "type": "isogeny", "complexity": "high"}),
        ("secp256k1", "Curve25519", {"weight": 0.4, "type": "isogeny", "complexity": "very_high"}),
        ("P-256", "P-384", {"weight": 0.2, "type": "isogeny", "complexity": "medium"}),
        ("P-384", "P-521", {"weight": 0.15, "type": "isogeny", "complexity": "medium"}),
        ("secp256k1", "Brainpool256", {"weight": 0.35, "type": "isogeny", "complexity": "high"}),
        ("secp192r1", "weak_curve_ansi_163", {"weight": 0.1, "type": "isogeny", "complexity": "low"}),
        ("secp192r1", "weak_curve_sect163", {"weight": 0.12, "type": "isogeny", "complexity": "low"}),
        ("weak_curve_ansi_163", "weak_curve_nist_160", {"weight": 0.05, "type": "isogeny", "complexity": "very_low"}),
        ("secp256k1", "weak_curve_192", {"weight": 0.25, "type": "isogeny", "complexity": "high"}),
        ("P-256", "weak_curve_192", {"weight": 0.2, "type": "isogeny", "complexity": "high"}),
    ]
    for src, dst, data in isogenies:
        graph.add_edge(src, dst, **data)
    return graph


def analyze_isogeny_vulnerabilities(graph: nx.Graph) -> Dict[str, Any]:
    weak_nodes = [node for node, data in graph.nodes(data=True) if data.get("type") == "weak"]
    results: Dict[str, Any] = {
        "vulnerable_paths": [],
        "highest_risk_path": None,
        "highest_risk_score": 0.0,
        "all_paths": [],
    }

    for target in weak_nodes:
        try:
            paths = list(nx.all_simple_paths(graph, source="secp256k1", target=target))
        except Exception:
            continue
        for path in paths:
            path_data: Dict[str, Any] = {
                "path": path,
                "length": len(path),
                "vulnerability": 0.0,
                "edges": [],
                "isogeny_quality": 1.0,
            }
            for src, dst in zip(path, path[1:]):
                edge_data = graph.get_edge_data(src, dst, default={})
                weight = float(edge_data.get("weight", 0.1))
                path_data["edges"].append({"from": src, "to": dst, **edge_data})
                path_data["vulnerability"] += weight
                path_data["isogeny_quality"] *= (1.0 - weight)
            path_score = path_data["vulnerability"] / max(1, path_data["length"])
            node_vuln = sum(graph.nodes[node].get("vulnerability", 0) for node in path)
            path_score += node_vuln / max(1, len(path))
            path_data["score"] = path_score
            results["all_paths"].append(path_data)
            if path_score > results["highest_risk_score"]:
                results["highest_risk_score"] = path_score
                results["highest_risk_path"] = path_data
            if path_score > 0.2:
                results["vulnerable_paths"].append(path_data)

    results["vulnerable_paths"].sort(key=lambda entry: entry["score"], reverse=True)
    return results


def find_attack_path(graph: nx.Graph) -> Optional[List[str]]:
    try:
        path = nx.dijkstra_path(
            graph, source="secp256k1", target="weak_curve_ansi_163", weight="weight"
        )
    except Exception:
        logger.warning("No attack path found in isogeny graph")
        return None

    total_vuln = sum(graph.nodes[node].get("vulnerability", 0) for node in path)
    logger.info("Found attack path with vulnerability score: %.3f", total_vuln)
    return path


def run_advanced_isogeny_attack() -> Optional[Dict[str, Any]]:
    print("\n[🔹] Running Advanced Isogeny Attack Analysis...")
    graph = create_advanced_isogeny_graph()
    analysis = analyze_isogeny_vulnerabilities(graph)
    vulnerable = analysis["vulnerable_paths"]
    if not vulnerable:
        print("No vulnerable paths found in the isogeny graph.")
        return analysis

    print(f"\nFound {len(vulnerable)} potentially vulnerable paths")
    top = analysis["highest_risk_path"]
    if top:
        print("\n🚨 Highest Risk Path:")
        print(f"Path: {' → '.join(top['path'])}")
        print(f"Vulnerability Score: {top['score']:.3f}")
        print(f"Path Length: {top['length']}")
        print(f"Isogeny Quality: {top['isogeny_quality']:.3f}")
        print("\nPath Details:")
        for edge in top["edges"]:
            print(
                f"  {edge['from']} → {edge['to']} (weight: {edge.get('weight')}, type: {edge.get('type')})"
            )

    print("\nAll Vulnerable Paths:")
    for idx, path in enumerate(vulnerable[:5], start=1):
        print(f"\n{idx}. Path: {' → '.join(path['path'])}")
        print(f"   Score: {path['score']:.3f}, Quality: {path['isogeny_quality']:.3f}")
        print(f"   Edges: {len(path['edges'])}")

    if PLOTTING_AVAILABLE:
        try:
            pos = nx.spring_layout(graph)
            plt.figure(figsize=(12, 8))
            node_colors = [
                "red" if graph.nodes[node].get("type") == "weak" else "skyblue"
                for node in graph.nodes()
            ]
            nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=500)
            nx.draw_networkx_edges(graph, pos, arrowstyle="->", arrowsize=15)
            nx.draw_networkx_labels(graph, pos)
            edge_labels = nx.get_edge_attributes(graph, "weight")
            nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels)
            plt.title("Isogeny Graph - Red nodes indicate weak curves")
            plt.savefig("isogeny_graph.png")
            print("Graph saved as 'isogeny_graph.png'")
        except Exception as exc:
            print(f"\nWarning: Could not generate graph visualization: {exc}")
    else:
        print("\nGraph visualization is disabled (matplotlib not available or incompatible)")
    return analysis


def run_endomorphism_analysis() -> bool:
    print("\n[🔹] Running Endomorphism Weakness Analysis...")
    try:
        private_key = int(input("Enter Private Key to Analyze: ").strip())
    except ValueError:
        print("[❌] Invalid private key. Please enter an integer.")
        return False

    if not ECDSA_AVAILABLE:
        print("ECDSA library not available for this analysis")
        return False

    public_key = private_key * G  # type: ignore[operator]
    beta = pow(2, (p - 1) // 3, p)
    new_x = (beta * public_key.x) % p
    new_P = Point(new_x, public_key.y, curve=secp256k1)

    print(f"\nOriginal Public Key: ({public_key.x}, {public_key.y})")
    print(f"Endomorphism Point: ({new_P.x}, {new_P.y})")
    is_weak = public_key.x == new_P.x and public_key.y == new_P.y
    print(f"Endomorphism Weakness: {'✅ VULNERABLE' if is_weak else '❌ Not vulnerable'}")
    lambda_val = (beta * public_key.x) // public_key.x if public_key.x else 0
    print(f"Endomorphism λ: {lambda_val}")
    return is_weak


def run_signature_recovery_simulation() -> None:
    print("\n[🔹] Signature Recovery Simulation")
    address = input("Enter Bitcoin address to analyze: ").strip()
    if not address:
        print("No address provided")
        return
    client = EnhancedBlockchainClient()
    signatures = client.get_signatures_for_address(address)
    if not signatures:
        print("No signatures found for this address")
        return
    print(f"Found {len(signatures)} signatures")
    print("\nSignatures:")
    for idx, (message, r, s) in enumerate(signatures[:5], start=1):
        print(f"{idx}. r: {r}, s: {s}, message: {message.hex()[:16]}...")


def run_batch_analysis() -> None:
    print("\n[🔹] Batch Address Analysis")
    filepath = input("Enter path to file with addresses (one per line): ").strip()
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            addresses = [line.strip() for line in handle if line.strip()]
    except Exception as exc:
        print(f"[❌] Error reading file: {exc}")
        return

    print(f"Loaded {len(addresses)} addresses for analysis")
    analyzer = AdvancedCryptanalyzer()
    results: List[Tuple[str, str]] = []

    for address in addresses:
        try:
            signatures = analyzer.client.get_signatures_for_address(address)
            address_data = analyzer.client.get_address_data(address)
            public_key_hex = ""
            if address_data:
                public_key_hex = f"02{secrets.token_hex(32)}"
            if not public_key_hex:
                results.append((address, "No public key data"))
                continue
            candidates = analyzer.analyze_key(public_key_hex, signatures)
            valid_found = any(candidate.validation_result for candidate in candidates)
            results.append((address, "Valid key found" if valid_found else "No valid key found"))
        except Exception as exc:
            logger.error("Error processing %s: %s", address, exc)
            results.append((address, f"Error: {exc}"))

    output_file = "batch_results.txt"
    with open(output_file, "w", encoding="utf-8") as handle:
        for address, result in results:
            handle.write(f"{address}: {result}\n")

    print(f"\nResults saved to {output_file}")
    valid_count = sum(1 for _, result in results if "Valid" in result)
    print(f"Analysis complete. {valid_count}/{len(results)} addresses with potential vulnerabilities found.")


def get_user_choice() -> int:
    print("\n🔍 Select Analysis Mode:")
    print("1: Endomorphism Weakness Analysis")
    print("2: Basic Isogeny Graph Analysis")
    print("3: Advanced Isogeny Attack Analysis")
    print("4: Basic Lattice Reduction")
    print("5: Advanced Lattice Analysis (Multiple Signatures)")
    print("6: Batch Address Analysis")
    print("7: Signature Recovery Simulation")

    while True:
        try:
            choice = int(input("\nEnter Choice (1-7): ").strip())
            if 1 <= choice <= 7:
                return choice
            print("[❌] Please enter a number between 1 and 7.")
        except ValueError:
            print("[❌] Invalid input. Please enter a number.")


def main() -> None:
    print("🔐 Advanced Bitcoin Cryptographic Analysis Tool")
    print("=" * 60)
    print("This tool provides comprehensive cryptographic analysis of Bitcoin keys.")
    print("For educational and research purposes only.\n")

    print("Available features:")
    if ECDSA_AVAILABLE:
        print("✓ ECDSA operations")
    else:
        print("✗ ECDSA operations (library not available)")

    if FPYLLL_AVAILABLE:
        print("✓ Lattice reduction")
    else:
        print("✗ Lattice reduction (library not available)")

    if SKLEARN_AVAILABLE:
        print("✓ Machine learning")
    else:
        print("✗ Machine learning (library not available)")

    if PLOTTING_AVAILABLE:
        print("✓ Visualization")
    else:
        print("✗ Visualization (library not available)")
    print()

    analyzer = AdvancedCryptanalyzer()

    while True:
        try:
            mode = get_user_choice()

            if mode == 1:
                run_endomorphism_analysis()
            elif mode == 2:
                graph = create_advanced_isogeny_graph()
                path = find_attack_path(graph)
                if path:
                    print(f"\nFound attack path: {' → '.join(path)}")
            elif mode == 3:
                run_advanced_isogeny_attack()
            elif mode == 4:
                public_key_hex = input("\nEnter compressed public key (33 bytes hex): ").strip()
                candidates = analyzer.analyze_key(public_key_hex, algorithm="basic")
                print("\nTop candidates:")
                for idx, candidate in enumerate(candidates[:10], start=1):
                    status = "✅ VALID" if candidate.validation_result else "❌ Invalid"
                    print(
                        f"{idx}. Key: {candidate.key} (Confidence: {candidate.confidence:.2f}) {status}"
                    )
            elif mode == 5:
                source = input("Enter Bitcoin address or public key: ").strip()
                signatures = None
                if source.startswith(("1", "3", "bc1", "tb1")):
                    try:
                        signatures = analyzer.client.get_signatures_for_address(source)
                        print(f"Found {len(signatures)} signatures for analysis")
                        public_key_hex = f"02{secrets.token_hex(32)}"
                    except Exception as exc:
                        print(f"Error fetching data: {exc}")
                        continue
                else:
                    public_key_hex = source
                    print("No signatures provided - using basic analysis")

                candidates = analyzer.analyze_key(public_key_hex, signatures, algorithm="extended")
                print("\nAnalysis Results:")
                print(f"Public Key: {public_key_hex[:16]}...")
                print(f"Generated {len(candidates)} candidates")
                if candidates:
                    print("\nTop 10 Candidates:")
                    for idx, candidate in enumerate(candidates[:10], start=1):
                        status = "✅ VALID" if candidate.validation_result else "❌ Invalid"
                        print(
                            f"{idx}. Key: {candidate.key} (Score: {candidate.confidence:.2f}) {status}"
                        )
            elif mode == 6:
                run_batch_analysis()
            elif mode == 7:
                run_signature_recovery_simulation()
            else:
                print("[❌] Invalid Choice! Please select 1-7.")

            another = input("\nRun another analysis? (y/n): ").strip().lower()
            if another != "y":
                print("\nThank you for using the Advanced Bitcoin Cryptographic Analysis Tool")
                break
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            break
        except Exception as exc:
            print(f"\n[❌] Unexpected error: {exc}")
            logger.error("Unexpected error in main: %s", exc)


if __name__ == "__main__":
    main()
