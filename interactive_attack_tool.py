import math
import random
from dataclasses import dataclass
from typing import Generator, List, Optional, Sequence, Tuple

import networkx as nx
import requests
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from fpylll import IntegerMatrix, LLL

p = secp256k1.p
n = secp256k1.q
G = secp256k1.G


def get_attack_mode():
    print("\n🔍 Select Attack Mode:")
    print("1: Endomorphism Weakness")
    print("2: Isogeny Graph Pathfinding")
    print("3: Lattice Reduction (Private Key Extraction)")

    while True:
        try:
            choice = int(input("Enter Choice (1/2/3): ").strip())
        except ValueError:
            print("[❌] Invalid input. Please enter 1, 2, or 3.")
            continue

        if choice in {1, 2, 3}:
            return choice

        print("[❌] Invalid choice. Please enter 1, 2, or 3.")


def check_endomorphism():
    print("\n[🔹] Running Endomorphism Weakness Check...")
    try:
        private_key = int(input("Enter Private Key to Analyze: ").strip())
        public_key = private_key * G
        beta = pow(2, (p - 1) // 3, p)
        new_x = (beta * public_key.x) % p
        new_P = Point(new_x, public_key.y, curve=secp256k1)
        print(f"Original Public Key: {public_key}")
        print(f"Weak Endomorphism Point: {new_P}")
    except ValueError:
        print("[❌] Invalid private key. Please enter an integer.")


def create_isogeny_graph():
    print("\n[🔹] Constructing Isogeny Graph...")

    while True:
        try:
            graph_size = int(input("Enter Graph Size (Recommended: 50+): ").strip())
        except ValueError:
            print("[❌] Invalid graph size. Please enter an integer.")
            continue

        if graph_size <= 0:
            print("[❌] Graph size must be positive.")
            continue

        graph = nx.Graph()
        for i in range(1, graph_size):
            graph.add_edge(i, i + 2)
        print("[✅] Isogeny Graph Created Successfully!")
        return graph


def find_attack_path(graph):
    try:
        start = int(input("Enter Start Node: ").strip())
        target = int(input("Enter Target Node: ").strip())
        path = nx.shortest_path(graph, source=start, target=target)
        print(f"⚡ Isogeny Attack Path Found: {path}")
    except ValueError:
        print("[❌] Invalid input. Please enter integers for start and target nodes.")
    except nx.NodeNotFound:
        print("[❌] One or both nodes do not exist in the graph.")
    except nx.NetworkXNoPath:
        print("[❌] No path exists between the selected nodes.")


class BlockstreamError(RuntimeError):
    """Raised when the Blockstream API request fails."""


@dataclass
class ScriptData:
    """Container for parsed script data from transaction inputs."""

    signatures: List[bytes]
    public_keys: List[str]


class BlockstreamClient:
    """Helper that streams transaction data for a Bitcoin address."""

    def __init__(self, base_url: str = "https://blockstream.info/api") -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def _get(self, endpoint: str) -> Sequence[dict]:
        response = self.session.get(endpoint, timeout=15)
        if response.status_code >= 400:
            raise BlockstreamError(
                f"Blockstream API error {response.status_code}: {response.text.strip()}"
            )
        return response.json()

    def iter_address_transactions(
        self, address: str, limit: Optional[int] = None
    ) -> Generator[dict, None, None]:
        """Yield transactions that spend from or pay to *address*.

        The Blockstream address endpoint returns results in reverse chronological
        order, 25 per page. For addresses with a large history we paginate using
        the "chain" variant to avoid storing all results in memory at once.
        """

        endpoint = f"{self.base_url}/address/{address}/txs"
        last_seen_txid: Optional[str] = None
        yielded = 0

        while True:
            if last_seen_txid is None:
                page_endpoint = endpoint
            else:
                page_endpoint = f"{endpoint}/chain/{last_seen_txid}"

            transactions = self._get(page_endpoint)
            if not transactions:
                return

            for tx in transactions:
                yield tx
                yielded += 1
                if limit is not None and yielded >= limit:
                    return

            last_seen_txid = transactions[-1]["txid"]

    @staticmethod
    def _read_push(data: bytes, index: int) -> Tuple[bytes, int]:
        opcode = data[index]
        index += 1
        if opcode <= 75:
            length = opcode
        elif opcode == 76:  # OP_PUSHDATA1
            length = data[index]
            index += 1
        elif opcode == 77:  # OP_PUSHDATA2
            length = int.from_bytes(data[index : index + 2], "little")
            index += 2
        elif opcode == 78:  # OP_PUSHDATA4
            length = int.from_bytes(data[index : index + 4], "little")
            index += 4
        else:
            return b"", index
        push = data[index : index + length]
        index += length
        return push, index

    @classmethod
    def _parse_script_sig(cls, script_sig_hex: str) -> ScriptData:
        if not script_sig_hex:
            return ScriptData(signatures=[], public_keys=[])

        raw = bytes.fromhex(script_sig_hex)
        signatures: List[bytes] = []
        public_keys: List[str] = []
        index = 0
        while index < len(raw):
            push, index = cls._read_push(raw, index)
            if not push:
                continue
            if len(push) in (33, 65):
                public_keys.append(push.hex())
            elif len(push) >= 70:
                signatures.append(push)
        return ScriptData(signatures=signatures, public_keys=public_keys)

    @staticmethod
    def _parse_witness(witness_data: Sequence[str]) -> ScriptData:
        if not witness_data:
            return ScriptData(signatures=[], public_keys=[])

        signatures: List[bytes] = []
        public_keys: List[str] = []
        for item in witness_data:
            raw = bytes.fromhex(item)
            if len(raw) in (33, 65):
                public_keys.append(raw.hex())
            elif len(raw) >= 70:
                signatures.append(raw)
        return ScriptData(signatures=signatures, public_keys=public_keys)

    @classmethod
    def extract_script_data(cls, tx: dict) -> ScriptData:
        signatures: List[bytes] = []
        public_keys: List[str] = []

        for vin in tx.get("vin", []):
            script_sig_data = cls._parse_script_sig(vin.get("scriptsig", ""))
            witness_data = cls._parse_witness(vin.get("witness", []))

            signatures.extend(script_sig_data.signatures)
            signatures.extend(witness_data.signatures)

            public_keys.extend(script_sig_data.public_keys)
            public_keys.extend(witness_data.public_keys)

        return ScriptData(signatures=signatures, public_keys=public_keys)

    def gather_public_keys(
        self, address: str, limit: Optional[int] = None
    ) -> List[str]:
        unique_keys: List[str] = []
        seen: set[str] = set()
        for tx in self.iter_address_transactions(address, limit=limit):
            script_data = self.extract_script_data(tx)
            for key_hex in script_data.public_keys:
                if key_hex not in seen:
                    seen.add(key_hex)
                    unique_keys.append(key_hex)
        return unique_keys

    def gather_signatures(
        self, address: str, limit: Optional[int] = None
    ) -> List[bytes]:
        signatures: List[bytes] = []
        for tx in self.iter_address_transactions(address, limit=limit):
            script_data = self.extract_script_data(tx)
            signatures.extend(script_data.signatures)
        return signatures


def _integer_matrix_rows(matrix: IntegerMatrix) -> List[List[int]]:
    """Convert an IntegerMatrix to a list of native Python rows."""

    rows: List[List[int]] = []
    nrows = matrix.nrows()
    ncols = matrix.ncols()
    for i in range(nrows):
        rows.append([int(matrix[i, j]) for j in range(ncols)])
    return rows


def decompress_public_key(public_key_hex: str) -> Point:
    if not public_key_hex:
        raise ValueError("Public key hex value is required")

    public_key_hex = public_key_hex.strip().lower()
    if len(public_key_hex) != 66:
        raise ValueError("Compressed public key must be 33 bytes (66 hex characters)")

    prefix = int(public_key_hex[:2], 16)
    if prefix not in (2, 3):
        raise ValueError("Invalid compressed public key prefix")

    x = int(public_key_hex[2:], 16)
    alpha = (pow(x, 3, p) + 7) % p
    beta = pow(alpha, (p + 1) // 4, p)
    if (beta % 2 == 0 and prefix == 3) or (beta % 2 == 1 and prefix == 2):
        beta = (-beta) % p

    return Point(x, beta, curve=secp256k1)


def parse_der_signature(signature: bytes) -> Optional[Tuple[int, int]]:
    if not signature:
        return None

    # Bitcoin DER signatures typically end with a sighash flag byte. Strip it
    # before handing the payload to a hardened ASN.1 decoder.
    core_signature = signature[:-1] if len(signature) > 1 else signature

    try:
        r, s = asym_utils.decode_dss_signature(core_signature)
    except ValueError:
        return None

    return r, s


def construct_optimal_lattice_matrix(public_key_hex: str):
    print("\n[🔹] Constructing Optimal Lattice Matrix for Private Key Recovery...")
    try:
        public_key_point = decompress_public_key(public_key_hex)
    except ValueError as error:
        print(f"[❌] {error}")
        return None

    print(f"Public Key Point (Q): {public_key_point}")

    matrix = [
        [n, 0, 0, public_key_point.x],
        [0, n, 0, public_key_point.y],
        [0, 0, n, 1],
    ]
    print("Optimal Lattice Matrix:")
    for row in matrix:
        print(row)
    return matrix


def _safe_modular_inverse(value: int, modulus: int) -> Optional[int]:
    """Return the multiplicative inverse when it exists."""

    value %= modulus
    if value == 0:
        return None
    try:
        return pow(value, -1, modulus)
    except ValueError:
        return None


@dataclass
class CandidateKey:
    """Container tying a lattice row to a candidate private key."""

    key: int
    row: List[int]


def extract_candidate_private_keys(lattice_matrix: IntegerMatrix) -> List[CandidateKey]:
    """Generate candidate private keys from the reduced lattice matrix."""

    rows = _integer_matrix_rows(lattice_matrix)
    candidates: List[CandidateKey] = []
    seen: set[int] = set()

    for row in rows:
        if not row:
            continue

        last_value = row[-1]
        modulus_candidate = abs(last_value) % n
        if modulus_candidate and modulus_candidate not in seen:
            seen.add(modulus_candidate)
            candidates.append(CandidateKey(modulus_candidate, row))

        if len(row) >= 2:
            numerator = row[-2]
            inverse = _safe_modular_inverse(last_value, n)
            if inverse is not None:
                derived = (numerator * inverse) % n
                if derived not in seen:
                    seen.add(derived)
                    candidates.append(CandidateKey(derived, row))

        for element in row:
            candidate = abs(element) % n
            if candidate and candidate not in seen:
                seen.add(candidate)
                candidates.append(CandidateKey(candidate, row))

    return candidates


class LogisticRankingModel:
    """Tiny logistic regression trained on synthetic lattice statistics."""

    _trained_parameters: Optional[Tuple[List[float], float, List[float], List[float]]] = None

    def __init__(self) -> None:
        if LogisticRankingModel._trained_parameters is None:
            LogisticRankingModel._trained_parameters = self._train()

        (
            trained_weights,
            trained_bias,
            trained_mean,
            trained_std,
        ) = LogisticRankingModel._trained_parameters

        self.weights = list(trained_weights)
        self.bias = float(trained_bias)
        self.feature_mean = list(trained_mean)
        self.feature_std = list(trained_std)

    def _generate_feature_vector(self, row: Sequence[int], candidate: int) -> List[float]:
        row_abs = [abs(value) for value in row]
        total = sum(row_abs) or 1
        min_val = min(row_abs) if row_abs else 0
        max_val = max(row_abs) if row_abs else 0
        spread = max_val - min_val
        distance_from_half = abs(candidate - (n // 2))
        return [
            math.log1p(total),
            math.log1p(min_val),
            math.log1p(max_val),
            math.log1p(spread),
            math.log1p(distance_from_half),
        ]

    def _synthetic_dataset(
        self, rng: random.Random, size: int = 256
    ) -> Tuple[List[List[float]], List[int]]:
        features: List[List[float]] = []
        labels: List[int] = []
        for _ in range(size):
            row = [rng.randint(-10_000, 10_000) for _ in range(4)]
            candidate = abs(rng.randint(1, n - 1))
            feature = self._generate_feature_vector(row, candidate)
            plausibility = 1 if min(abs(value) for value in row) < 500 else 0
            if abs(candidate - (n // 2)) < n // 10:
                plausibility = 0
            features.append(feature)
            labels.append(plausibility)
        return features, labels

    def _train(self) -> Tuple[List[float], float, List[float], List[float]]:
        rng = random.Random(1337)
        features, labels = self._synthetic_dataset(rng)
        if not features:
            return [], 0.0, [], []

        num_features = len(features[0])
        feature_mean = [0.0] * num_features
        feature_std = [1.0] * num_features

        for idx in range(num_features):
            column = [row[idx] for row in features]
            mean = sum(column) / len(column)
            variance = sum((value - mean) ** 2 for value in column) / max(
                len(column) - 1, 1
            )
            std = math.sqrt(variance) or 1.0
            feature_mean[idx] = mean
            feature_std[idx] = std

        normalized = [
            [
                (row[idx] - feature_mean[idx]) / feature_std[idx]
                for idx in range(num_features)
            ]
            for row in features
        ]

        learning_rate = 0.05
        weights = [0.0 for _ in range(num_features)]
        bias = 0.0

        for _ in range(200):
            gradient_w = [0.0 for _ in weights]
            gradient_b = 0.0
            for feats, label in zip(normalized, labels):
                z = sum(w * f for w, f in zip(weights, feats)) + bias
                prediction = 1.0 / (1.0 + math.exp(-z))
                error = prediction - label
                for idx, value in enumerate(feats):
                    gradient_w[idx] += error * value
                gradient_b += error

            weights = [
                w - learning_rate * gw / len(normalized)
                for w, gw in zip(weights, gradient_w)
            ]
            bias -= learning_rate * gradient_b / len(normalized)

        return weights, bias, feature_mean, feature_std

    def score(self, row: Sequence[int], candidate: int) -> float:
        feature = self._generate_feature_vector(row, candidate)
        if not self.weights:
            return 0.0
        normalized = [
            (value - mean) / std if std else 0.0
            for value, mean, std in zip(feature, self.feature_mean, self.feature_std)
        ]
        z = sum(w * f for w, f in zip(self.weights, normalized)) + self.bias
        return 1.0 / (1.0 + math.exp(-z))


class CandidateRanker:
    """Rank candidate private keys using a lightweight ML model."""

    def __init__(self) -> None:
        self.model = LogisticRankingModel()

    def rank(self, candidates: Sequence[CandidateKey]) -> List[Tuple[CandidateKey, float]]:
        scored: List[Tuple[CandidateKey, float]] = []
        for candidate in candidates:
            score = self.model.score(candidate.row, candidate.key)
            scored.append((candidate, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored


def verify_public_key_matches(private_key: int, public_key_hex: str) -> bool:
    try:
        target_point = decompress_public_key(public_key_hex)
    except ValueError:
        return False

    candidate_point = private_key * G
    return candidate_point == target_point


def lattice_attack():
    print("\n[🔹] Running Lattice Reduction Attack...")
    print("Provide a compressed secp256k1 public key (33-byte hex) or")
    print("optionally enter a Bitcoin address to retrieve keys via Blockstream.")
    print("Press Enter to use the supplied target key.")

    mode = input("Input Mode ([k]ey / [a]ddress / default): ").strip().lower()
    public_key_hex: Optional[str] = None

    if mode == "a":
        address = input("Bitcoin Address: ").strip()
        if not address:
            print("[❌] Address is required when selecting address mode.")
        else:
            client = BlockstreamClient()
            try:
                public_keys = client.gather_public_keys(address)
                signatures = client.gather_signatures(address)
            except (BlockstreamError, requests.RequestException) as error:
                print(f"[❌] Blockstream fetch failed: {error}")
                public_keys = []
                signatures = []

            if public_keys:
                print(f"[✅] Retrieved {len(public_keys)} unique public keys from Blockstream.")
                for index, key_hex in enumerate(public_keys, start=1):
                    marker = " (compressed)" if len(key_hex) == 66 else ""
                    print(f"  {index}. {key_hex}{marker}")
                selection = input(
                    "Select key index to target (press Enter for first available): "
                ).strip()
                try:
                    idx = int(selection) - 1 if selection else 0
                    public_key_hex = public_keys[idx]
                except (ValueError, IndexError):
                    print("[❌] Invalid selection. Falling back to default key.")
            else:
                print("[❌] No public keys recovered from Blockstream. Using default key.")

            if signatures:
                parsed = [parse_der_signature(sig) for sig in signatures]
                parsed = [item for item in parsed if item]
                if parsed:
                    print(f"[ℹ️] Parsed {len(parsed)} ECDSA signatures from address history.")
                else:
                    print("[⚠️] Unable to parse valid DER signatures from fetched data.")

    if public_key_hex is None:
        if mode == "k":
            public_key_hex = input("Compressed Public Key: ").strip()
        else:
            user_input = input("Compressed Public Key (press Enter for default): ").strip()
            public_key_hex = (
                user_input
                or "033bb421d32a069f078cfdfd56cdc1391fbd87e4183ca94458e3f5c4c8945782be"
            )

    matrix = construct_optimal_lattice_matrix(public_key_hex)
    if matrix is None:
        return

    lattice_matrix = IntegerMatrix.from_matrix(matrix)
    LLL.reduction(lattice_matrix)
    print("[✅] Lattice Reduction Completed!")
    print("Reduced Matrix (Potential Private Key Data):")
    print(lattice_matrix)
    candidates = extract_candidate_private_keys(lattice_matrix)
    if not candidates:
        print("[⚠️] Unable to derive candidate private keys from the reduced basis.")
        return

    ranker = CandidateRanker()
    ranked_candidates = ranker.rank(candidates)

    print("[🤖] AI-assisted ranking of candidate private keys:")
    for index, (candidate, score) in enumerate(ranked_candidates[:10], start=1):
        print(
            f"  {index}. key={candidate.key} (score={score:.4f}) row={candidate.row}"
        )

    print("[🔍] Verifying ranked candidates against the target public key...")
    matches: List[int] = []
    for candidate, score in ranked_candidates:
        if verify_public_key_matches(candidate.key, public_key_hex):
            print(
                f"[✅] Candidate {candidate.key} (score={score:.4f}) matches the target public key."
            )
            matches.append(candidate.key)

    if not matches:
        print("[❌] No ranked candidates matched the selected public key.")


if __name__ == "__main__":
    mode = get_attack_mode()
    if mode == 1:
        check_endomorphism()
    elif mode == 2:
        attack_graph = create_isogeny_graph()
        find_attack_path(attack_graph)
    elif mode == 3:
        lattice_attack()
    else:
        print("[❌] Invalid Choice! Restart and Select a Valid Option.")
