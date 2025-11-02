import math
import random
from dataclasses import dataclass
from typing import Generator, Iterable, List, Optional, Sequence, Tuple

import requests
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
    try:
        return int(input("Enter Choice (1/2/3): ").strip())
    except ValueError:
        print("[❌] Invalid input. Please enter 1, 2, or 3.")
        return get_attack_mode()


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
    import networkx as nx

    print("\n[🔹] Constructing Isogeny Graph...")
    try:
        graph_size = int(input("Enter Graph Size (Recommended: 50+): ").strip())
        graph = nx.Graph()
        for i in range(1, graph_size):
            graph.add_edge(i, i + 2)
        print("[✅] Isogeny Graph Created Successfully!")
        return graph
    except ValueError:
        print("[❌] Invalid graph size. Please enter an integer.")
        return create_isogeny_graph()


def find_attack_path(graph):
    import networkx as nx

    try:
        start = int(input("Enter Start Node: ").strip())
        target = int(input("Enter Target Node: ").strip())
        path = nx.shortest_path(graph, source=start, target=target)
        print(f"⚡ Isogeny Attack Path Found: {path}")
    except ValueError:
        print("[❌] Invalid nodes or no path exists.")
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
    if not signature or signature[0] != 0x30:
        return None

    try:
        total_length = signature[1]
        if total_length + 2 > len(signature):
            return None
        r_offset = 4
        r_length = signature[3]
        r = int.from_bytes(signature[r_offset : r_offset + r_length], "big")
        s_offset = r_offset + r_length + 2
        s_length = signature[s_offset - 1]
        s = int.from_bytes(signature[s_offset : s_offset + s_length], "big")
        return r, s
    except (IndexError, ValueError):
        return None


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


def _normalize(values: Iterable[float]) -> List[float]:
    data = list(values)
    if not data:
        return []
    mean = sum(data) / len(data)
    variance = sum((item - mean) ** 2 for item in data) / max(len(data) - 1, 1)
    std = math.sqrt(variance) or 1.0
    return [(item - mean) / std for item in data]


class LogisticRankingModel:
    """Tiny logistic regression trained on synthetic lattice statistics."""

    def __init__(self) -> None:
        self.weights: List[float] = []
        self.bias: float = 0.0
        self._train()

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

    def _synthetic_dataset(self, size: int = 256) -> Tuple[List[List[float]], List[int]]:
        features: List[List[float]] = []
        labels: List[int] = []
        for _ in range(size):
            row = [random.randint(-10_000, 10_000) for _ in range(4)]
            candidate = abs(random.randint(1, n - 1))
            feature = self._generate_feature_vector(row, candidate)
            plausibility = 1 if min(abs(value) for value in row) < 500 else 0
            if abs(candidate - (n // 2)) < n // 10:
                plausibility = 0
            features.append(feature)
            labels.append(plausibility)
        return features, labels

    def _train(self) -> None:
        features, labels = self._synthetic_dataset()
        if not features:
            return

        transposed = list(zip(*features))
        normalized_columns = [_normalize(column) for column in transposed]
        normalized = list(zip(*normalized_columns))
        learning_rate = 0.05
        self.weights = [0.0 for _ in range(len(normalized[0]))]
        self.bias = 0.0

        for _ in range(200):
            gradient_w = [0.0 for _ in self.weights]
            gradient_b = 0.0
            for feats, label in zip(normalized, labels):
                z = sum(w * f for w, f in zip(self.weights, feats)) + self.bias
                prediction = 1.0 / (1.0 + math.exp(-z))
                error = prediction - label
                for idx, value in enumerate(feats):
                    gradient_w[idx] += error * value
                gradient_b += error

            self.weights = [
                w - learning_rate * gw / len(normalized)
                for w, gw in zip(self.weights, gradient_w)
            ]
            self.bias -= learning_rate * gradient_b / len(normalized)

    def score(self, row: Sequence[int], candidate: int) -> float:
        feature = self._generate_feature_vector(row, candidate)
        normalized = _normalize(feature)
        if not self.weights or not normalized:
            return 0.0
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
