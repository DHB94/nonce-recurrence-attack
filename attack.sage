#!/usr/bin/env sage

import hashlib
import random
import time
from itertools import permutations
from sage.all import GF, PolynomialRing
import ecdsa
import datetime


class TerminalColors:
    """ANSI color codes for terminal output styling."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class ECDSANonceRecurrenceAttack:
    """
    Implementation of an attack against ECDSA signatures when nonces follow
    a predictable polynomial recurrence relation.
    
    This attack works WITHOUT knowing the coefficients of the recurrence relation.
    It only requires that the nonces follow some polynomial recurrence relation
    of a known degree, and then uses mathematical properties to recover the private key.
    """
    
    def __init__(self, curve=ecdsa.curves.SECP256k1, signatures_count=7, verbose=True):
        """
        Initialize the ECDSA attack with specified parameters.
        
        Args:
            curve: The elliptic curve to use (default: SECP256k1)
            signatures_count: Number of signatures to use (N >= 4)
            verbose: Whether to print detailed information
        """
        self.curve = curve
        self.N = signatures_count
        self.verbose = verbose
        self.colors = TerminalColors()
        
        # Validate parameters
        if self.N < 4:
            raise ValueError("Number of signatures must be at least 4")
            
        # Initialize field and polynomial ring for later use
        self.Z = GF(self.curve.order)
        self.R = PolynomialRing(self.Z, names=('dd',))
        (self.dd,) = self.R._first_ngens(1)
        
        if self.verbose:
            self._print_attack_info()
    
    def _print_attack_info(self):
        """Print information about the attack configuration."""
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self._print_header("ECDSA NONCE RECURRENCE ATTACK", centered=True)
        self._print_info(f"Start time: {current_time}")
        self._print_info(f"Selected curve: {self.colors.BOLD}{self.curve.name}{self.colors.END}")
        self._print_info(f"Number of signatures (N): {self.colors.BOLD}{self.N}{self.colors.END}")
        self._print_info(f"Recurrence relation degree: {self.colors.BOLD}{self.N - 3}{self.colors.END}")
        self._print_info(f"Final polynomial degree: {self.colors.BOLD}{self._calculate_final_polynomial_degree()}{self.colors.END}")
        
        # Add information about how the attack works without knowing coefficients
        self._print_info(f"{self.colors.BOLD}Attack properties:{self.colors.END}")
        self._print_info(f"  - Works without knowing the coefficients of the recurrence relation")
        self._print_info(f"  - Only requires that nonces follow a polynomial recurrence relation")
        self._print_info(f"  - Uses mathematical relationships between consecutive signatures")
        self._print_separator()
    
    def _calculate_final_polynomial_degree(self):
        """Calculate the degree of the final polynomial in d."""
        return 1 + sum(range(1, self.N - 2))
    
    def _print_separator(self, char="─"):
        """Print a visual separator line."""
        width = 80
        print(f"{self.colors.BLUE}{char * width}{self.colors.END}")
    
    def _print_header(self, text, centered=False):
        """Print a formatted header."""
        width = 80
        if centered:
            padding = (width - len(text)) // 2
            text = " " * padding + text
        
        self._print_separator("═")
        print(f"{self.colors.HEADER}{self.colors.BOLD}{text}{self.colors.END}")
        self._print_separator("═")
    
    def _print_info(self, text):
        """Print formatted information text."""
        print(f"{self.colors.CYAN}[INFO]{self.colors.END} {text}")
    
    def _print_success(self, text):
        """Print formatted success message."""
        print(f"{self.colors.GREEN}[SUCCESS]{self.colors.END} {text}")
    
    def _print_warning(self, text):
        """Print formatted warning message."""
        print(f"{self.colors.YELLOW}[WARNING]{self.colors.END} {text}")
    
    def _print_error(self, text):
        """Print formatted error message."""
        print(f"{self.colors.RED}[ERROR]{self.colors.END} {text}")
    
    def _print_progress(self, current, total, prefix="Progress", length=50):
        """Print a progress bar."""
        percent = (current / total) * 100
        filled_length = int(length * current // total)
        bar = "█" * filled_length + "░" * (length - filled_length)
        
        print(f"\r{self.colors.CYAN}{prefix}:{self.colors.END} |{self.colors.BLUE}{bar}{self.colors.END}| {percent:.1f}% ({current}/{total})", end="\r")
        if current == total:
            print()
    
    def generate_test_data(self):
        """
        Generate test data including private key, nonces with recurrence relation,
        and corresponding ECDSA signatures.
        
        Returns:
            tuple: (private_key, public_key, hashes, signatures)
        """
        # Generate private key
        g = self.curve.generator
        self.d = random.randint(1, self.curve.order - 1)
        
        pubkey = ecdsa.ecdsa.Public_key(g, g * self.d)
        privkey = ecdsa.ecdsa.Private_key(pubkey, self.d)
        
        if self.verbose:
            self._print_header("TEST DATA GENERATION")
            self._print_info(f"Generated private key (hex): {self.colors.YELLOW}{hex(self.d)}{self.colors.END}")
        
        # Generate coefficients for recurrence relation
        a = [random.randint(1, self.curve.order - 1) for _ in range(self.N - 2)]
        
        # Generate nonces using the recurrence relation
        k = [random.randint(1, self.curve.order - 1)]  # First nonce is random
        
        for i in range(self.N - 1):
            new_k = 0
            for j in range(self.N - 2):
                new_k += a[j] * pow(k[i], j, self.curve.order) % self.curve.order
            k.append(new_k % self.curve.order)
        
        # Generate signatures using the nonces
        h = []
        signatures = []
        
        if self.verbose:
            self._print_info(f"Generating {self.N} signatures with polynomial recurrence relation...")
            self._print_info(f"  (Note: This is test data generation, not the attack itself)")
        
        for i in range(self.N):
            # Create a unique message for each signature
            digest_fnc = hashlib.sha256()
            digest_fnc.update(f"ECDSA recurrence attack test {i}".encode('utf-8'))
            msg_hash = digest_fnc.digest()
            
            # Adjust hash to fit curve order
            if self.curve.order.bit_length() < 256:
                hash_int = (int.from_bytes(msg_hash, "big") >> 
                           (256 - self.curve.order.bit_length())) % self.curve.order
            else:
                hash_int = int.from_bytes(msg_hash, "big") % self.curve.order
                
            h.append(hash_int)
            signatures.append(privkey.sign(hash_int, k[i]))
            
            if self.verbose:
                self._print_progress(i + 1, self.N, prefix="Signature Generation")
        
        # Extract signature components
        r = [sig.r for sig in signatures]
        s = [sig.s for sig in signatures]
        
        if self.verbose:
            self._print_info(f"[TEST DATA ONLY] Recurrence coefficients: {self.colors.YELLOW}{a}{self.colors.END}")
            self._print_info(f"{self.colors.BOLD}Note:{self.colors.END} These coefficients are {self.colors.RED}NOT{self.colors.END} used in the attack.")
            self._print_info(f"      Real attacks would have no knowledge of these values.")
            self._print_separator()
        
        return self.d, pubkey, h, signatures
    
    def k_ij_poly(self, i, j, h, r, s_inv):
        """
        Calculate the k_ij polynomial (k_i - k_j) as a function of the private key.
        
        Args:
            i, j: Signature indices
            h: Array of message hashes
            r: Array of r values from signatures
            s_inv: Array of modular inverses of s values
            
        Returns:
            A polynomial in dd representing k_i - k_j
        """
        hi = self.Z(h[i])
        hj = self.Z(h[j])
        s_invi = self.Z(s_inv[i])
        s_invj = self.Z(s_inv[j])
        ri = self.Z(r[i])
        rj = self.Z(r[j])
        
        # k_ij = (dd * (ri * s_invi - rj * s_invj) + hi * s_invi - hj * s_invj)
        return self.dd * (ri * s_invi - rj * s_invj) + hi * s_invi - hj * s_invj
    
    def dpoly(self, n, i, j, h, r, s_inv):
        """
        Recursively compute the polynomial whose roots include the private key.
        
        This is the key method of the attack that constructs a polynomial
        based only on the observed signatures - WITHOUT requiring knowledge
        of the coefficients that generated the nonces.
        
        Args:
            n: Total number of signatures minus 4
            i: Current recursion depth
            j: Starting index
            h, r, s_inv: Signature data arrays
            
        Returns:
            The polynomial whose roots contain the private key
        """
        # Base case: second-degree polynomial for 4 signatures
        if i == 0:
            k12 = self.k_ij_poly(j + 1, j + 2, h, r, s_inv)
            k23 = self.k_ij_poly(j + 2, j + 3, h, r, s_inv)
            k01 = self.k_ij_poly(j + 0, j + 1, h, r, s_inv)
            return k12 * k12 - k23 * k01
        
        # Recursive case: build higher degree polynomials
        left = self.dpoly(n, i - 1, j, h, r, s_inv)
        for m in range(1, i + 2):
            left *= self.k_ij_poly(j + m, j + i + 2, h, r, s_inv)
            
        right = self.dpoly(n, i - 1, j + 1, h, r, s_inv)
        for m in range(1, i + 2):
            right *= self.k_ij_poly(j, j + m, h, r, s_inv)
            
        return left - right
    
    def attack(self, h, signatures, max_permutations=None):
        """
        Execute the attack to recover the private key.
        
        This attack works WITHOUT knowing the coefficients of the recurrence relation.
        It only requires the signatures and message hashes, and exploits the mathematical
        relationships between signatures when nonces follow a recurrence relation.
        
        Args:
            h: Array of message hashes
            signatures: Array of ECDSA signatures
            max_permutations: Maximum number of permutations to try (None for all)
            
        Returns:
            The recovered private key or None if not found
        """
        start_time = time.time()
        
        self._print_header("EXECUTING ATTACK")
        
        # Extract signature components
        r = [sig.r for sig in signatures]
        s = [sig.s for sig in signatures]
        s_inv = [ecdsa.numbertheory.inverse_mod(sig.s, self.curve.order) for sig in signatures]
        
        # Get permutations to try
        indices = list(range(self.N))
        all_perms = list(permutations(indices))
        
        if max_permutations is not None and max_permutations < len(all_perms):
            perms_to_try = random.sample(all_perms, max_permutations)
            if self.verbose:
                self._print_info(f"Trying {self.colors.YELLOW}{max_permutations}{self.colors.END} random permutations out of {len(all_perms)} possible")
        else:
            perms_to_try = all_perms
            if self.verbose:
                self._print_info(f"Trying all {self.colors.YELLOW}{len(all_perms)}{self.colors.END} permutations")
        
        # Try permutations until we find the private key
        for perm_idx, perm in enumerate(perms_to_try):
            if self.verbose:
                self._print_progress(perm_idx + 1, len(perms_to_try), prefix="Testing Permutations")
                if perm_idx % 10 == 0 and perm_idx > 0:
                    elapsed = time.time() - start_time
                    rate = perm_idx / elapsed
                    estimated_total = len(perms_to_try) / rate if rate > 0 else 0
                    remaining = max(0, estimated_total - elapsed)
                    self._print_info(f"Permutation {perm_idx}/{len(perms_to_try)}: {self.colors.YELLOW}{perm}{self.colors.END}")
                    self._print_info(f"Time elapsed: {elapsed:.2f}s | Est. remaining: {remaining:.2f}s")
            
            h_perm = [h[i] for i in perm]
            r_perm = [r[i] for i in perm]
            s_perm = [s[i] for i in perm]
            s_inv_perm = [s_inv[i] for i in perm]
            
            # Construct the polynomial and find its roots
            try:
                poly = self.dpoly(self.N - 4, self.N - 4, 0, h_perm, r_perm, s_inv_perm)
                roots = poly.roots()
                
                # Check if any root matches the private key
                for root, _ in roots:
                    private_key = int(root)
                    if self.verify_private_key(private_key, signatures, h):
                        elapsed_time = time.time() - start_time
                        if self.verbose:
                            print()  # Clear the progress bar line
                            self._print_success(f"Private key recovered in {elapsed_time:.2f} seconds")
                            self._print_success(f"Private key (hex): {self.colors.GREEN}{hex(private_key)}{self.colors.END}")
                            self._print_separator()
                        return private_key
            except Exception as e:
                if self.verbose and perm_idx % 50 == 0:
                    self._print_warning(f"Error in permutation {perm}: {str(e)}")
                continue
        
        if self.verbose:
            self._print_error("Attack failed: No valid private key found in the tried permutations.")
        return None
    
    def verify_private_key(self, private_key, signatures, h):
        """
        Verify if a private key candidate is correct by checking signatures.
        
        Args:
            private_key: The private key candidate
            signatures: The signatures to verify
            h: The message hashes
            
        Returns:
            True if the private key is valid, False otherwise
        """
        g = self.curve.generator
        pubkey_point = private_key * g
        pubkey = ecdsa.ecdsa.Public_key(g, pubkey_point)
        
        # Check if we can verify at least one signature
        for i, sig in enumerate(signatures):
            try:
                if pubkey.verifies(h[i], sig):
                    return True
            except:
                continue
                
        return False
    
    def run_demo(self):
        """Run a full demonstration of the attack."""
        self._print_header("ECDSA NONCE RECURRENCE ATTACK DEMONSTRATION", centered=True)
        
        # Generate test data with nonces following a recurrence relation
        self._print_info(f"{self.colors.YELLOW}IMPORTANT:{self.colors.END} For demonstration purposes, we generate test data")
        self._print_info(f"  with nonces following a known recurrence relation.")
        self._print_info(f"  In a real attack scenario, we would only have the signatures.")
        self._print_info(f"  The attack itself does NOT use knowledge of the recurrence coefficients.")
        
        # Generate test data
        private_key, public_key, hashes, signatures = self.generate_test_data()
        
        # Run the attack
        self._print_info(f"Now running the attack using {self.colors.BOLD}only the signatures{self.colors.END}...")
        recovered_key = self.attack(hashes, signatures)
        
        # Verify the result
        if recovered_key is not None and recovered_key == private_key:
            self._print_header("ATTACK RESULTS", centered=True)
            self._print_success("Attack successfully recovered the private key!")
            
            # Calculate public key from recovered private key
            g = self.curve.generator
            pubkey_point = recovered_key * g
            
            self._print_info(f"Computed public key (x, y):")
            print(f"{self.colors.CYAN}x = {self.colors.YELLOW}{pubkey_point.x():x}{self.colors.END}")
            print(f"{self.colors.CYAN}y = {self.colors.YELLOW}{pubkey_point.y():x}{self.colors.END}")
            
            return recovered_key
        else:
            self._print_error("Attack failed to recover the correct private key.")
            return None


# Main execution code
if __name__ == "__main__":
    # You can customize these parameters directly in the code
    curve = ecdsa.curves.SECP256k1
    # curve = ecdsa.curves.NIST521p
    # curve = ecdsa.curves.BRAINPOOLP160r1
    
    # Number of signatures to use (minimum signature required, N >= 4)
    signatures_count = 7
    
    # Maximum permutations to try (None for all)
    max_permutations = None
    
    print("\n")  # Start with a clean line
    
    print("""
\033[1mECDSA Nonce Recurrence Attack\033[0m
-----------------------------------------------------------------------------------
This demonstrates an attack against ECDSA when the nonces follow a polynomial 
recurrence relation. The key feature of this attack is that it works WITHOUT 
knowledge of the recurrence coefficients.

While we generate test data with known coefficients for demonstration purposes,
the actual attack algorithm does NOT use this information, simulating a real-world
scenario where only the signatures would be available to an attacker.
-----------------------------------------------------------------------------------
""")
    
    try:
        # Create and run the attack
        attack = ECDSANonceRecurrenceAttack(
            curve=curve,
            signatures_count=signatures_count,
            verbose=True
        )
        
        # Run the full demonstration
        attack.run_demo()
    except KeyboardInterrupt:
        print("\n\033[91m[INTERRUPTED]\033[0m Attack was interrupted by user.")
    except Exception as e:
        print(f"\n\033[91m[ERROR]\033[0m An unexpected error occurred: {str(e)}")
    finally:
        print("\n\033[94m" + "─" * 80 + "\033[0m")
        print("\033[1mECDSA Nonce Recurrence Attack - Completed\033[0m")
        print("\033[94m" + "─" * 80 + "\033[0m")
