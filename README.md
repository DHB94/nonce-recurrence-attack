# ECDSA Nonce Recurrence Attack: In-Depth Explanation

This code implements a sophisticated attack against ECDSA signatures when the nonces (`k` values) follow a predictable recurrence relation. I'll explain how it works, the mathematical principles behind it, and provide detailed setup instructions.

## Concept Overview

The security of ECDSA relies heavily on the randomness of the nonce (`k`) used in each signature. If these nonces follow any pattern or relation, it can lead to private key recovery. This implementation demonstrates how to exploit nonces that follow polynomial recurrence relations of various degrees (linear, quadratic, cubic, or higher).

## The Attack Explained

### Mathematical Background

The attack exploits the relationship:
- For a signature, we have: `s = k^(-1) * (h + r * d) mod n`
- If we know `k`, we can solve for `d`: `d = (s * k - h) * r^(-1) mod n`

When nonces follow a recurrence relation like:
```
k_i+1 = a_0 + a_1*k_i + a_2*k_i^2 + ... + a_(N-3)*k_i^(N-3) mod n
```

The code builds a polynomial in `d` whose roots include the target private key.

### Attack Complexity

The polynomial degree increases with the complexity of the recurrence relation:
- Linear (N=4): 2nd degree polynomial
- Quadratic (N=5): 4th degree polynomial 
- Cubic (N=6): 7th degree polynomial
- And so on according to the formula: 1 + Σ(i=1 to N-3) i

### Code Breakdown

1. **Parameter Setup**:
   - Choose an elliptic curve (default is SECP256k1)
   - Generate a random private key `d` for testing
   - Set N ≥ 4 (number of signatures, determines recurrence complexity)

2. **Nonce Generation**:
   - Generate random coefficients for the recurrence relation
   - Create N nonces following this relation
   - Generate ECDSA signatures using these nonces

3. **Polynomial Construction**:
   - Builds a polynomial in the private key variable `dd`
   - Implements the recursive algorithm to construct a polynomial whose roots include the private key
   - Tries all permutations of signatures to find a valid solution

4. **Key Recovery**:
   - Solves the polynomial to find the private key
   - Verifies the result matches the original key

## Setting Up and Running the Attack

### Prerequisites

- [SageMath](https://www.sagemath.org/) (mathematical software)
- Python libraries: `hashlib`, `ecdsa`, `random`, `itertools` (included with SageMath)

### Setup Instructions

#### Windows

1. **Install SageMath**:
   - Download the Windows installer from [SageMath's website](https://www.sagemath.org/download-windows.html)
   - Complete the installation process
   - Add SageMath to your PATH environment variable

2. **Install ECDSA library**:
   ```
   sage -pip install ecdsa
   ```

3. **Run the script**:
   - Save the code to a file (e.g., `nonce_attack.sage`)
   - Open a command prompt and navigate to the directory
   - Run: `sage nonce_attack.sage`

#### macOS

1. **Install SageMath**:
   ```
   brew install --cask sage
   ```
   Or download from [SageMath's website](https://www.sagemath.org/download-mac.html)

2. **Install ECDSA library**:
   ```
   sage -pip install ecdsa
   ```

3. **Run the script**:
   ```
   sage nonce_attack.sage
   ```

#### Linux

1. **Install SageMath**:
   ```
   sudo apt-get install sagemath   # Debian/Ubuntu
   sudo dnf install sagemath       # Fedora
   ```
   Or follow distro-specific instructions from [SageMath's website](https://www.sagemath.org/download-linux.html)

2. **Install ECDSA library**:
   ```
   sage -pip install ecdsa
   ```

3. **Run the script**:
   ```
   sage nonce_attack.sage
   ```

## Customizing the Attack

### Changing Parameters

- **Curve Selection**: Uncomment different curves to test against various elliptic curves
- **Signature Count**: Modify `N` to test different recurrence relation degrees:
  - N=4: Linear relation
  - N=5: Quadratic relation
  - N=6: Cubic relation
  - N=7: 4th-degree relation (default)

### Real-World Applications

This attack can be applied to any ECDSA implementation where:
1. Multiple signatures are available
2. The nonces follow a predictable pattern
3. The recurrence relation coefficients can be identified

## Security Implications

This attack demonstrates why proper nonce generation is critical for ECDSA security:
- Nonces must be truly random
- Deterministic nonce generation (RFC 6979) should be used when true randomness is unreliable
- Any pattern in nonce generation can lead to private key compromise
