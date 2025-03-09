# ECDSA Nonce Recurrence Attack:

This code implements a sophisticated attack against ECDSA signatures when the nonces (k values) follow a predictable recurrence relation.

## Concept Overview

The security of ECDSA relies heavily on the randomness of the nonce (k) used in each signature. If these nonces follow any pattern or relation, it can lead to private key recovery. This implementation demonstrates how to exploit nonces that follow polynomial recurrence relations of various degrees (linear, quadratic, cubic, or higher).

## The Attack Explained

### Mathematical Background

The attack exploits the relationship:

- For a signature, we have: `s = k^(-1) * (h + r * d) mod n`
- If we know k, we can solve for d: `d = (s * k - h) * r^(-1) mod n`

When nonces follow a recurrence relation like:

`k_i+1 = a_0 + a_1*k_i + a_2*k_i^2 + ... + a_(N-3)*k_i^(N-3) mod n`

The code builds a polynomial in d whose roots include the target private key.

### Attack Complexity

The polynomial degree increases with the complexity of the recurrence relation:

- Linear (N=4): 2nd degree polynomial
- Quadratic (N=5): 4th degree polynomial
- Cubic (N=6): 7th degree polynomial
- And so on according to the formula: `1 + Σ(i=1 to N-3) i`

## Code Breakdown

### Parameter Setup:
- Choose an elliptic curve (default is SECP256k1)
- Generate a random private key d for testing
- minimum number of signatures required, N ≥ 4 (number of signatures, determines recurrence complexity)

### Nonce Generation:
- Generate random coefficients for the recurrence relation
- Create N nonces following this relation
- Generate ECDSA signatures using these nonces

### Polynomial Construction:
- Builds a polynomial in the private key variable dd
- Implements the recursive algorithm to construct a polynomial whose roots include the private key
- Tries all permutations of signatures to find a valid solution

### Key Recovery:
- Solves the polynomial to find the private key
- Verifies the result matches the original key

## Setting Up and Running the Attack

### Prerequisites
- SageMath (mathematical software)
- Python libraries: hashlib, ecdsa, random, itertools (included with SageMath)

### Setup Instructions

#### Windows
1. Install SageMath:
   - Download the Windows installer from SageMath's website
   - Complete the installation process
   - Add SageMath to your PATH environment variable

2. Install ECDSA library:
   ```
   sage -pip install ecdsa
   ```

3. Run the script:
   - Save the code to a file (e.g., `nonce_attack.sage`)
   - Open a command prompt and navigate to the directory
   - Run: `sage nonce_attack.sage`

#### macOS
1. Install SageMath:
   ```
   brew install --cask sage
   ```
   Or download from SageMath's website

2. Install ECDSA library:
   ```
   sage -pip install ecdsa
   ```

3. Run the script:
   ```
   sage nonce_attack.sage
   ```

#### Linux
1. Install SageMath:
   ```
   sudo apt-get install sagemath   # Debian/Ubuntu
   sudo dnf install sagemath       # Fedora
   ```
   Or follow distro-specific instructions from SageMath's website

2. Install ECDSA library:
   ```
   sage -pip install ecdsa
   ```

3. Run the script:
   ```
   sage nonce_attack.sage
   ```

## Customizing the Attack

### Changing Parameters
- **Curve Selection**: Uncomment different curves to test against various elliptic curves
- **Signature Count**: Modify N to test different recurrence relation degrees:
  - N=4: Linear relation
  - N=5: Quadratic relation
  - N=6: Cubic relation
  - N=7: 4th-degree relation (default)

## Real-World Applications

This attack can be applied to any ECDSA implementation where:
- Multiple signatures are available
- The nonces follow a predictable pattern
- The recurrence relation coefficients can be identified

Examples include:
- **Algorithmic RNG**: A system uses a polynomial congruential generator for nonce generation
  - Such generators follow exactly the kind of recurrence relation exploited here
- **State Reuse**: A system that updates internal state polynomially between signature operations
  - Each signature's nonce is derived from this evolving state
- **Custom ECDSA Implementations**: Non-standard implementations that attempt to create their own nonce generation
  - Especially vulnerable if they use mathematical formulas to update nonce state

This attack demonstrates the importance of proper nonce generation in ECDSA systems and the dangers of any mathematical relationship between successive signature nonces.

## Security Implications

- Linear
![Screenshot 2025-03-09 204922](https://github.com/user-attachments/assets/d1275ece-a3cf-4892-8137-c87215a53131)

- Quadratic
![Screenshot 2025-03-09 205239](https://github.com/user-attachments/assets/4a87210e-e271-4acf-8755-b27e21144789)

- Cubic
![Screenshot 2025-03-09 205431](https://github.com/user-attachments/assets/840c9855-b281-4231-85c8-00e449a0c87f)
 
- Higher Degree
![Screenshot 2025-03-09 205703](https://github.com/user-attachments/assets/a1a9bc02-cf68-427b-83ac-2fd2f390d8f5)



### Polynomial Recurrence Vulnerabilities

**Linear Recurrence (N=4)**:
- If nonces follow a pattern: `k_i+1 = a_0 + a_1*k_i`
- Only 4 signatures needed to recover the private key
- Produces a quadratic equation easily solvable for the private key

**Quadratic Recurrence (N=5)**:
- If nonces follow a pattern: `k_i+1 = a_0 + a_1k_i + a_2k_i²`
- Requires 5 signatures
- Results in a 4th-degree polynomial with the private key as a root

**Higher Degree Recurrences**:
- The attack scales to any polynomial recurrence relation
- Each additional degree requires one more signature
- Computational complexity increases with degree, but remains feasible

**Unknown Coefficients**:
- The attack doesn't require knowing the coefficients of the recurrence relation
- It only requires that such a relation exists
- This makes the attack particularly powerful against systematic nonce generation

This attack demonstrates why proper nonce generation is critical for ECDSA security:
- Nonces must be truly random
- Deterministic nonce generation (RFC 6979) should be used when true randomness is unreliable
- Any pattern in nonce generation can lead to private key compromise

Code written after reading the theory of:
-  https://eprint.iacr.org/2023/305.pdf
-  Marco Macchetti , Kudelski Security. 
