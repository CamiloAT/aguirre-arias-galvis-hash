# Block Hashing for Large Files

A custom cryptographic hash function algorithm built from scratch in Python. It is designed to process large files (>1MB) deterministically in blocks, implementing chaining mechanisms, and outputting a unique fixed-length integrity value. 

The decision for the name `aguirre_arias_galvis_hash.py` was a simple creative process of joining the first surnames of the three authors who developed the idea for the encryption process: **Diego Fernando Aguirre Tenjo**, **Camilo Andres Arias Tenjo**, and **Katlyn Jennelis Galvis Rodriguez**.

---

## 1. System Description

The `aguirre_arias_galvis_hash.py` program calculates hashes for large files efficiently by streaming chunks of data rather than loading the entire file into memory. It ensures file integrity with a custom algorithm designed to meet the following parameters:
- **Input Block Size:** 512 bits (64 bytes)
- **Hash Output:** 256 bits (32 bytes) fixed length
- **Chaining System:** Each block incorporates the result of the previous block to ensure sequential integrity.

---

## 2. Algorithm Architecture

```text
+-------------------------------------------------------------+
|                         Input File                          |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|             [Read in 512-bit (64-byte) blocks]              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|    [Block 1]  -->  Compression Function  <-- IV (256 bits)  |
+-------------------------------------------------------------+
                              |
                              v
                    +--------------------+
                    |  Chaining Value 1  |
                    +--------------------+
                              |
                              v
+-------------------------------------------------------------+
| [Block 2] -->  Compression Function <-- Chaining Value 1    |
+-------------------------------------------------------------+
                              |
                              v
                    +--------------------+
                    |  Chaining Value 2  |
                    +--------------------+
                              |
                              v
                    +--------------------+
                    | ... (N blocks) ... |
                    +--------------------+
                              |
                              v
+-------------------------------------------------------------+
|    [Last Block + Padding]  -->  Compression Function        |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|               Final Hash (256 bits = 64 hex)                |
+-------------------------------------------------------------+
```

### 2.1 Initialization and Chaining Value (IV)
- Initializes an 8-word (256-bit) Chaining Value based on custom fractional roots of primes.

### 2.2 Piece-wise Block Processing (512-bit Blocks)
- The file is read iteratively in precise 512-bit (64-byte) blocks avoiding memory overflow on massive files.

### 2.3 Custom Compression Function
- **Message Expansion:** Expands 16 32-bit words into 32 words using bitwise rotations.
- **32-Round Mixing:** Applies mathematical diffusion mixing XOR operations, bitwise rotations (left and right), and modular 32-bit additions. It includes custom majority and conditional logic functions inspired by industry-standard crypto architectures.
- **Davies-Meyer Construction:** Combines the post-processed state with the original chaining value, ensuring a secure, non-reversible one-way compression function.

### 2.4 Padding Scheme (Merkle-Damgård Compatibility)
- Fills the final block if it doesn't align to exactly 512 bits.
- Starts padding with a `0x80` byte, fills with `0x00`, and mathematically appends the absolute original file size (in bits) at the tail to prevent length-extension attacks.

---

## 3. Cryptographic Analysis and Mathematical Foundation

### 3.1 Avalanche Effect
A modification of just 1 bit in the input reliably flips approximately 50% of the bits in the output hash. This measures structural chaos and prevents similarity tracking between a file and its slightly modified replica.

### 3.2 Performance vs. SHA-256
The implementation processes 1MB, 5MB, and 10MB test artifacts, then benchmarks its completion times against Python's native `hashlib.sha256()`. 

### 3.3 Security Overview
- **Vulnerabilities:** Susceptible to length-extension attacks without HMAC and contains fewer mixing rounds (32 versus SHA-256's 64). Python's native execution without constant-time guarantees makes it susceptible to side-channel timing attacks.
- **Usage Recommendations:** Appropriate for educational prototyping or internal non-cryptographic checksum verification, but dangerous for real-world production compared to NIST-audited implementations due to the lack of formal cryptographic peer-review.

---

## 4. Requirements

- Python **3.6 or higher**
- Standard built-in Python libraries (`os`, `time`, `hashlib`, `struct`, `json`, `random`)
- **No external dependencies** or `pip` installs required
- Multi-platform (Windows, macOS, Linux)

---

## 5. Execution Instructions

To run the custom hashing software and generate the automated evaluation reports, open a terminal (PowerShell, CMD, or Bash) in the project directory and run:

```bash
python aguirre_arias_galvis_hash.py
```

### 5.1 Automated Testing and Operations
When executed, the program will automatically perform the following workflow outputting to the console screen:
1. **Generate Test Files:** Creates a 1MB repetitive text file, a 5MB random binary file, a 10MB structured JSON file, and a modified copy of the 1MB file with precisely **1 bit flipped**.
2. **Execute Hashing:** Calculates the 64-character (256-bit) custom hexadecimal hash for each generated file.
3. **Validate Avalanche Effect:** Compares the base 1MB file against the modified replica, calculating exactly how many bits changed and generating a percentage.
4. **Benchmark Verification:** Runs SHA-256 against the same files and visually compares execution times.
5. **Print Technical Summaries:** Outputs all the evaluated data into tabulated formats onto the console along with a comprehensive critical analysis report versus the SHA-256 metric.
