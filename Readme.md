
# AES Encryption Implementation in C

![C](https://img.shields.io/badge/Language-C-blue)
## Table of Contents
- [Overview](#overview)
- [Project Structure](#project-structure)
- [Compilation](#compilation)
- [Running the Program](#running-the-program)
- [How the Algorithm Works](#how-the-algorithm-works)
- [Performance Notes](#performance-notes)
- [Potential Improvements](#potential-improvements)
- [References](#references)

---

## Overview

This project implements a **simplified AES encryption algorithm** in C. It demonstrates:

- Conversion of plaintext and keys to **hexadecimal**.
- **AES key schedule generation**.
- AES transformations including:
  - `SubBytes`
  - `ShiftRows`
  - `MixColumns`
  - `AddRoundKey`
- Encryption of **16-byte blocks** of plaintext.
- Measurement of **encryption execution time**.

⚠ **Note:** This implementation is educational and **not suitable for production-level encryption**.

---

## Project Structure

```
AES-C/
│
├── encryption.c      # Main encryption logic
├── scheduling.c      # Key schedule and helper functions
├── scheduling.h      # Header file with shared function declarations
├── README.md         # Project documentation
```

---

## Compilation

Open a terminal in the `AES-C` directory and run:

```bash
gcc -std=c11 -O2 encryption.c scheduling.c -o encrypt
```

**Explanation:**

- `gcc` – GNU C Compiler  
- `-std=c11` – Use **C11 standard**  
- `-O2` – Optimize the code for faster execution  
- `-o encrypt` – Output executable file named `encrypt`  

---

## Running the Program

```bash
./encrypt
```

**Sample Output:**

```
text is: One Two Nine One
34 A0 D0 46
3B 8D C2 BE
60 E5 A8 67
10 6B 03 DE

Execution time: 4000 microseconds
Execution time: 4 milliseconds
```

---

## How the Algorithm Works

### 1. Convert String to Hex
Each character of the plaintext and key is converted into a **4x4 hexadecimal matrix**.

### 2. Key Schedule
Generates **11 round keys** from the initial key using:

- `rotWord` – rotates a 4-byte word
- `subWord` – substitutes bytes using S-box
- `xorWords` – XOR operation between words
- `rCon` – round constant

### 3. Encryption Process
Applies **10 AES rounds**:

1. **AddRoundKey** – XOR with round key  
2. **SubBytes** – Substitute bytes using **S-box**  
3. **ShiftRows** – Rotate rows cyclically  
4. **MixColumns** – Column-wise matrix multiplication  

*Final round excludes `MixColumns`.*

### 4. Output
Prints **encrypted 4x4 matrix** for each 16-byte block.

---

## Performance Notes

- Current execution time: ~4 ms for a single block of 16 bytes.  
- Console output can add overhead; actual encryption is faster.  
- For better timing:
  - Compile with `-O3` for maximum optimization.  

---

## Potential Improvements

- Implement **AES decryption**  
- Support **larger plaintext files**  
- Precompute **round keys** for multiple blocks  
- Optimize using **hardware AES instructions**  

---

## References
- AES Key Expansion  
