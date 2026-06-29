"""
ML-DSA usage examples.

Demonstrates:
    1. Basic sign / verify
    2. Using context strings
    3. All three security levels
    4. HashML-DSA (pre-hash variant)
    5. Serialising and reloading keys
    6. Error handling
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_dsa import ML_DSA, HashML_DSA


# ── 1. Basic Sign / Verify ─────────────────────────────────────────────────────

def example_basic() -> None:
    print("\n=== Example 1: Basic Sign / Verify ===")

    dsa = ML_DSA("ML-DSA-44")   # 128-bit post-quantum security

    pk, sk = dsa.KeyGen()
    print(f"Public key  : {len(pk)} bytes")
    print(f"Private key : {len(sk)} bytes")

    message = b"Hello, post-quantum world!"
    sig = dsa.Sign(sk, message)
    print(f"Signature   : {len(sig)} bytes")

    valid = dsa.Verify(pk, message, sig)
    print(f"Valid?      : {valid}")          # True

    # Tampered message
    invalid = dsa.Verify(pk, b"tampered!", sig)
    print(f"Tampered?   : {invalid}")        # False


# ── 2. Context Strings ─────────────────────────────────────────────────────────

def example_context() -> None:
    print("\n=== Example 2: Context Strings ===")

    dsa = ML_DSA("ML-DSA-65")

    pk, sk = dsa.KeyGen()
    message = b"Transaction: send 100 USD to Alice"
    ctx     = b"bank.example.com/v1/transfers"

    sig = dsa.Sign(sk, message, ctx=ctx)
    print(f"Signed with ctx ({len(ctx)} bytes)")

    # Correct ctx → valid
    ok = dsa.Verify(pk, message, sig, ctx=ctx)
    print(f"Correct ctx : {ok}")             # True

    # Wrong ctx → invalid
    bad = dsa.Verify(pk, message, sig, ctx=b"attacker.example.com")
    print(f"Wrong ctx   : {bad}")            # False


# ── 3. All Security Levels ─────────────────────────────────────────────────────

def example_all_modes() -> None:
    print("\n=== Example 3: All Security Levels ===")

    message = b"Testing all ML-DSA parameter sets"

    for mode in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        dsa = ML_DSA(mode)
        pk, sk = dsa.KeyGen()
        sig = dsa.Sign(sk, message)
        ok  = dsa.Verify(pk, message, sig)
        print(f"  {mode:<12}  pk={len(pk)}B  sk={len(sk)}B  sig={len(sig)}B  valid={ok}")


# ── 4. HashML-DSA ─────────────────────────────────────────────────────────────

def example_hash_ml_dsa() -> None:
    print("\n=== Example 4: HashML-DSA (pre-hash variant) ===")

    dsa = HashML_DSA("ML-DSA-87")
    pk, sk = dsa.KeyGen()

    # Simulate signing a large file
    large_file = os.urandom(1_000_000)   # 1 MB

    for hash_fn in ["SHA256", "SHA512", "SHAKE128"]:
        sig = dsa.Sign(sk, large_file, hash_name=hash_fn)
        ok  = dsa.Verify(pk, large_file, sig, hash_name=hash_fn)
        print(f"  {hash_fn:<10}  sig={len(sig)}B  valid={ok}")


# ── 5. Key Serialisation ───────────────────────────────────────────────────────

def example_serialisation() -> None:
    print("\n=== Example 5: Key Serialisation ===")

    dsa = ML_DSA("ML-DSA-44")
    pk, sk = dsa.KeyGen()

    # Keys are already raw bytes – write them to files / databases directly.
    pk_hex = pk.hex()
    sk_hex = sk.hex()

    # Reload from hex
    pk2 = bytes.fromhex(pk_hex)
    sk2 = bytes.fromhex(sk_hex)

    message = b"Key round-trip test"
    sig = dsa.Sign(sk2, message)
    ok  = dsa.Verify(pk2, message, sig)
    print(f"  Round-trip valid: {ok}")       # True


# ── 6. Error Handling ──────────────────────────────────────────────────────────

def example_error_handling() -> None:
    print("\n=== Example 6: Error Handling ===")

    dsa = ML_DSA("ML-DSA-44")

    # Context too long
    try:
        pk, sk = dsa.KeyGen()
        dsa.Sign(sk, b"msg", ctx=b"x" * 256)
    except ValueError as e:
        print(f"  Context too long: {e}")

    # Invalid mode
    try:
        ML_DSA("ML-DSA-999")
    except ValueError as e:
        print(f"  Invalid mode: {e}")

    # Verify returns False (never raises) on bad inputs
    pk, sk = dsa.KeyGen()
    result = dsa.Verify(b"\x00" * 10, b"msg", b"\x00" * 100)
    print(f"  Bad pk/sig returns False: {result}")    # False


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    example_basic()
    example_context()
    example_all_modes()
    example_hash_ml_dsa()
    example_serialisation()
    example_error_handling()
    print("\nAll examples complete.\n")
