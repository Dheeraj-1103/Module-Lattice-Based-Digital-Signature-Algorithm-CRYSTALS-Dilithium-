"""
Performance benchmarks for ML-DSA.

Run with:
    python benchmarks/bench.py

Or individual sections:
    python benchmarks/bench.py --mode ML-DSA-44
    python benchmarks/bench.py --all
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Dict, List

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_dsa import ML_DSA, HashML_DSA

MODES = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

# ── Timing helper ──────────────────────────────────────────────────────────────

def _time_fn(fn, warmup: int = 1, repeats: int = 10) -> float:
    """Return median wall-clock time (seconds) of *fn()* over *repeats* runs."""
    times: List[float] = []
    for i in range(warmup + repeats):
        t0 = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - t0
        if i >= warmup:
            times.append(elapsed)
    times.sort()
    return times[len(times) // 2]          # median


# ── Per-mode benchmark ─────────────────────────────────────────────────────────

def bench_mode(mode: str, repeats: int = 10) -> Dict[str, float]:
    """Benchmark KeyGen / Sign / Verify for *mode*.

    Returns a dict of ``{operation: seconds_median}``.
    """
    dsa = ML_DSA(mode)
    msg = b"benchmark message " * 10       # 180 bytes

    # Key generation
    keygen_time = _time_fn(dsa.KeyGen, repeats=repeats)
    pk, sk = dsa.KeyGen()

    # Signing
    sign_time = _time_fn(lambda: dsa.Sign(sk, msg), repeats=repeats)
    sig = dsa.Sign(sk, msg)

    # Verification
    verify_time = _time_fn(lambda: dsa.Verify(pk, msg, sig), repeats=repeats)

    return {
        "keygen":  keygen_time,
        "sign":    sign_time,
        "verify":  verify_time,
    }


def bench_hash_mode(mode: str, repeats: int = 10) -> Dict[str, float]:
    """Benchmark HashML-DSA with SHA-512."""
    dsa  = HashML_DSA(mode)
    msg  = os.urandom(4096)              # 4 KB message
    pk, sk = dsa.KeyGen()
    sig    = dsa.Sign(sk, msg, hash_name="SHA512")

    sign_time   = _time_fn(lambda: dsa.Sign(sk, msg, hash_name="SHA512"),   repeats=repeats)
    verify_time = _time_fn(lambda: dsa.Verify(pk, msg, sig, hash_name="SHA512"), repeats=repeats)

    return {"sign": sign_time, "verify": verify_time}


# ── Formatting ─────────────────────────────────────────────────────────────────

def _ms(t: float) -> str:
    return f"{t * 1000:.2f} ms"


def _ops(t: float) -> str:
    return f"{1.0 / t:.1f} ops/s" if t > 0 else "N/A"


def print_table(results: Dict[str, Dict[str, float]]) -> None:
    """Pretty-print benchmark results."""
    print()
    header = f"{'Mode':<14}  {'KeyGen':>12}  {'Sign':>12}  {'Verify':>12}"
    print(header)
    print("-" * len(header))
    for mode, r in results.items():
        row = (
            f"{mode:<14}  "
            f"{_ms(r['keygen']):>12}  "
            f"{_ms(r['sign']):>12}  "
            f"{_ms(r['verify']):>12}"
        )
        print(row)
    print()


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ML-DSA benchmark")
    parser.add_argument("--mode",    choices=MODES, default=None,
                        help="Benchmark a specific parameter set only.")
    parser.add_argument("--repeats", type=int, default=10,
                        help="Number of timed repetitions (default: 10).")
    parser.add_argument("--hash",    action="store_true",
                        help="Also benchmark HashML-DSA.")
    args = parser.parse_args()

    modes = [args.mode] if args.mode else MODES

    print(f"\n{'='*60}")
    print("  ML-DSA Benchmark  (pure Python, FIPS 204)")
    print(f"{'='*60}")
    print(f"  Repeats per operation: {args.repeats}")
    print(f"  Python median wall-clock time")

    results: Dict[str, Dict[str, float]] = {}
    for mode in modes:
        print(f"\n  Benchmarking {mode} …", end="", flush=True)
        results[mode] = bench_mode(mode, repeats=args.repeats)
        print("  done")

    print_table(results)

    if args.hash:
        print("HashML-DSA (SHA-512, 4 KB message)")
        print("-" * 50)
        for mode in modes:
            r = bench_hash_mode(mode, repeats=args.repeats)
            print(f"  {mode:<14}  sign {_ms(r['sign'])}  verify {_ms(r['verify'])}")
        print()


if __name__ == "__main__":
    main()
