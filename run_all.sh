#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "========================================"
echo "  ML-DSA Project - Full Run"
echo "========================================"

# ── 1. Run example usage ──────────────────────────────────────
echo ""
echo "1. Running example usage..."
PYTHONPATH=. python3 examples/usage.py

# ── 2. Run tests ──────────────────────────────────────────────
echo ""
echo "2. Running test suite..."
PYTHONPATH=. python3 -m pytest tests/ -v

# ── 3. Run standard benchmarks (all modes) ────────────────────
echo ""
echo "3. Running standard benchmarks (all modes)..."
PYTHONPATH=. python3 benchmarks/bench.py

# ── 4. Run ML-DSA-44 benchmark with 20 repeats ───────────────
echo ""
echo "4. Running ML-DSA-44 benchmark (20 repeats)..."
PYTHONPATH=. python3 benchmarks/bench.py --mode ML-DSA-44 --repeats 20

# ── 5. Run ML-DSA-65 benchmark with hash ─────────────────────
echo ""
echo "5. Running ML-DSA-65 benchmark with HashML-DSA..."
PYTHONPATH=. python3 benchmarks/bench.py --mode ML-DSA-65 --hash

# ── 6. Run ML-DSA-87 benchmark with hash ─────────────────────
echo ""
echo "6. Running ML-DSA-87 benchmark with HashML-DSA..."
PYTHONPATH=. python3 benchmarks/bench.py --mode ML-DSA-87 --hash

echo ""
echo "========================================"
echo "  All steps completed successfully!"
echo "========================================"
