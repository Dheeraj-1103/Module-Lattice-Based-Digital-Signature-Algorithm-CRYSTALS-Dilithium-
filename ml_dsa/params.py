"""
ML-DSA Parameter Sets (FIPS 204, Section 4, Table 1).

All parameter sets share:
    q  = 8380417  (prime modulus, 2^23 - 2^13 + 1)
    ζ  = 1753     (512th root of unity in Z_q)
    d  = 13       (dropped bits from t)
"""

# ---------------------------------------------------------------------------
# Global modulus
# ---------------------------------------------------------------------------
Q: int = 8_380_417          # 2^23 − 2^13 + 1
ZETA: int = 1_753           # 512th root of unity mod Q
D: int = 13                  # Low-order bits dropped from public key

# ---------------------------------------------------------------------------
# Parameter sets
# ---------------------------------------------------------------------------
PARAMETER_SETS: dict = {
    "ML-DSA-44": {
        "k":       4,
        "l":       4,
        "eta":     2,
        "tau":     39,
        "gamma_1": 1 << 17,          # 2^17
        "gamma_2": (Q - 1) // 88,    # 95 232
        "omega":   80,
        "lambda":  128,              # collision-strength bits (λ)
        "d":       D,
        # Derived
        "beta":    39 * 2,           # τ · η = 78
    },
    "ML-DSA-65": {
        "k":       6,
        "l":       5,
        "eta":     4,
        "tau":     49,
        "gamma_1": 1 << 19,          # 2^19
        "gamma_2": (Q - 1) // 32,   # 261 888
        "omega":   55,
        "lambda":  192,
        "d":       D,
        "beta":    49 * 4,           # 196
    },
    "ML-DSA-87": {
        "k":       8,
        "l":       7,
        "eta":     2,
        "tau":     60,
        "gamma_1": 1 << 19,          # 2^19
        "gamma_2": (Q - 1) // 32,   # 261 888
        "omega":   75,
        "lambda":  256,
        "d":       D,
        "beta":    60 * 2,           # 120
    },
}

# ---------------------------------------------------------------------------
# Expected key / signature sizes in bytes (FIPS 204, Table 2)
# ---------------------------------------------------------------------------
SIZES: dict = {
    "ML-DSA-44": {"pk": 1312,  "sk": 2560,  "sig": 2420},
    "ML-DSA-65": {"pk": 1952,  "sk": 4032,  "sig": 3309},
    "ML-DSA-87": {"pk": 2592,  "sk": 4896,  "sig": 4627},
}
