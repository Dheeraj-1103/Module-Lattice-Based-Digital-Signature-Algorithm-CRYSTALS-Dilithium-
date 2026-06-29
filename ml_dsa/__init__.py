"""
ML-DSA: Module-Lattice-Based Digital Signature Algorithm
=========================================================

FIPS 204 compliant implementation of ML-DSA (derived from CRYSTALS-Dilithium).

Provides three security levels:
    - ML-DSA-44  (NIST Category 2, ~128-bit post-quantum security)
    - ML-DSA-65  (NIST Category 3, ~192-bit post-quantum security)
    - ML-DSA-87  (NIST Category 5, ~256-bit post-quantum security)

Example
-------
>>> from ml_dsa import ML_DSA
>>> dsa = ML_DSA("ML-DSA-44")
>>> pk, sk = dsa.KeyGen()
>>> sig = dsa.Sign(sk, b"Hello, post-quantum world!")
>>> assert dsa.Verify(pk, b"Hello, post-quantum world!", sig)

References
----------
FIPS 204 – Module-Lattice-Based Digital Signature Standard (August 2024)
https://doi.org/10.6028/NIST.FIPS.204
"""

from ml_dsa.ml_dsa import ML_DSA, HashML_DSA
from ml_dsa.params import PARAMETER_SETS, Q
from ml_dsa.polynomial import Polynomial, PolynomialVector, PolynomialMatrix

__version__ = "1.0.0"
__author__  = "ML-DSA Python Implementation"
__license__ = "MIT"

__all__ = [
    "ML_DSA",
    "HashML_DSA",
    "Polynomial",
    "PolynomialVector",
    "PolynomialMatrix",
    "PARAMETER_SETS",
    "Q",
]
