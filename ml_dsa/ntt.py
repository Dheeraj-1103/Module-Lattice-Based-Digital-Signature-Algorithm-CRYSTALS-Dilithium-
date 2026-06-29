"""
Pre-computed NTT constants for ML-DSA.

FIPS 204 Appendix B specifies the full zetas table used by NTT (Algorithm 41)
and NTT⁻¹ (Algorithm 42).
"""

from ml_dsa.params import Q, ZETA


def _compute_zetas() -> list:
    """Generate the 256-element zetas array (bit-reversed powers of ζ).

    Each entry ``zetas[k]`` equals ``ζ^(BitRev8(k)) mod q`` for k=0..255.
    """
    result = [0] * 256
    for k in range(256):
        # Bit-reverse the 8-bit representation of k
        brev = int(f"{k:08b}"[::-1], 2)
        result[k] = pow(ZETA, brev, Q)
    return result


# Precomputed at import time – matches Appendix B of FIPS 204.
ZETAS: list = _compute_zetas()
