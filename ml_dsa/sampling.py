"""
Pseudorandom sampling functions for ML-DSA.

Implements FIPS 204 §7.3, Algorithms 29–34:
    SampleInBall   – challenge polynomial
    RejNTTPoly     – uniform NTT polynomial (used in ExpandA)
    RejBoundedPoly – bounded polynomial (used in ExpandS)
    ExpandA        – matrix generation
    ExpandS        – secret-vector generation
    ExpandMask     – mask-vector generation
"""

from __future__ import annotations

from hashlib import shake_128, shake_256
from typing import List, Tuple

from ml_dsa.params import Q
from ml_dsa.polynomial import Polynomial, PolynomialVector, PolynomialMatrix
from ml_dsa.utils import ShakeXOF, IntegerToBytes


# ---------------------------------------------------------------------------
# Coefficient helpers
# ---------------------------------------------------------------------------

def _coeff_from_three_bytes(b0: int, b1: int, b2: int):
    """FIPS 204 Algorithm 14 – CoeffFromThreeBytes.

    Returns an element of {0, …, q−1} or *None* if rejected.
    """
    b2p = b2 & 0x7F                       # clear top bit
    z = (b2p << 16) | (b1 << 8) | b0
    return z if z < Q else None


def _coeff_from_half_byte(b: int, eta: int):
    """FIPS 204 Algorithm 15 – CoeffFromHalfByte.

    Returns an element of {−η, …, η} or *None* if rejected.
    """
    if eta == 2 and b < 15:
        return 2 - (b % 5)
    if eta == 4 and b < 9:
        return 4 - b
    return None


# ---------------------------------------------------------------------------
# SampleInBall (Algorithm 29)
# ---------------------------------------------------------------------------

def SampleInBall(seed: bytes, tau: int) -> Polynomial:
    """FIPS 204 Algorithm 29 – SampleInBall.

    Samples a polynomial *c* ∈ R with exactly *tau* coefficients in
    {−1, +1} and the rest zero.

    Parameters
    ----------
    seed:
        λ/4-byte seed (commitment hash c̃).
    tau:
        Number of non-zero coefficients.

    Returns
    -------
    Polynomial
        Challenge polynomial.
    """
    xof = ShakeXOF(shake_256)
    xof.absorb(seed)

    sign_bytes = xof.read(8)
    sign_int = int.from_bytes(sign_bytes, "little")

    coeffs = [0] * 256
    for i in range(256 - tau, 256):
        # Rejection sample j ∈ {0, …, i}
        while True:
            j = xof.read(1)[0]
            if j <= i:
                break
        coeffs[i] = coeffs[j]
        coeffs[j] = 1 - 2 * (sign_int & 1)
        sign_int >>= 1

    return Polynomial(coeffs)


# ---------------------------------------------------------------------------
# RejNTTPoly (Algorithm 30)
# ---------------------------------------------------------------------------

def _rej_ntt_poly(seed: bytes) -> Polynomial:
    """FIPS 204 Algorithm 30 – RejNTTPoly.

    Parameters
    ----------
    seed:
        34-byte seed (rho ‖ s ‖ r indices).

    Returns
    -------
    Polynomial
        Uniform polynomial in T_q (NTT domain).
    """
    xof = ShakeXOF(shake_128)
    xof.absorb(seed)

    coeffs: List[int] = []
    while len(coeffs) < 256:
        buf = xof.read(3)
        c = _coeff_from_three_bytes(buf[0], buf[1], buf[2])
        if c is not None:
            coeffs.append(c)

    return Polynomial(coeffs[:256], is_ntt=True)


# ---------------------------------------------------------------------------
# RejBoundedPoly (Algorithm 31)
# ---------------------------------------------------------------------------

def _rej_bounded_poly(seed: bytes, eta: int) -> Polynomial:
    """FIPS 204 Algorithm 31 – RejBoundedPoly.

    Parameters
    ----------
    seed:
        66-byte seed.
    eta:
        Bound (2 or 4).

    Returns
    -------
    Polynomial
        Polynomial with coefficients in [−η, η].
    """
    xof = ShakeXOF(shake_256)
    xof.absorb(seed)

    coeffs: List[int] = []
    while len(coeffs) < 256:
        b = xof.read(1)[0]
        c0 = _coeff_from_half_byte(b & 0x0F, eta)
        if c0 is not None:
            coeffs.append(c0)
        if len(coeffs) < 256:
            c1 = _coeff_from_half_byte(b >> 4, eta)
            if c1 is not None:
                coeffs.append(c1)

    return Polynomial(coeffs[:256])


# ---------------------------------------------------------------------------
# ExpandA (Algorithm 32)
# ---------------------------------------------------------------------------

def ExpandA(rho: bytes, k: int, l: int) -> PolynomialMatrix:
    """FIPS 204 Algorithm 32 – ExpandA.

    Generates the k×ℓ public matrix Â ∈ T_q^{k×ℓ} from a 32-byte seed.

    Parameters
    ----------
    rho:
        32-byte public seed.
    k:
        Number of matrix rows.
    l:
        Number of matrix columns.

    Returns
    -------
    PolynomialMatrix
        Matrix in NTT domain.
    """
    # Note: seed is rho ‖ IntegerToBytes(s,1) ‖ IntegerToBytes(r,1)
    rows = [
        [_rej_ntt_poly(rho + bytes([s, r])) for s in range(l)]
        for r in range(k)
    ]
    return PolynomialMatrix(rows)


# ---------------------------------------------------------------------------
# ExpandS (Algorithm 33)
# ---------------------------------------------------------------------------

def ExpandS(
    rho_prime: bytes, eta: int, k: int, l: int
) -> Tuple[PolynomialVector, PolynomialVector]:
    """FIPS 204 Algorithm 33 – ExpandS.

    Samples the secret vectors s1 ∈ R_q^ℓ and s2 ∈ R_q^k.

    Parameters
    ----------
    rho_prime:
        64-byte private seed.
    eta:
        Coefficient range (2 or 4).
    k:
        Dimension of s2.
    l:
        Dimension of s1.

    Returns
    -------
    (s1, s2):
        Secret polynomial vectors.
    """
    s1_polys = [
        _rej_bounded_poly(rho_prime + IntegerToBytes(r, 2), eta)
        for r in range(l)
    ]
    s2_polys = [
        _rej_bounded_poly(rho_prime + IntegerToBytes(l + r, 2), eta)
        for r in range(k)
    ]
    return PolynomialVector(s1_polys), PolynomialVector(s2_polys)


# ---------------------------------------------------------------------------
# ExpandMask (Algorithm 34)
# ---------------------------------------------------------------------------

def ExpandMask(
    rho_pp: bytes, kappa: int, gamma_1: int, l: int
) -> PolynomialVector:
    """FIPS 204 Algorithm 34 – ExpandMask.

    Generates the mask vector y ∈ R_q^ℓ with coefficients in
    [−γ₁+1, γ₁].

    Parameters
    ----------
    rho_pp:
        64-byte private randomness seed (ρ'').
    kappa:
        Loop counter (incremented by ℓ each rejection).
    gamma_1:
        Masking bound (2^17 or 2^19).
    l:
        Vector dimension.

    Returns
    -------
    PolynomialVector
        Mask vector y.
    """
    # c = 1 + bitlen(γ₁ − 1)  (γ₁ is always a power of two)
    bit_count = gamma_1.bit_length()          # = 18 or 20
    total_bytes = 32 * bit_count              # = 576 or 640

    mask = (1 << bit_count) - 1
    polys: List[Polynomial] = []

    for r in range(l):
        seed = rho_pp + IntegerToBytes(kappa + r, 2)
        xof = ShakeXOF(shake_256)
        xof.absorb(seed)
        raw = xof.read(total_bytes)

        # Unpack bit_count-bit integers from the byte stream
        packed = int.from_bytes(raw, "little")
        coeffs = [
            gamma_1 - ((packed >> (bit_count * j)) & mask)
            for j in range(256)
        ]
        polys.append(Polynomial(coeffs))

    return PolynomialVector(polys)
