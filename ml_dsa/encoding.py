"""
Bit-packing and encoding routines for ML-DSA keys and signatures.

Implements FIPS 204 §7.2, Algorithms 16–28.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ml_dsa.params import Q
from ml_dsa.polynomial import Polynomial, PolynomialVector
from ml_dsa.utils import IntegerToBytes, IntegerToBits, BitsToInteger, BitsToBytes, BytesToBits


# ---------------------------------------------------------------------------
# Generic bit-packing helpers (Algorithms 16–19)
# ---------------------------------------------------------------------------

def simple_bit_pack(poly: Polynomial, b: int) -> bytes:
    """Algorithm 16 – SimpleBitPack.  Coefficients in [0, b]."""
    width = b.bit_length()                    # bitlen(b)
    bits: List[int] = []
    for c in poly.coeffs:
        bits.extend(IntegerToBits(c, width))
    return BitsToBytes(bits)


def bit_pack(poly: Polynomial, a: int, b: int) -> bytes:
    """Algorithm 17 – BitPack.  Coefficients in [−a, b]."""
    width = (a + b).bit_length()
    bits: List[int] = []
    for c in poly.coeffs:
        bits.extend(IntegerToBits(b - c, width))
    return BitsToBytes(bits)


def simple_bit_unpack(data: bytes, b: int) -> Polynomial:
    """Algorithm 18 – SimpleBitUnpack."""
    width = b.bit_length()
    bits = BytesToBits(data)
    coeffs = [
        BitsToInteger(bits[i * width: (i + 1) * width], width)
        for i in range(256)
    ]
    return Polynomial(coeffs)


def bit_unpack(data: bytes, a: int, b: int) -> Polynomial:
    """Algorithm 19 – BitUnpack."""
    width = (a + b).bit_length()
    bits = BytesToBits(data)
    coeffs = [
        b - BitsToInteger(bits[i * width: (i + 1) * width], width)
        for i in range(256)
    ]
    return Polynomial(coeffs)


# ---------------------------------------------------------------------------
# HintBitPack / HintBitUnpack (Algorithms 20–21)
# ---------------------------------------------------------------------------

def hint_bit_pack(h_vec: PolynomialVector, omega: int) -> bytes:
    """FIPS 204 Algorithm 20 – HintBitPack.

    Encodes a hint vector into (omega + k) bytes where:
    - First omega bytes contain non-zero coefficient positions
    - Last k bytes are running counts per polynomial

    Parameters
    ----------
    h_vec:
        Hint polynomial vector.
    omega:
        Maximum number of hints (from parameter set).

    Returns
    -------
    bytes
        Encoded hint of length ``omega + k``.
    """
    k = len(h_vec)
    y = bytearray(omega + k)
    index = 0

    for i, poly in enumerate(h_vec.polys):
        for j in range(256):
            if poly.coeffs[j] != 0:
                if index >= omega:
                    raise ValueError("Too many hint bits (> omega)")
                y[index] = j
                index += 1
        y[omega + i] = index          # cumulative count after poly i

    return bytes(y)


def hint_bit_unpack(data: bytes, omega: int, k: int) -> Optional[PolynomialVector]:
    """FIPS 204 Algorithm 21 – HintBitUnpack.

    Parameters
    ----------
    data:
        Encoded hint of length ``omega + k``.
    omega:
        Maximum number of hints.
    k:
        Number of polynomials.

    Returns
    -------
    PolynomialVector or None
        Decoded hint vector, or *None* on malformed input.
    """
    if len(data) != omega + k:
        return None

    polys: List[Polynomial] = []
    index = 0

    for i in range(k):
        end = data[omega + i]

        # Boundary checks
        if end < index or end > omega:
            return None

        first = index
        coeffs = [0] * 256
        while index < end:
            # Strict monotonic ordering (FIPS 204 Algorithm 21, line 9)
            if index > first and data[index - 1] >= data[index]:
                return None
            pos = data[index]
            if pos >= 256:
                return None
            coeffs[pos] = 1
            index += 1

        polys.append(Polynomial(coeffs))

    # Remaining bytes in the hint region must be zero
    for i in range(index, omega):
        if data[i] != 0:
            return None

    return PolynomialVector(polys)


# ---------------------------------------------------------------------------
# Public-key encoding (Algorithms 22–23)
# ---------------------------------------------------------------------------

def pk_encode(rho: bytes, t1: PolynomialVector) -> bytes:
    """Algorithm 22 – pkEncode.

    pk = rho ‖ SimpleBitPack(t1[0], 2^(bitlen(q−1)−d) − 1) ‖ …
    """
    # bitlen(q−1) − d = 23 − 13 = 10  →  t1 coefficients in [0, 2^10 − 1]
    b = (1 << 10) - 1
    parts = [rho] + [simple_bit_pack(p, b) for p in t1.polys]
    return b"".join(parts)


def pk_decode(pk: bytes) -> Tuple[bytes, PolynomialVector]:
    """Algorithm 23 – pkDecode.

    Returns
    -------
    (rho, t1):
        32-byte seed and t1 polynomial vector.
    """
    rho = pk[:32]
    b = (1 << 10) - 1
    chunk = 32 * b.bit_length()            # = 320 bytes per polynomial
    polys = [
        simple_bit_unpack(pk[32 + i * chunk: 32 + (i + 1) * chunk], b)
        for i in range((len(pk) - 32) // chunk)
    ]
    return rho, PolynomialVector(polys)


# ---------------------------------------------------------------------------
# Secret-key encoding (Algorithms 24–25)
# ---------------------------------------------------------------------------

def sk_encode(
    rho: bytes,
    K: bytes,
    tr: bytes,
    s1: PolynomialVector,
    s2: PolynomialVector,
    t0: PolynomialVector,
    eta: int,
    d: int,
) -> bytes:
    """Algorithm 24 – skEncode.

    Parameters
    ----------
    rho:
        32-byte public seed.
    K:
        32-byte private seed.
    tr:
        64-byte public-key hash.
    s1, s2:
        Secret vectors with coefficients in [−η, η].
    t0:
        Low-order bits of t, coefficients in [−2^{d−1}+1, 2^{d−1}].
    eta, d:
        Parameter set values.

    Returns
    -------
    bytes
        Encoded private key.
    """
    parts = [rho, K, tr]
    for p in s1.polys:
        parts.append(bit_pack(p, eta, eta))
    for p in s2.polys:
        parts.append(bit_pack(p, eta, eta))
    for p in t0.polys:
        parts.append(bit_pack(p, (1 << (d - 1)) - 1, 1 << (d - 1)))
    return b"".join(parts)


def sk_decode(
    sk: bytes, k: int, l: int, eta: int, d: int
) -> Tuple[bytes, bytes, bytes, PolynomialVector, PolynomialVector, PolynomialVector]:
    """Algorithm 25 – skDecode.

    Parameters
    ----------
    sk:
        Encoded private key.
    k, l:
        Parameter set dimensions.
    eta, d:
        Parameter set values.

    Returns
    -------
    (rho, K, tr, s1, s2, t0):
        Decoded private-key components.
    """
    offset = 0

    rho = sk[offset: offset + 32];  offset += 32
    K   = sk[offset: offset + 32];  offset += 32
    tr  = sk[offset: offset + 64];  offset += 64

    s_width = (2 * eta).bit_length()       # bits per coefficient
    s_bytes = 32 * s_width                  # bytes per polynomial

    s1_polys = []
    for _ in range(l):
        s1_polys.append(bit_unpack(sk[offset: offset + s_bytes], eta, eta))
        offset += s_bytes

    s2_polys = []
    for _ in range(k):
        s2_polys.append(bit_unpack(sk[offset: offset + s_bytes], eta, eta))
        offset += s_bytes

    # t0: coefficients in [−2^{d−1}+1, 2^{d−1}], packed with d bits each
    t0_bytes = 32 * d                        # 32 × 13 = 416 bytes per poly
    t0_polys = []
    for _ in range(k):
        t0_polys.append(
            bit_unpack(sk[offset: offset + t0_bytes], (1 << (d - 1)) - 1, 1 << (d - 1))
        )
        offset += t0_bytes

    return rho, K, tr, PolynomialVector(s1_polys), PolynomialVector(s2_polys), PolynomialVector(t0_polys)


# ---------------------------------------------------------------------------
# Signature encoding (Algorithms 26–27)
# ---------------------------------------------------------------------------

def sig_encode(
    c_tilde: bytes,
    z: PolynomialVector,
    h: PolynomialVector,
    gamma_1: int,
    omega: int,
) -> bytes:
    """Algorithm 26 – sigEncode."""
    parts = [c_tilde]
    for p in z.polys:
        parts.append(bit_pack(p, gamma_1 - 1, gamma_1))
    parts.append(hint_bit_pack(h, omega))
    return b"".join(parts)


def sig_decode(
    sig: bytes,
    lambda_bytes: int,
    l: int,
    gamma_1: int,
    omega: int,
    k: int,
) -> Optional[Tuple[bytes, PolynomialVector, Optional[PolynomialVector]]]:
    """Algorithm 27 – sigDecode.

    Parameters
    ----------
    sig:
        Encoded signature bytes.
    lambda_bytes:
        λ/4 (number of c̃ bytes).
    l:
        Number of z polynomials.
    gamma_1:
        Masking bound.
    omega:
        Maximum hint count.
    k:
        Number of hint polynomials.

    Returns
    -------
    (c_tilde, z, h) or None
        Decoded components or *None* on bad length.  *h* may be *None*
        on malformed hints (caller should return False in that case).
    """
    z_width = gamma_1.bit_length()          # 18 or 20
    z_poly_bytes = 32 * z_width             # 576 or 640

    expected = lambda_bytes + l * z_poly_bytes + omega + k
    if len(sig) != expected:
        return None

    offset = 0
    c_tilde = sig[offset: offset + lambda_bytes];  offset += lambda_bytes

    z_polys = []
    for _ in range(l):
        z_polys.append(bit_unpack(sig[offset: offset + z_poly_bytes], gamma_1 - 1, gamma_1))
        offset += z_poly_bytes

    h = hint_bit_unpack(sig[offset:], omega, k)   # None → malformed

    return c_tilde, PolynomialVector(z_polys), h


# ---------------------------------------------------------------------------
# w1Encode (Algorithm 28)
# ---------------------------------------------------------------------------

def w1_encode(w1: PolynomialVector, gamma_2: int) -> bytes:
    """Algorithm 28 – w1Encode.

    Parameters
    ----------
    w1:
        Commitment vector whose coefficients are in [0, (q−1)/(2γ₂) − 1].
    gamma_2:
        Low-order rounding bound.

    Returns
    -------
    bytes
        Packed byte representation.
    """
    b = (Q - 1) // (2 * gamma_2) - 1    # max coefficient value
    return b"".join(simple_bit_pack(p, b) for p in w1.polys)
