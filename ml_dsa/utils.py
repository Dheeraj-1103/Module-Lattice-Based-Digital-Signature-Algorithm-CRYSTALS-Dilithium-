"""
Utility functions for ML-DSA.

Implements FIPS 204 §3.7 symmetric primitives and §7.1 data-type conversions.
"""

from __future__ import annotations

from hashlib import shake_128, shake_256
from typing import List


# ---------------------------------------------------------------------------
# Hash / XOF wrappers (FIPS 204 §3.7)
# ---------------------------------------------------------------------------

def H(data: bytes, output_len: int) -> bytes:
    """SHAKE-256 with fixed output length (λ/4 or 64 bytes).

    Parameters
    ----------
    data:
        Input byte string.
    output_len:
        Number of output bytes.

    Returns
    -------
    bytes
        ``output_len`` bytes of SHAKE-256 digest.
    """
    return shake_256(data).digest(output_len)


def G(data: bytes, output_len: int) -> bytes:
    """SHAKE-128 with fixed output length (used in ExpandA / RejNTTPoly).

    Parameters
    ----------
    data:
        Input byte string.
    output_len:
        Number of output bytes.

    Returns
    -------
    bytes
        ``output_len`` bytes of SHAKE-128 digest.
    """
    return shake_128(data).digest(output_len)


class ShakeXOF:
    """Streaming XOF wrapper supporting incremental reads.

    Abstracts Python's one-shot ``shake_*.digest()`` into an
    incremental absorb/squeeze API close to FIPS 202 SP 800-185.

    Parameters
    ----------
    algorithm:
        ``shake_128`` or ``shake_256``.
    """

    def __init__(self, algorithm) -> None:
        self._algo = algorithm
        self._buf: bytes = b""
        self._pos: int = 0
        self._digest_fn = None

    # ------------------------------------------------------------------
    def absorb(self, data: bytes) -> "ShakeXOF":
        """Absorb *data* and reset the read position.

        Parameters
        ----------
        data:
            Bytes to absorb.

        Returns
        -------
        ShakeXOF
            *self* for chaining.
        """
        self._digest_fn = self._algo(data).digest
        self._buf = self._digest_fn(168)   # one block to start
        self._pos = 0
        return self

    # ------------------------------------------------------------------
    def read(self, n: int) -> bytes:
        """Read *n* bytes from the XOF stream.

        Parameters
        ----------
        n:
            Bytes to read.

        Returns
        -------
        bytes
            Next *n* bytes from the XOF output.
        """
        while self._pos + n > len(self._buf):
            # Double the output buffer until we have enough
            self._buf = self._digest_fn(len(self._buf) * 2)
        chunk = self._buf[self._pos: self._pos + n]
        self._pos += n
        return chunk


# ---------------------------------------------------------------------------
# Data-type conversions (FIPS 204 §7.1, Algorithms 9–13)
# ---------------------------------------------------------------------------

def IntegerToBits(x: int, alpha: int) -> List[int]:
    """Algorithm 9 – little-endian integer → bit string of length *alpha*.

    Parameters
    ----------
    x:
        Non-negative integer.
    alpha:
        Bit-string length.

    Returns
    -------
    List[int]
        Bit string of length *alpha* in little-endian order.
    """
    bits: List[int] = []
    for _ in range(alpha):
        bits.append(x & 1)
        x >>= 1
    return bits


def BitsToInteger(bits: List[int], alpha: int) -> int:
    """Algorithm 10 – little-endian bit string → integer.

    Parameters
    ----------
    bits:
        Bit string of length *alpha* in little-endian order.
    alpha:
        Bit-string length.

    Returns
    -------
    int
        Reconstructed non-negative integer.
    """
    x = 0
    for i in range(1, alpha + 1):
        x = (x << 1) | bits[alpha - i]
    return x


def IntegerToBytes(x: int, alpha: int) -> bytes:
    """Algorithm 11 – little-endian integer → byte string of length *alpha*.

    Parameters
    ----------
    x:
        Non-negative integer.
    alpha:
        Byte-string length.

    Returns
    -------
    bytes
        Little-endian byte representation.
    """
    return x.to_bytes(alpha, "little")


def BitsToBytes(bits: List[int]) -> bytes:
    """Algorithm 12 – bit string → byte string (little-endian packing).

    Parameters
    ----------
    bits:
        Bit string (length need not be a multiple of 8).

    Returns
    -------
    bytes
        Packed bytes (ceil(len(bits)/8) bytes).
    """
    n = len(bits)
    out = bytearray((n + 7) >> 3)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def BytesToBits(data: bytes) -> List[int]:
    """Algorithm 13 – byte string → bit string (little-endian unpacking).

    Parameters
    ----------
    data:
        Input bytes.

    Returns
    -------
    List[int]
        Bit string of length ``8 * len(data)`` in little-endian order.
    """
    bits: List[int] = []
    for byte in data:
        for j in range(8):
            bits.append((byte >> j) & 1)
    return bits
