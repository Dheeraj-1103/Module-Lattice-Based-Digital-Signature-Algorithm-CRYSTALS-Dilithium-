"""
Polynomial algebra for ML-DSA.

Implements the ring  R_q = Z_q[X] / (X^256 + 1)  as well as length-k
vectors and k×ℓ matrices over R_q.  Both standard (coefficient) and
NTT representations are supported.

FIPS 204 §2.4, §7.5, §7.6.
"""

from __future__ import annotations

from typing import List, Tuple, Union

from ml_dsa.params import Q
from ml_dsa.ntt import ZETAS


# ---------------------------------------------------------------------------
# Scalar helpers
# ---------------------------------------------------------------------------

def _reduce_mod_pm(r: int, n: int) -> int:
    """Centered reduction: return r' ≡ r (mod n), r' ∈ (−n/2, n/2].

    Parameters
    ----------
    r:
        Input integer.
    n:
        Positive modulus.

    Returns
    -------
    int
        Centered representative.
    """
    r = r % n
    if r > (n >> 1):
        r -= n
    return r


def _decompose(r: int, alpha: int) -> Tuple[int, int]:
    """FIPS 204 Algorithm 36 – Decompose.

    Decomposes *r* ∈ Z_q into (r1, r0) such that
    r ≡ r1·alpha + r0 (mod q) with |r0| ≤ alpha/2, handling the
    special boundary case r1 = (q-1)/alpha.

    Parameters
    ----------
    r:
        Element of Z_q.
    alpha:
        Divisor (2·γ₂).

    Returns
    -------
    (r1, r0):
        High and low parts.
    """
    r_pos = r % Q
    r0 = _reduce_mod_pm(r_pos, alpha)
    if r_pos - r0 == Q - 1:
        return 0, r0 - 1
    return (r_pos - r0) // alpha, r0


def _high_bits(r: int, alpha: int) -> int:
    """FIPS 204 Algorithm 37 – HighBits."""
    r1, _ = _decompose(r, alpha)
    return r1


def _low_bits(r: int, alpha: int) -> int:
    """FIPS 204 Algorithm 38 – LowBits."""
    _, r0 = _decompose(r, alpha)
    return r0


def _make_hint(z: int, r: int, alpha: int) -> int:
    """FIPS 204 Algorithm 39 – MakeHint."""
    return int(_high_bits(r, alpha) != _high_bits(r + z, alpha))


def _use_hint(h: int, r: int, alpha: int) -> int:
    """FIPS 204 Algorithm 40 – UseHint."""
    m = (Q - 1) // alpha
    r1, r0 = _decompose(r, alpha)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def _check_norm(coeff: int, bound: int) -> bool:
    """Return True if |coeff mod±q| ≥ bound."""
    x = coeff % Q
    # Centered absolute value without branching
    x = ((Q - 1) >> 1) - x
    x = x ^ (x >> 31)          # abs
    x = ((Q - 1) >> 1) - x
    return x >= bound


# ---------------------------------------------------------------------------
# Polynomial
# ---------------------------------------------------------------------------

class Polynomial:
    """Polynomial in R_q = Z_q[X]/(X^256 + 1).

    Coefficients are always stored modulo *Q*.  The boolean flag
    ``is_ntt`` distinguishes the NTT representation from the
    coefficient representation.

    Parameters
    ----------
    coeffs:
        List of up to 256 integer coefficients.
    is_ntt:
        True if the coefficients are in NTT domain.
    """

    __slots__ = ("coeffs", "is_ntt")

    def __init__(self, coeffs: List[int], is_ntt: bool = False) -> None:
        if len(coeffs) > 256:
            raise ValueError(f"Polynomial degree must be < 256, got {len(coeffs)}")
        self.coeffs: List[int] = list(coeffs) + [0] * (256 - len(coeffs))
        self.is_ntt: bool = is_ntt

    # ------------------------------------------------------------------
    # Arithmetic
    # ------------------------------------------------------------------

    def __add__(self, other: "Polynomial") -> "Polynomial":
        return Polynomial(
            [(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)],
            self.is_ntt,
        )

    def __sub__(self, other: "Polynomial") -> "Polynomial":
        return Polynomial(
            [(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)],
            self.is_ntt,
        )

    def __mul__(self, other: Union["Polynomial", int]) -> "Polynomial":
        """Multiply by scalar int or by another Polynomial.

        Polynomial × Polynomial is only supported when *both* operands
        are in NTT form (fast, pointwise) or *neither* is (schoolbook,
        used only in tests).
        """
        if isinstance(other, int):
            return Polynomial([(c * other) % Q for c in self.coeffs], self.is_ntt)

        if isinstance(other, Polynomial):
            if self.is_ntt and other.is_ntt:
                return Polynomial(
                    [(a * b) % Q for a, b in zip(self.coeffs, other.coeffs)],
                    is_ntt=True,
                )
            if self.is_ntt ^ other.is_ntt:
                raise ValueError(
                    "Cannot multiply NTT polynomial with non-NTT polynomial; "
                    "convert both to the same domain first."
                )
            # Schoolbook (rarely executed path – correctness only)
            out = [0] * 256
            for i, ai in enumerate(self.coeffs):
                for j, bj in enumerate(other.coeffs):
                    k = i + j
                    if k < 256:
                        out[k] += ai * bj
                    else:
                        out[k - 256] -= ai * bj
            return Polynomial([c % Q for c in out], False)

        raise TypeError(f"Unsupported operand type: {type(other)}")

    def __neg__(self) -> "Polynomial":
        return Polynomial([(-c) % Q for c in self.coeffs], self.is_ntt)

    # ------------------------------------------------------------------
    # NTT
    # ------------------------------------------------------------------

    def to_ntt(self) -> "Polynomial":
        """FIPS 204 Algorithm 41 – forward NTT.

        Returns
        -------
        Polynomial
            *self* converted to NTT domain.

        Raises
        ------
        ValueError
            If already in NTT form.
        """
        if self.is_ntt:
            raise ValueError("Polynomial is already in NTT form.")

        w = self.coeffs[:]
        k = 0
        length = 128
        while length >= 1:
            start = 0
            while start < 256:
                k += 1
                zeta = ZETAS[k]
                for j in range(start, start + length):
                    t = (zeta * w[j + length]) % Q
                    w[j + length] = (w[j] - t) % Q
                    w[j]         = (w[j] + t) % Q
                start += 2 * length
            length >>= 1

        return Polynomial(w, is_ntt=True)

    def from_ntt(self) -> "Polynomial":
        """FIPS 204 Algorithm 42 – inverse NTT (NTT⁻¹).

        Returns
        -------
        Polynomial
            *self* converted back to coefficient domain.

        Raises
        ------
        ValueError
            If not in NTT form.
        """
        if not self.is_ntt:
            raise ValueError("Polynomial is not in NTT form.")

        w = self.coeffs[:]
        k = 256
        length = 1
        while length < 256:
            start = 0
            while start < 256:
                k -= 1
                zeta = (-ZETAS[k]) % Q
                for j in range(start, start + length):
                    t = w[j]
                    w[j]         = (t + w[j + length]) % Q
                    w[j + length] = (zeta * (t - w[j + length])) % Q
                start += 2 * length
            length <<= 1

        f_inv = pow(256, -1, Q)   # 256⁻¹ mod q = 8 347 681
        w = [(c * f_inv) % Q for c in w]
        return Polynomial(w, is_ntt=False)

    # ------------------------------------------------------------------
    # Decomposition helpers (applied coefficient-wise)
    # ------------------------------------------------------------------

    def power2round(self, d: int) -> Tuple["Polynomial", "Polynomial"]:
        """FIPS 204 Algorithm 35 – Power2Round applied coefficient-wise.

        Parameters
        ----------
        d:
            Number of dropped bits.

        Returns
        -------
        (r1, r0):
            High and low polynomials.
        """
        pow2 = 1 << d
        r1_c, r0_c = [], []
        for c in self.coeffs:
            r = c % Q
            r0 = _reduce_mod_pm(r, pow2)
            r1_c.append((r - r0) >> d)
            r0_c.append(r0)
        return Polynomial(r1_c), Polynomial(r0_c)

    def high_bits(self, alpha: int) -> "Polynomial":
        """HighBits applied to each coefficient."""
        return Polynomial([_high_bits(c, alpha) for c in self.coeffs])

    def low_bits(self, alpha: int) -> "Polynomial":
        """LowBits applied to each coefficient."""
        return Polynomial([_low_bits(c, alpha) for c in self.coeffs])

    def decompose(self, alpha: int) -> Tuple["Polynomial", "Polynomial"]:
        """Decompose each coefficient."""
        r1_c, r0_c = [], []
        for c in self.coeffs:
            r1, r0 = _decompose(c, alpha)
            r1_c.append(r1)
            r0_c.append(r0)
        return Polynomial(r1_c), Polynomial(r0_c)

    def make_hint(self, other: "Polynomial", alpha: int) -> "Polynomial":
        """MakeHint applied coefficient-wise: hint(self, other)."""
        return Polynomial(
            [_make_hint(a, b, alpha) for a, b in zip(self.coeffs, other.coeffs)]
        )

    def use_hint(self, h: "Polynomial", alpha: int) -> "Polynomial":
        """UseHint applied coefficient-wise: useHint(h, self)."""
        return Polynomial(
            [_use_hint(ha, ra, alpha) for ha, ra in zip(h.coeffs, self.coeffs)]
        )

    # ------------------------------------------------------------------
    # Norm check
    # ------------------------------------------------------------------

    def check_norm_bound(self, bound: int) -> bool:
        """Return True if **any** coefficient's centred absolute value ≥ *bound*.

        Parameters
        ----------
        bound:
            Norm bound to test.

        Returns
        -------
        bool
            ``True`` iff the polynomial's infinity norm exceeds *bound*.
        """
        return any(_check_norm(c, bound) for c in self.coeffs)

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        domain = "NTT" if self.is_ntt else "std"
        preview = self.coeffs[:4]
        return f"Polynomial([{preview}...], {domain})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self.is_ntt == other.is_ntt and self.coeffs == other.coeffs


# ---------------------------------------------------------------------------
# PolynomialVector
# ---------------------------------------------------------------------------

class PolynomialVector:
    """Length-k vector of Polynomial objects.

    Parameters
    ----------
    polys:
        List of polynomials.
    """

    __slots__ = ("polys",)

    def __init__(self, polys: List[Polynomial]) -> None:
        self.polys: List[Polynomial] = list(polys)

    # Indexing / length
    def __getitem__(self, idx: int) -> Polynomial:
        return self.polys[idx]

    def __len__(self) -> int:
        return len(self.polys)

    # Arithmetic
    def __add__(self, other: "PolynomialVector") -> "PolynomialVector":
        return PolynomialVector([a + b for a, b in zip(self.polys, other.polys)])

    def __sub__(self, other: "PolynomialVector") -> "PolynomialVector":
        return PolynomialVector([a - b for a, b in zip(self.polys, other.polys)])

    def __neg__(self) -> "PolynomialVector":
        return PolynomialVector([-p for p in self.polys])

    def scale(self, scalar: int) -> "PolynomialVector":
        """Multiply every polynomial by an integer scalar."""
        return PolynomialVector([p * scalar for p in self.polys])

    # NTT
    def to_ntt(self) -> "PolynomialVector":
        """Convert all polynomials to NTT domain."""
        return PolynomialVector([p.to_ntt() for p in self.polys])

    def from_ntt(self) -> "PolynomialVector":
        """Convert all polynomials from NTT domain."""
        return PolynomialVector([p.from_ntt() for p in self.polys])

    # Norm check
    def check_norm_bound(self, bound: int) -> bool:
        """Return True if any polynomial's infinity norm ≥ *bound*."""
        return any(p.check_norm_bound(bound) for p in self.polys)

    def __repr__(self) -> str:
        return f"PolynomialVector(len={len(self.polys)})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PolynomialVector):
            return NotImplemented
        return self.polys == other.polys


# ---------------------------------------------------------------------------
# PolynomialMatrix
# ---------------------------------------------------------------------------

class PolynomialMatrix:
    """k×ℓ matrix of Polynomial objects (always stored in NTT domain).

    Parameters
    ----------
    rows:
        List of rows; each row is a list of Polynomial objects.
    """

    __slots__ = ("rows", "nrows", "ncols")

    def __init__(self, rows: List[List[Polynomial]]) -> None:
        self.rows: List[List[Polynomial]] = rows
        self.nrows: int = len(rows)
        self.ncols: int = len(rows[0]) if rows else 0

    def __mul__(self, vec: PolynomialVector) -> PolynomialVector:
        """Matrix–vector product in NTT domain (Algorithm 48).

        Parameters
        ----------
        vec:
            Length-ℓ vector in NTT domain.

        Returns
        -------
        PolynomialVector
            Result of A·v (NTT domain), length k.
        """
        result: List[Polynomial] = []
        for row in self.rows:
            acc = Polynomial([0] * 256, is_ntt=True)
            for a_ij, v_j in zip(row, vec.polys):
                acc = acc + (a_ij * v_j)
            result.append(acc)
        return PolynomialVector(result)

    def __repr__(self) -> str:
        return f"PolynomialMatrix({self.nrows}×{self.ncols})"
