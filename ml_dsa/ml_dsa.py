"""
ML-DSA and HashML-DSA implementation.

Implements FIPS 204 §5–§6:
    ML_DSA.KeyGen            (Algorithm 1 → 6)
    ML_DSA.Sign              (Algorithm 2 → 7)
    ML_DSA.Verify            (Algorithm 3 → 8)
    HashML_DSA.Sign          (Algorithm 4)
    HashML_DSA.Verify        (Algorithm 5)

All critical FIPS 204 correctness requirements are enforced, including:
    • Norm-bound rejection on z, r0, ct0    (reject when OUTSIDE bound)
    • kappa incremented by ℓ each iteration (per Algorithm 7, line 31)
    • Strict monotone index check in HintBitUnpack
    • Constant-time signature comparison via hmac.compare_digest
    • Message framing with context string   (§5.2, §5.3)
"""

from __future__ import annotations

import hmac
import os
from hashlib import sha256, sha512, shake_128
from typing import Optional, Tuple

from ml_dsa.params import PARAMETER_SETS, SIZES, Q
from ml_dsa.polynomial import Polynomial, PolynomialVector
from ml_dsa.sampling import ExpandA, ExpandS, ExpandMask, SampleInBall
from ml_dsa.encoding import (
    pk_encode, pk_decode,
    sk_encode, sk_decode,
    sig_encode, sig_decode,
    w1_encode,
    hint_bit_pack,
)
from ml_dsa.utils import H, IntegerToBytes, BytesToBits, BitsToBytes


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _center(x: int) -> int:
    """Reduce x to the centred representative in (−q/2, q/2]."""
    x = x % Q
    if x > Q >> 1:
        x -= Q
    return x


# ---------------------------------------------------------------------------
# ML_DSA
# ---------------------------------------------------------------------------

class ML_DSA:
    """FIPS 204 ML-DSA digital signature scheme.

    Parameters
    ----------
    mode:
        One of ``"ML-DSA-44"``, ``"ML-DSA-65"``, ``"ML-DSA-87"``.

    Raises
    ------
    ValueError
        If *mode* is not a recognised parameter set.

    Example
    -------
    >>> dsa = ML_DSA("ML-DSA-44")
    >>> pk, sk = dsa.KeyGen()
    >>> sig = dsa.Sign(sk, b"message")
    >>> assert dsa.Verify(pk, b"message", sig)
    """

    def __init__(self, mode: str = "ML-DSA-44") -> None:
        if mode not in PARAMETER_SETS:
            raise ValueError(
                f"Unknown parameter set '{mode}'. "
                f"Valid choices: {list(PARAMETER_SETS.keys())}"
            )
        self.mode = mode
        p = PARAMETER_SETS[mode]

        self.k:       int = p["k"]
        self.l:       int = p["l"]
        self.eta:     int = p["eta"]
        self.tau:     int = p["tau"]
        self.gamma_1: int = p["gamma_1"]
        self.gamma_2: int = p["gamma_2"]
        self.omega:   int = p["omega"]
        self.lam:     int = p["lambda"]        # λ (collision strength)
        self.d:       int = p["d"]
        self.beta:    int = p["beta"]          # τ · η

        # λ/4 bytes = size of c̃
        self.lambda_bytes: int = self.lam // 4

        # Validate derived parameters
        assert self.beta < self.gamma_2, (
            f"Parameter constraint violated: beta ({self.beta}) must be < "
            f"gamma_2 ({self.gamma_2})"
        )
        assert self.beta < self.gamma_1, (
            f"Parameter constraint violated: beta ({self.beta}) must be < "
            f"gamma_1 ({self.gamma_1})"
        )

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def KeyGen(self) -> Tuple[bytes, bytes]:
        """FIPS 204 Algorithm 1 – ML-DSA.KeyGen.

        Returns
        -------
        (pk, sk):
            Encoded public key and private key.
        """
        xi = os.urandom(32)
        return self.KeyGen_internal(xi)

    def KeyGen_internal(self, xi: bytes) -> Tuple[bytes, bytes]:
        """FIPS 204 Algorithm 6 – ML-DSA.KeyGen_internal.

        Parameters
        ----------
        xi:
            32-byte random seed.

        Returns
        -------
        (pk, sk):
            Encoded public and private keys.
        """
        # Expand seed with domain separation (k ‖ l)
        seed_bytes = H(
            xi + IntegerToBytes(self.k, 1) + IntegerToBytes(self.l, 1),
            128,
        )
        rho      = seed_bytes[:32]
        rho_p    = seed_bytes[32:96]
        K        = seed_bytes[96:128]

        # Generate A, s1, s2
        A_hat        = ExpandA(rho, self.k, self.l)
        s1, s2       = ExpandS(rho_p, self.eta, self.k, self.l)

        # t = A·s1 + s2
        s1_hat  = s1.to_ntt()
        t_hat   = A_hat * s1_hat
        t       = t_hat.from_ntt() + s2

        # Compress: t → (t1, t0) via Power2Round
        t1_polys, t0_polys = [], []
        for p in t.polys:
            p1, p0 = p.power2round(self.d)
            t1_polys.append(p1)
            t0_polys.append(p0)
        t1 = PolynomialVector(t1_polys)
        t0 = PolynomialVector(t0_polys)

        # Encode public key; hash for tr
        pk = pk_encode(rho, t1)
        tr = H(pk, 64)

        # Encode private key
        sk = sk_encode(rho, K, tr, s1, s2, t0, self.eta, self.d)

        assert len(pk) == SIZES[self.mode]["pk"], "BUG: pk length mismatch"
        assert len(sk) == SIZES[self.mode]["sk"], "BUG: sk length mismatch"

        return pk, sk

    # ------------------------------------------------------------------
    # Signing – external wrapper
    # ------------------------------------------------------------------

    def Sign(
        self,
        sk: bytes,
        M: bytes,
        ctx: bytes = b"",
        deterministic: bool = False,
    ) -> Optional[bytes]:
        """FIPS 204 Algorithm 2 – ML-DSA.Sign.

        Parameters
        ----------
        sk:
            Encoded private key.
        M:
            Message (bytes).
        ctx:
            Context string, at most 255 bytes.
        deterministic:
            Use all-zero randomness instead of fresh randomness.
            **Do not use in production** – provided only for testing.

        Returns
        -------
        bytes or None
            Signature, or *None* on catastrophic failure (extremely rare).

        Raises
        ------
        ValueError
            If *ctx* exceeds 255 bytes.
        """
        if len(ctx) > 255:
            raise ValueError("Context string must be at most 255 bytes.")

        rnd = bytes(32) if deterministic else os.urandom(32)

        # M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M
        M_prime = bytes([0x00, len(ctx)]) + ctx + M
        return self.Sign_internal(sk, M_prime, rnd)

    def Sign_internal(
        self, sk: bytes, M_prime: bytes, rnd: bytes
    ) -> Optional[bytes]:
        """FIPS 204 Algorithm 7 – ML-DSA.Sign_internal.

        Parameters
        ----------
        sk:
            Encoded private key.
        M_prime:
            Formatted message (includes domain-separation prefix).
        rnd:
            32-byte randomness string.

        Returns
        -------
        bytes or None
            Signature, or *None* if the rejection-sampling loop exceeds
            its safety limit (probability < 2^{-256}).
        """
        # Decode private key
        rho, K, tr, s1, s2, t0 = sk_decode(sk, self.k, self.l, self.eta, self.d)

        # Pre-compute NTT forms of secret vectors
        s1_hat = s1.to_ntt()
        s2_hat = s2.to_ntt()
        t0_hat = t0.to_ntt()

        # Expand public matrix
        A_hat = ExpandA(rho, self.k, self.l)

        # Message representative: μ = H(tr ‖ M', 64)
        mu = H(tr + M_prime, 64)

        # Private randomness seed: ρ'' = H(K ‖ rnd ‖ μ, 64)
        rho_pp = H(K + rnd + mu, 64)

        # ----------------------------------------------------------------
        # Rejection-sampling loop
        # ----------------------------------------------------------------
        kappa = 0
        MAX_ITERATIONS = 814          # FIPS 204 Appendix C (2^{-256} failure)
        alpha = 2 * self.gamma_2

        while kappa < MAX_ITERATIONS:
            # Sample mask y and compute w = A·y
            y       = ExpandMask(rho_pp, kappa, self.gamma_1, self.l)
            y_hat   = y.to_ntt()
            w_hat   = A_hat * y_hat
            w       = w_hat.from_ntt()

            # Decompose w into (w1, w0)  →  commitment w1
            w1_polys, w0_polys = [], []
            for p in w.polys:
                p1, p0 = p.decompose(alpha)
                w1_polys.append(p1)
                w0_polys.append(p0)
            w1 = PolynomialVector(w1_polys)
            w0 = PolynomialVector(w0_polys)

            # Commitment hash c̃ = H(μ ‖ w1Encode(w1), λ/4)
            c_tilde = H(mu + w1_encode(w1, self.gamma_2), self.lambda_bytes)

            # Sample challenge c from c̃
            c     = SampleInBall(c_tilde, self.tau)
            c_hat = c.to_ntt()

            # Compute z = y + c·s1  and  r0 = LowBits(w − c·s2)
            cs1 = PolynomialVector([
                (c_hat * s1_hat[i]).from_ntt() for i in range(self.l)
            ])
            cs2 = PolynomialVector([
                (c_hat * s2_hat[i]).from_ntt() for i in range(self.k)
            ])
            z  = y + cs1
            r0 = w0 - cs2

            # FIPS 204 Algorithm 7, line 33: z is encoded as z mod±q
            # Centre z coefficients into (−q/2, q/2] so BitPack works correctly
            z = PolynomialVector([
                Polynomial([_center(c) for c in p.coeffs])
                for p in z.polys
            ])

            # ---- Rejection checks ----------------------------------------
            # (a) ||z||_∞ ≥ γ₁ − β  →  reject
            if z.check_norm_bound(self.gamma_1 - self.beta):
                kappa += self.l
                continue

            # (b) ||r0||_∞ ≥ γ₂ − β  →  reject
            if r0.check_norm_bound(self.gamma_2 - self.beta):
                kappa += self.l
                continue

            # Compute ct0 for hints
            ct0 = PolynomialVector([
                (c_hat * t0_hat[i]).from_ntt() for i in range(self.k)
            ])

            # (c) ||ct0||_∞ ≥ γ₂  →  reject
            if ct0.check_norm_bound(self.gamma_2):
                kappa += self.l
                continue

            # ---- Compute hints h = MakeHint(−ct0, w − cs2 + ct0) --------
            h_polys = []
            hint_count = 0
            for i in range(self.k):
                # w − cs2 + ct0 = (w0 − cs2) + ct0 = r0 + ct0
                r0_plus_ct0 = r0[i] + ct0[i]
                neg_ct0     = (-ct0[i])

                h_p = neg_ct0.make_hint(r0_plus_ct0, alpha)
                h_polys.append(h_p)
                hint_count += sum(h_p.coeffs)

            # (d) hint count > ω  →  reject
            if hint_count > self.omega:
                kappa += self.l
                continue

            # ---- Accept: encode and return signature ----------------------
            h   = PolynomialVector(h_polys)
            sig = sig_encode(c_tilde, z, h, self.gamma_1, self.omega)

            assert len(sig) == SIZES[self.mode]["sig"], "BUG: sig length mismatch"
            return sig

        # Extremely unlikely to reach here
        return None

    # ------------------------------------------------------------------
    # Verification – external wrapper
    # ------------------------------------------------------------------

    def Verify(
        self, pk: bytes, M: bytes, sig: bytes, ctx: bytes = b""
    ) -> bool:
        """FIPS 204 Algorithm 3 – ML-DSA.Verify.

        Parameters
        ----------
        pk:
            Encoded public key.
        M:
            Message.
        sig:
            Signature.
        ctx:
            Context string (at most 255 bytes).

        Returns
        -------
        bool
            True iff the signature is valid.
        """
        if len(ctx) > 255:
            return False

        M_prime = bytes([0x00, len(ctx)]) + ctx + M
        return self.Verify_internal(pk, M_prime, sig)

    def Verify_internal(self, pk: bytes, M_prime: bytes, sig: bytes) -> bool:
        """FIPS 204 Algorithm 8 – ML-DSA.Verify_internal.

        Parameters
        ----------
        pk:
            Encoded public key.
        M_prime:
            Formatted message.
        sig:
            Encoded signature.

        Returns
        -------
        bool
            True iff the signature is valid.
        """
        # ---- Length checks (FIPS 204 §3.6.2) ----------------------------
        if len(pk) != SIZES[self.mode]["pk"]:
            return False
        if len(sig) != SIZES[self.mode]["sig"]:
            return False

        # ---- Decode ------------------------------------------------------
        rho, t1 = pk_decode(pk)

        decoded = sig_decode(
            sig, self.lambda_bytes, self.l, self.gamma_1, self.omega, self.k
        )
        if decoded is None:
            return False
        c_tilde, z, h = decoded
        if h is None:
            return False

        # ---- Norm check on z  (FIPS 204 Alg. 8, line 13) ----------------
        if z.check_norm_bound(self.gamma_1 - self.beta):
            return False

        # ---- Recompute verification equation -----------------------------
        tr  = H(pk, 64)
        mu  = H(tr + M_prime, 64)

        A_hat = ExpandA(rho, self.k, self.l)
        c     = SampleInBall(c_tilde, self.tau)
        c_hat = c.to_ntt()

        # w'_Approx = A·z − c·t1·2^d
        z_hat    = z.to_ntt()
        Az_hat   = A_hat * z_hat

        t1_2d = t1.scale(1 << self.d)
        ct1_hat = PolynomialVector([
            c_hat * t1_2d[i].to_ntt() for i in range(self.k)
        ])

        w_approx = (Az_hat - ct1_hat).from_ntt()

        # w'1 = UseHint(h, w'_Approx)
        alpha     = 2 * self.gamma_2
        w1_prime_polys = []
        for i in range(self.k):
            w1_prime_polys.append(w_approx[i].use_hint(h[i], alpha))
        w1_prime = PolynomialVector(w1_prime_polys)

        # Recompute c̃'
        c_tilde_prime = H(mu + w1_encode(w1_prime, self.gamma_2), self.lambda_bytes)

        # Constant-time comparison (FIPS 204 §3.6.4 spirit; avoids early exit)
        return hmac.compare_digest(c_tilde, c_tilde_prime)


# ---------------------------------------------------------------------------
# HashML_DSA  (pre-hash variant)
# ---------------------------------------------------------------------------

class HashML_DSA(ML_DSA):
    """FIPS 204 HashML-DSA (pre-hash variant).

    Supports SHA-256, SHA-512, and SHAKE-128 as pre-hash functions.
    The signing and verification algorithms differ from plain ML-DSA in
    that a hash digest of the message is signed rather than the raw message.

    Example
    -------
    >>> dsa = HashML_DSA("ML-DSA-65")
    >>> pk, sk = dsa.KeyGen()
    >>> sig = dsa.Sign(sk, large_file_bytes, hash_name="SHA512")
    >>> assert dsa.Verify(pk, large_file_bytes, sig, hash_name="SHA512")
    """

    # OID table (FIPS 204, Algorithm 4)
    _OID: dict = {
        "SHA256":   bytes([0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01]),
        "SHA512":   bytes([0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03]),
        "SHAKE128": bytes([0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0B]),
    }

    def _prehash(self, M: bytes, hash_name: str) -> Tuple[bytes, bytes]:
        """Compute the pre-hash digest and return (OID, digest).

        Raises
        ------
        ValueError
            If *hash_name* is not supported.
        """
        name = hash_name.upper()
        if name not in self._OID:
            raise ValueError(
                f"Unsupported hash '{hash_name}'. "
                f"Supported: {list(self._OID)}"
            )
        oid = self._OID[name]
        if name == "SHA256":
            digest = sha256(M).digest()
        elif name == "SHA512":
            digest = sha512(M).digest()
        else:  # SHAKE128
            digest = shake_128(M).digest(32)
        return oid, digest

    def Sign(               # type: ignore[override]
        self,
        sk: bytes,
        M: bytes,
        ctx: bytes = b"",
        deterministic: bool = False,
        hash_name: str = "SHA512",
    ) -> Optional[bytes]:
        """FIPS 204 Algorithm 4 – HashML-DSA.Sign.

        Parameters
        ----------
        sk:
            Encoded private key.
        M:
            Full message (will be hashed internally).
        ctx:
            Context string (at most 255 bytes).
        deterministic:
            Use all-zero randomness (testing only).
        hash_name:
            Pre-hash function: ``"SHA256"``, ``"SHA512"``, or ``"SHAKE128"``.

        Returns
        -------
        bytes or None
            Signature or *None* on failure.
        """
        if len(ctx) > 255:
            raise ValueError("Context string must be at most 255 bytes.")

        rnd     = bytes(32) if deterministic else os.urandom(32)
        oid, ph = self._prehash(M, hash_name)

        # M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID ‖ PH(M)
        M_prime = bytes([0x01, len(ctx)]) + ctx + oid + ph
        return self.Sign_internal(sk, M_prime, rnd)

    def Verify(             # type: ignore[override]
        self,
        pk: bytes,
        M: bytes,
        sig: bytes,
        ctx: bytes = b"",
        hash_name: str = "SHA512",
    ) -> bool:
        """FIPS 204 Algorithm 5 – HashML-DSA.Verify.

        Parameters
        ----------
        pk:
            Encoded public key.
        M:
            Original message.
        sig:
            Signature.
        ctx:
            Context string.
        hash_name:
            Same pre-hash function used during signing.

        Returns
        -------
        bool
            True iff signature is valid.
        """
        if len(ctx) > 255:
            return False
        try:
            oid, ph = self._prehash(M, hash_name)
        except ValueError:
            return False

        M_prime = bytes([0x01, len(ctx)]) + ctx + oid + ph
        return self.Verify_internal(pk, M_prime, sig)
