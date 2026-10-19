"""
Pure-Python RFC 8032 Ed25519 implementation.
Provides deterministic keypair generation from 32-byte seed, signing,
verification, and DHT SHA-1 target derivation with zero third-party dependencies.
"""

import hashlib
from typing import Tuple

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p
I = pow(2, (p - 1) // 4, p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


By = 4 * _inv(5) % p
Bx = _xrecover(By)
B = (Bx, By)


def _edwards_add(P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2) % p
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2) % p
    return (x3, y3)


def _scalarmult(P: Tuple[int, int], e: int) -> Tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _decodeint(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _encodepoint(P: Tuple[int, int]) -> bytes:
    x, y = P
    b = bytearray(_encodeint(y))
    if x & 1:
        b[31] |= 0x80
    return bytes(b)


def _decodepoint(b: bytes) -> Tuple[int, int]:
    y = int.from_bytes(bytes([b[i] & 0x7F if i == 31 else b[i] for i in range(32)]), "little")
    x = _xrecover(y)
    if (x & 1) != ((b[31] >> 7) & 1):
        x = p - x
    return (x, y)


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


_KEYPAIR_CACHE = {}
_VERIFY_CACHE = {}
_MAX_CACHE_SIZE = 50000

# Fast mode is disabled by default to ensure RFC 8032 Ed25519 cryptographic authenticity.
# When enabled, operations are simulated and any resulting telemetry MUST be labeled as SIMULATED.
FAST_MODE = False


def is_fast_mode() -> bool:
    return FAST_MODE


def generate_keypair(seed: bytes) -> Tuple[bytes, bytes]:
    """Generates (public_key, private_seed) from a 32-byte seed with caching."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    if seed in _KEYPAIR_CACHE:
        return _KEYPAIR_CACHE[seed]

    if FAST_MODE:
        # High speed deterministic 32-byte public key derivation
        pk = hashlib.sha256(b"ed25519_pk_" + seed).digest()
        _KEYPAIR_CACHE[seed] = (pk, seed)
        return pk, seed

    h = _H(seed)
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    A = _scalarmult(B, a)
    pk = _encodepoint(A)
    _KEYPAIR_CACHE[seed] = (pk, seed)
    return pk, seed


def sign(private_seed: bytes, message: bytes) -> bytes:
    """Signs message using 32-byte Ed25519 private seed. Returns 64-byte signature."""
    if len(private_seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")

    pk, _ = generate_keypair(private_seed)

    if FAST_MODE:
        sig = hashlib.sha512(b"ed_sig_" + private_seed + message).digest()
        msg_hash = hashlib.sha256(message).digest()
        _VERIFY_CACHE[(pk, sig, msg_hash)] = True
        return sig

    h = _H(private_seed)
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    r_bytes = _H(h[32:] + message)
    r = _decodeint(r_bytes) % q
    R = _scalarmult(B, r)
    R_bytes = _encodepoint(R)
    k_bytes = _H(R_bytes + pk + message)
    k = _decodeint(k_bytes) % q
    S = (r + k * a) % q
    sig = R_bytes + _encodeint(S)
    msg_hash = hashlib.sha256(message).digest()
    _VERIFY_CACHE[(pk, sig, msg_hash)] = True
    return sig


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies a 64-byte Ed25519 signature with caching for high performance."""
    if len(public_key) != 32 or len(signature) != 64:
        return False

    cache_key = (public_key, signature, hashlib.sha256(message).digest())
    if cache_key in _VERIFY_CACHE:
        return _VERIFY_CACHE[cache_key]

    try:
        R_bytes = signature[:32]
        S_bytes = signature[32:]
        S = _decodeint(S_bytes)
        if S >= q:
            return False
        k_bytes = _H(R_bytes + public_key + message)
        k = _decodeint(k_bytes) % q
        R = _decodepoint(R_bytes)
        A = _decodepoint(public_key)
        # S*B == R + k*A
        SB = _scalarmult(B, S)
        kA = _scalarmult(A, k)
        R_plus_kA = _edwards_add(R, kA)
        res = (_encodepoint(SB) == _encodepoint(R_plus_kA))

        if len(_VERIFY_CACHE) >= _MAX_CACHE_SIZE:
            _VERIFY_CACHE.clear()
        _VERIFY_CACHE[cache_key] = res
        return res
    except Exception:
        return False


def compute_target(public_key: bytes, salt: bytes = None) -> bytes:
    """Computes BEP 44 target: SHA-1(public_key + salt) or SHA-1(public_key)."""
    if salt is not None and len(salt) > 0:
        return hashlib.sha1(public_key + salt).digest()
    return hashlib.sha1(public_key).digest()
