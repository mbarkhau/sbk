# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""KDF parameter encoding and key derivation."""

import enum
import math
import time
import typing as typ
import threading

import argon2


class HashAlgo(enum.Enum):

    ARGON2_V19_D  = 0
    ARGON2_V19_I  = 1
    ARGON2_V19_ID = 2


HASH_ALGO_NAMES = {
    HashAlgo.ARGON2_V19_I : 'argon2_v19_i',
    HashAlgo.ARGON2_V19_D : 'argon2_v19_d',
    HashAlgo.ARGON2_V19_ID: 'argon2_v19_id',
}


NumThreads = int
MebiBytes  = int
Iterations = int
HashAlgoVal = int
Seconds = float

# types for progress bar
Increment = float
ProgressCallback = typ.Callable[[Increment], None]
MaybeProgressCallback = typ.Optional[ProgressCallback]


# We are looking for an equation of the form
#
#   f(n) = ⌊o + s * b ** n⌋
#
# such that f(0) = 1 and f(1) = 2 for any given b
#
# n: [0..63]  (int)
# b: base   (chosen)
# s: scale  (unknown)
# o: offset (1 - s)
#
# Knowing that we can chose o = (1 - s), so that
# f(0) = 1. We can work with g(n) = s * b ** n,
# where for n = 0 it must hold that
#
#   g(0) + 1 = g(1)         # lem 1
#
# Given that
#
#  g(0) = s * b ** 0
#  g(0) = s * 1
#  g(0) = s                 # lem 2
#
#  g(1) = s * b ** 1
#  g(1) = s * b
#
#  g(0) + 1 = s + 1         # +1 to lem 2
#  s + 1 = s * b            # substitute g(1) given lem 1
#
# try to isolate s
#
#       s + 1 = s * b
#           1 = s * b - s             # - s
#           1 = s * (b - 1)           # factor out s
# 1 / (b - 1) = s                     # / (b - 1)
#
# if we chose b = 2   , then s = 1 and o = 0
# if we chose b = 1.25, then s = 4 and o = -3


def _exp(field_val: int, base: float) -> int:
    s = 1 / (base - 1)
    o = 1 - s
    return math.floor(o + s * base ** field_val)


def _log(raw_val: int, base: float) -> int:
    s = 1 / (base - 1)
    o = 1 - s
    return round(math.log((raw_val - o) / s) / math.log(base))


def _clamp(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, val))


class KDFParams(typ.NamedTuple):

    p_raw: NumThreads
    m_raw: MebiBytes
    t_raw: Iterations
    h    : HashAlgoVal

    @property
    def _field_values(self,) -> typ.Tuple[int, int, int]:
        f_p = _clamp(val=_log(self.p_raw, base=2   ), lo=0, hi=2 ** 4 - 1)
        f_m = _clamp(val=_log(self.m_raw, base=1.25), lo=0, hi=2 ** 6 - 1)
        f_t = _clamp(val=_log(self.t_raw, base=1.25), lo=0, hi=2 ** 6 - 1)

        assert 0 <= f_p < 2 ** 4, f"f_p={f_p}"
        assert 0 <= f_m < 2 ** 6, f"f_m={f_m}"
        assert 0 <= f_t < 2 ** 6, f"f_t={f_t}"

        return (f_p, f_m, f_t)

    def encode(self) -> int:
        """Convert raw values to serializable representation.

        The resulting integer can be encoded as a 16bit unsigned integer.
        """
        f_p, f_m, f_t = self._field_values
        fields = 0
        fields |= f_p << 12
        fields |= f_m << 6
        fields |= f_t << 0

        assert 0 <= fields < 2 ** 16
        return fields

    @staticmethod
    def decode(fields: int) -> 'KDFParams':
        assert 0 <= fields < 2 ** 16
        f_p = (fields >> 12) & 0xF
        f_m = (fields >>  6) & 0x3F
        f_t = (fields >>  0) & 0x3F

        p = _exp(f_p, base=2)
        m = _exp(f_m, base=1.25)
        t = _exp(f_t, base=1.25)
        h = HashAlgo.ARGON2_V19_ID.value
        return KDFParams(p, m, t, h)

    def _verify_encoding(self) -> None:
        """Validator for serialization.

        Helper to make sure  we always use KDFParams with values
        that can be serialized correctly. This should not be
        needed if we always use init_kdf_params.
        """
        other  = KDFParams.decode(self.encode())
        errmsg = f"{self} != {other}"
        assert self == other, errmsg

    @property
    def p(self) -> NumThreads:
        self._verify_encoding()
        return self.p_raw

    @property
    def m(self) -> NumThreads:
        self._verify_encoding()
        return self.m_raw

    @property
    def t(self) -> NumThreads:
        self._verify_encoding()
        return self.t_raw

    @property
    def argon2_type(self) -> int:
        if self.h == HashAlgo.ARGON2_V19_D.value:
            return argon2.low_level.Type.D
        if self.h == HashAlgo.ARGON2_V19_I.value:
            return argon2.low_level.Type.I
        if self.h == HashAlgo.ARGON2_V19_ID.value:
            return argon2.low_level.Type.ID

        err_msg = f"Unknown hash_algo={self.h}"
        raise ValueError(err_msg)

    def _replace_any(
        self, p: typ.Optional[int] = None, m: typ.Optional[int] = None, t: typ.Optional[int] = None
    ) -> 'KDFParams':
        updated = self

        if p:
            updated = updated._replace(p_raw=p)
        if m:
            updated = updated._replace(m_raw=m)
        if t:
            updated = updated._replace(t_raw=t)

        return init_kdf_params(p=updated.p_raw, m=updated.m_raw, t=updated.t_raw)

    def __repr__(self) -> str:
        return f"KDFParams(p={self.p_raw}, m={self.m_raw}, t={self.t_raw})"


def init_kdf_params(p: NumThreads, m: MebiBytes, t: Iterations) -> KDFParams:
    # NOTE mb: It's important to ALWAYS and ONLY use kdf parameters that have gone through
    #   this function so we always do the kdf parameter normalization.
    #
    # Only certain parameter values can be serialized. Everything goes through this
    # constructor to make sure we only use valid values.
    h   = HashAlgo.ARGON2_V19_ID.value
    tmp = KDFParams(p, m, t, h)
    return KDFParams.decode(tmp.encode())


def _hash(data: bytes, p: int, m: int, t: int, h: int = HashAlgo.ARGON2_V19_ID.value) -> bytes:
    version = argon2.low_level.ARGON2_VERSION
    assert version == 19, version

    return argon2.low_level.hash_secret_raw(
        secret=data,
        salt=data,
        hash_len=1024,
        parallelism=p,
        memory_cost=m * 1024,
        time_cost=t,
        type=h,
        version=version,
    )

DIGEST_STEPS = 10


class ProgressSmoother:

    increments: typ.List[float]

    def __init__(self, progress_cb: ProgressCallback) -> None:
        self.increments = [0]

        def fake_progress() -> None:
            tzero = time.time()
            while True:
                time.sleep(1)
                if self.total_incr == 0:
                    progress_cb(0.1)
                elif self.total_incr >= 100:
                    progress_cb(100)
                    return
                else:
                    duration     = time.time() - tzero
                    incr_per_sec = self.total_incr / duration
                    progress_cb(incr_per_sec * 1)

        self._thread = threading.Thread(target=fake_progress)
        self._thread.start()

    @property
    def total_incr(self):
        return sum(self.increments) + max(self.increments) * 0.55

    def progress_cb(self, incr: Increment) -> None:
        self.increments.append(incr)

    def join(self) -> None:
        self._thread.join()


def _dummy_cb(incr: Increment) -> None:
    pass


def digest(
    data       : bytes,
    kdf_params : KDFParams,
    hash_len   : int,
    progress_cb: MaybeProgressCallback = None,
) -> bytes:
    _ps = ProgressSmoother(progress_cb or _dummy_cb)

    remaining_iters   = kdf_params.t
    remaining_steps   = min(remaining_iters, DIGEST_STEPS)
    progress_per_iter = 100 / kdf_params.t

    constant_kwargs = {
        'p': kdf_params.p,
        'm': kdf_params.m,
        'h': kdf_params.argon2_type,
    }
    result = data

    while remaining_iters > 0:
        step_iters = max(1, round(remaining_iters / remaining_steps))
        result     = _hash(result, t=step_iters, **constant_kwargs)
        _ps.progress_cb(step_iters * progress_per_iter)
        remaining_iters -= step_iters
        remaining_steps -= 1

    assert remaining_iters == 0, remaining_iters
    assert remaining_steps == 0, remaining_steps
    _ps.join()

    return result[:hash_len]


MEASUREMENT_SIGNIFICANCE_THRESHOLD = 2


def kdf_params_for_duration(baseline_kdf_params: KDFParams, target_duration: Seconds) -> KDFParams:
    test_kdf_params = baseline_kdf_params._replace_any(t=1)
    constant_kwargs = {
        'p': test_kdf_params.p,
        'm': test_kdf_params.m,
        'h': test_kdf_params.argon2_type,
    }

    tgt_step_duration = target_duration / DIGEST_STEPS
    total_time        = 0.0

    while True:
        tzero = time.time()
        _hash(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00", t=test_kdf_params.t, **constant_kwargs)
        duration = time.time() - tzero
        total_time += duration

        iters_per_sec = test_kdf_params.t / duration
        step_iters    = tgt_step_duration * iters_per_sec * 1.25

        # print("<", round(duration, 3), "i/s =", iters_per_sec, "tgt =", step_iters)
        is_tgt_exceeded            = duration   > tgt_step_duration
        is_measurement_significant = duration   > MEASUREMENT_SIGNIFICANCE_THRESHOLD
        is_enough_already          = total_time > 5
        if is_tgt_exceeded or is_measurement_significant or is_enough_already:
            return test_kdf_params._replace_any(t=round(step_iters * DIGEST_STEPS))

        # min_iters is used to make sure we're always measuring with a higher value for t
        min_iters       = math.ceil(test_kdf_params.t * 1.25)
        new_t           = max(min_iters, round(1.25 * MEASUREMENT_SIGNIFICANCE_THRESHOLD * iters_per_sec))
        test_kdf_params = test_kdf_params._replace_any(t=new_t)
