# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""KDF parameter encoding and key derivation."""

import math
import time
import typing as typ
import importlib
import threading

NumThreads = int
MebiBytes  = int
Iterations = int
Seconds    = int

# types for progress bar
Increment             = float
ProgressCallback      = typ.Callable[[Increment], None]
MaybeProgressCallback = typ.Optional[ProgressCallback]
DEFAULT_PARALLELISM   = 128

# NOTE (mb 2021-05-29): Since we feed the hash output back into the
#   following iteration (to implement the progress bar), the HASH_LEN
#   is chosen to be much larger than the original input, hopefully
#   this makes loss of entropy between iterations negligable.
#   Feedback welcome.
HASH_LEN = 128

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
# Solve for s
#
#       s + 1 = s * b
#           1 = s * b - s             # - s
#           1 = s * (b - 1)           # factor out s
# 1 / (b - 1) = s                     # / (b - 1)
#
# if we chose b = 2     , then s =  1 and o = 0
# if we chose b = 1.5   , then s =  2 and o = -1
# if we chose b = 1.25  , then s =  4 and o = -3
# if we chose b = 1.125 , then s =  8 and o = -7
# if we chose b = 1.0625, then s = 16 and o = -15


def curve_params(base: float) -> typ.Tuple[float, float]:
    s = 1 / (base - 1)
    o = 1 - s
    return (s, o)


M_BASE = 1.125
T_BASE = 1.125

MIN_M = 100
MIN_T = 1

FieldVal = int


def log(raw_val: int, base: float) -> FieldVal:
    s, o = curve_params(base)
    return math.floor(math.log((raw_val - o) / s) / math.log(base))


def exp(field_val: FieldVal, base: float) -> int:
    s, o = curve_params(base)
    return math.ceil(o + s * base ** field_val)


def _clamp(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, val))


class KDFParams(typ.NamedTuple):

    p_raw: NumThreads
    m_raw: MebiBytes
    t_raw: Iterations

    @property
    def _field_values(self) -> typ.Tuple[int, int]:
        f_m = _clamp(val=log(self.m_raw // MIN_M, base=M_BASE), lo=0, hi=2 ** 6 - 1)
        f_t = _clamp(val=log(self.t_raw // MIN_T, base=T_BASE), lo=0, hi=2 ** 6 - 1)

        assert 0 <= f_m < 2 ** 6, f"f_m={f_m}"
        assert 0 <= f_t < 2 ** 6, f"f_t={f_t}"

        return (f_m, f_t)

    def encode(self) -> int:
        """Convert raw values to serializable representation.

        The resulting integer can be encoded as a 12bit unsigned integer.
        """
        f_m, f_t = self._field_values
        fields = 0
        fields |= f_m << 6
        fields |= f_t << 0
        assert 0 <= fields < 2 ** 12
        return fields

    @staticmethod
    def decode(fields: int) -> 'KDFParams':
        if 0 <= fields < 2 ** 12:
            f_m = fields >> 6 & 0x3F
            f_t = fields >> 0 & 0x3F

            m = exp(f_m, base=M_BASE) * MIN_M
            t = exp(f_t, base=T_BASE) * MIN_T
            return KDFParams(DEFAULT_PARALLELISM, m, t)
        else:
            errmsg = f"Invalid fields, out of bounds: {fields}"
            raise AssertionError(errmsg)

    def _verify_encoding(self) -> None:
        """Validator for serialization.

        Helper to make sure  we always use KDFParams with values
        that can be serialized correctly. This should not be
        needed if we always use init_kdf_params.
        """
        other = KDFParams.decode(self.encode())
        if self != other:
            errmsg = f"{self} != {other}"
            raise AssertionError(errmsg)

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

    def _replace_any(
        self,
        m: typ.Optional[int] = None,
        t: typ.Optional[int] = None,
    ) -> 'KDFParams':
        updated = self

        if m:
            updated = updated._replace(m_raw=m)
        if t:
            updated = updated._replace(t_raw=t)

        return init_kdf_params(m=updated.m_raw, t=updated.t_raw)

    def __repr__(self) -> str:
        return f"KDFParams(p={self.p_raw}, m={self.m_raw}, t={self.t_raw})"


def init_kdf_params(m: MebiBytes, t: Iterations) -> KDFParams:
    # NOTE mb: It's important to ALWAYS and ONLY use kdf parameters that have gone through
    #   this function so we always do the kdf parameter normalization.
    #
    # Only certain parameter values can be serialized. Everything goes through this
    # constructor to make sure we only use valid values.
    tmp = KDFParams(DEFAULT_PARALLELISM, m, t)
    return KDFParams.decode(tmp.encode())


def _hash_pyargon2(
    data: bytes,
    p   : NumThreads,
    m   : MebiBytes,
    t   : Iterations,
) -> bytes:
    # NOTE: only used for testing/validation
    pyargon2 = importlib.import_module('pyargon2')

    result = pyargon2.hash(  # type: ignore
        password=data,
        salt=data,
        encoding='raw',
        hash_len=HASH_LEN,
        parallelism=p,
        memory_cost=m * 1024,
        time_cost=t,
        variant='id',
        version=19,
    )
    assert isinstance(result, bytes)
    return result


def _hash_argon2_cffi(
    data: bytes,
    p   : NumThreads,
    m   : MebiBytes,
    t   : Iterations,
) -> bytes:
    import argon2

    version = argon2.low_level.ARGON2_VERSION
    assert version == 19, version

    result = argon2.low_level.hash_secret_raw(
        secret=data,
        salt=data,
        hash_len=HASH_LEN,
        parallelism=p,
        memory_cost=m * 1024,
        time_cost=t,
        type=argon2.low_level.Type.ID,
        version=version,
    )
    assert isinstance(result, bytes)
    return result


_hash = _hash_argon2_cffi


class ProgressSmoother:

    increments: typ.List[float]

    def __init__(self, progress_cb: ProgressCallback) -> None:
        self.increments = [0]

        def fake_progress() -> None:
            step_duration = 0.1
            tzero         = time.time()
            while True:
                time.sleep(step_duration)
                if self.total_incr() == 0:
                    progress_cb(0.01)
                elif self.total_incr() >= 100:
                    progress_cb(100)
                    return
                else:
                    duration      = time.time() - tzero
                    steps         = duration / step_duration
                    incr_per_step = self.total_incr() / steps
                    progress_cb(incr_per_step)

        self._thread = threading.Thread(target=fake_progress)
        self._thread.start()

    def total_incr(self) -> float:
        return sum(self.increments) + max(self.increments) * 0.55

    def progress_cb(self, incr: ProgressIncrement) -> None:
        self.increments.append(incr)

    def join(self) -> None:
        self._thread.join()


DIGEST_STEPS = 10


def digest(
    data       : bytes,
    kdf_params : KDFParams,
    hash_len   : int,
    progress_cb: MaybeProgressCallback = None,
) -> bytes:
    _ps           : typ.Optional[ProgressSmoother]
    if progress_cb:
        _ps = ProgressSmoother(progress_cb)
    else:
        _ps = None

    remaining_iters   = kdf_params.t
    remaining_steps   = min(remaining_iters, DIGEST_STEPS)
    progress_per_iter = 100 / kdf_params.t

    constant_kwargs = {
        'p': kdf_params.p,
        'm': kdf_params.m,
    }
    result = data

    while remaining_iters > 0:
        step_iters = max(1, round(remaining_iters / remaining_steps))
        result     = _hash(result, t=step_iters, **constant_kwargs)

        if _ps:
            _ps.progress_cb(step_iters * progress_per_iter)

        remaining_iters -= step_iters
        remaining_steps -= 1

    assert remaining_iters == 0, remaining_iters
    assert remaining_steps == 0, remaining_steps

    if _ps:
        _ps.join()

    return result[:hash_len]


MEASUREMENT_SIGNIFICANCE_THRESHOLD = 2


def kdf_params_for_duration(
    baseline_kdf_params : KDFParams,
    target_duration     : Seconds,
    max_measurement_time: Seconds = 5,
) -> KDFParams:
    test_kdf_params = baseline_kdf_params._replace_any(t=1)
    constant_kwargs = {
        # we only vary t, the baseline should be chosen to max out the others
        'p': test_kdf_params.p,
        'm': test_kdf_params.m,
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

        # t = test_kdf_params.t
        # print(f"< {duration:4.3f} t: {t} i/s: {iters_per_sec} tgt: {step_iters}")
        is_tgt_exceeded            = duration   > tgt_step_duration
        is_measurement_significant = duration   > MEASUREMENT_SIGNIFICANCE_THRESHOLD
        is_enough_already          = total_time > max_measurement_time
        if is_tgt_exceeded or is_measurement_significant or is_enough_already:
            new_t = round(step_iters * DIGEST_STEPS)
            return test_kdf_params._replace_any(t=new_t)
        else:
            # min_iters is used to make sure we're always measuring with a higher value for t
            min_iters       = math.ceil(test_kdf_params.t * 1.25)
            min_t           = round(1.25 * MEASUREMENT_SIGNIFICANCE_THRESHOLD * iters_per_sec)
            new_t           = max(min_iters, min_t)
            test_kdf_params = test_kdf_params._replace_any(t=new_t)


def debug_params() -> None:
    max_m = exp(2 ** 6 - 1, base=M_BASE) * MIN_M
    max_t = exp(2 ** 6 - 1, base=T_BASE) * MIN_T
    print(f"       {max_p=:>12}     {max_m=:>12}     {max_t=:>12}")

    for i in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 30, 31, 32, 62, 63, 64]:
        p = exp(i, base=P_BASE) * MIN_P
        m = exp(i, base=M_BASE) * MIN_M
        t = exp(i, base=T_BASE) * MIN_T
        p = min(p, max_p)

        kdf_params = init_kdf_params(p=p, m=m, t=t)

        print(f"{i:>2}"                     , end=" ")
        print(f"p: {kdf_params.p:>9} {p:>9}", end=" ")
        print(f"m: {kdf_params.m:>9} {m:>9}", end=" ")
        print(f"t: {kdf_params.t:>9} {t:>9}")


if __name__ == '__main__':
    debug_params()
