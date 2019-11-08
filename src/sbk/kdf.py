# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF derivation."""
import enum
import math
import typing as typ

import argon2


class HashAlgo(enum.Enum):

    ARGON2_V19_D  = 0
    ARGON2_V19_I  = 1
    ARGON2_V19_ID = 2


HashAlgoVal = int

HASH_ALGO_NAMES = {
    HashAlgo.ARGON2_V19_I : 'argon2_v19_i',
    HashAlgo.ARGON2_V19_D : 'argon2_v19_d',
    HashAlgo.ARGON2_V19_ID: 'argon2_v19_id',
}


NumThreads = int
MebiBytes  = int
Iterations = int


class KDFParams(typ.NamedTuple):

    p_raw: NumThreads
    m_raw: MebiBytes
    t_raw: Iterations
    h    : HashAlgoVal

    @property
    def _field_values(self,) -> typ.Tuple[int, int, int]:
        f_p = max(0, min(2 ** 4 - 1, round(math.log(self.p_raw) / math.log(2  ))))
        f_m = max(0, min(2 ** 6 - 1, round(math.log(self.m_raw) / math.log(1.5))))
        f_t = max(0, min(2 ** 6 - 1, round(math.log(self.t_raw) / math.log(1.5))))

        assert 0 <= f_p < 2 ** 4
        assert 0 <= f_m < 2 ** 6
        assert 0 <= f_t < 2 ** 6

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

        p = round(2   ** f_p)
        m = round(1.5 ** f_m)
        t = round(1.5 ** f_t)
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


def parse_argon2_version(h: HashAlgoVal) -> int:
    return 19


def parse_argon2_type(h: HashAlgoVal) -> int:
    if h == HashAlgo.ARGON2_V19_D.value:
        return argon2.low_level.Type.D
    if h == HashAlgo.ARGON2_V19_I.value:
        return argon2.low_level.Type.I
    if h == HashAlgo.ARGON2_V19_ID.value:
        return argon2.low_level.Type.ID

    err_msg = f"Unknown hash_algo={h}"
    raise ValueError(err_msg)


def derive_key(secret_data: bytes, salt_data: bytes, kdf_params: KDFParams, hash_len: int) -> bytes:
    return argon2.low_level.hash_secret_raw(
        secret=secret_data,
        salt=salt_data,
        hash_len=hash_len,
        type=parse_argon2_type(kdf_params.h),
        memory_cost=kdf_params.m * 1024,
        time_cost=kdf_params.t,
        parallelism=kdf_params.p,
        version=parse_argon2_version(kdf_params.h),
    )
