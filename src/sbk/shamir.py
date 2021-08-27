#!/usr/bin/env python
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Shamir Share generation."""

import math
import typing as typ

from . import gf
from . import params
from . import gf_poly
from . import enc_util
from . import common_types as ct

RawShares = typ.Sequence[ct.RawShare]


def _split_data_gf_p(
    data      : bytes,
    threshold : int,
    num_shares: int,
    prime     : int,
) -> typ.Iterable[ct.RawShare]:
    secret_int = enc_util.bytes2int(data)
    assert secret_int < prime

    field    = gf.init_field(prime)
    gfpoints = gf_poly.split(field, secret_int, threshold, num_shares)  # type: ignore
    for gfpoint in gfpoints:
        _raw_share = enc_util.gfpoint2bytes(gfpoint)
        yield ct.RawShare(_raw_share)


def _join_gf_p(raw_shares: RawShares, threshold: int, prime: int) -> ct.MasterKey:
    field       = gf.init_field(order=prime)
    points      = tuple(enc_util.bytes2gfpoint(share, field) for share in raw_shares)  # type: ignore
    secret_int  = gf_poly.join(field, points, threshold)  # type: ignore
    _master_key = enc_util.int2bytes(secret_int, zfill_bytes=math.ceil(math.log2(prime) / 8))
    return ct.MasterKey(_master_key)


#     i=  0   1   2   3   4   5   6   7
# x=1   y01 y11 y12 y13 y14 y15 y16 y17
# x=2   y02 y21 y22 y23 y24 y25 y26 y27
# x=3   y03 y31 y32 y33 y34 y35 y36 y37
Index   = int
XCoord  = int
YCoords = typ.Dict[typ.Tuple[XCoord, Index], int]


def _split_data_gf_256(data: bytes, threshold: int, num_shares: int) -> typ.Iterable[ct.RawShare]:
    field = gf.FieldGF256()

    y_coords: YCoords = {}
    for i, secret_int in enumerate(data):
        if not 0 <= secret_int <= 255:
            errmsg = f"Value out of gf bounds {secret_int}"
            raise ValueError(errmsg)

        gfpoints = gf_poly.split(field, secret_int, threshold, num_shares)
        for gfpoint in gfpoints:
            y_coords[gfpoint.x.val, i] = gfpoint.y.val

    x_coords = {x_coord for x_coord, _ in y_coords}
    for x_coord in x_coords:
        y_values  = [y_coords[x_coord, i] for i in range(len(data))]
        raw_share = bytes([x_coord]) + bytes(y_values)
        yield ct.RawShare(raw_share)


def _join_gf_256(raw_shares: RawShares, threshold: int) -> ct.MasterKey:
    assert len(raw_shares) >= threshold

    field = gf.FieldGF256()

    y_coords: YCoords = {}
    for raw_share in raw_shares:
        x_coord = raw_share[0]
        for i, y_coord in enumerate(raw_share[1:]):
            y_coords[x_coord, i] = y_coord

    data_len = len(raw_shares[0]) - 1
    x_coords = {x_coord for x_coord, _ in y_coords}
    assert all(0 < x < 64 for x in x_coords)
    assert len(x_coords) >= threshold

    secret_ints: typ.List[int] = []
    for i in range(data_len):
        gfpoints: typ.List[gf_poly.Point] = []
        for x_coord in x_coords:
            y_coord  = y_coords[x_coord, i]
            gf_point = gf_poly.Point(field[x_coord], field[y_coord])
            gfpoints.append(gf_point)
        secret_ints.append(gf_poly.join(field, tuple(gfpoints), threshold=threshold))

    _master_key = bytes(secret_ints)
    return ct.MasterKey(_master_key)


def _split(
    param_cfg: params.ParamConfig,
    raw_salt : ct.RawSalt,
    brainkey : ct.BrainKey,
    use_gf_p : bool = False,
) -> typ.Iterable[ct.Share]:
    if len(raw_salt) != params.RAW_SALT_LEN:
        errmsg = f"{len(raw_salt)} != {params.RAW_SALT_LEN}"
        raise Exception(errmsg)

    shares_input = raw_salt + brainkey

    if len(shares_input) != params.MASTER_KEY_LEN:
        errmsg = f"{len(shares_input)} != {params.MASTER_KEY_LEN}"
        raise Exception(errmsg)

    param_cfg_data = params.param_cfg2bytes(param_cfg)
    threshold      = param_cfg.threshold
    num_shares     = param_cfg.num_shares

    if use_gf_p:
        key_bits   = parameters.master_key_len(param_cfg) * 8
        gf_prime   = primes.get_pow2prime(key_bits)
        raw_shares = _split_data_gf_p(shares_input, threshold, num_shares, gf_prime)
    else:
        raw_shares = _split_data_gf_256(shares_input, threshold, num_shares)

    for raw_share in raw_shares:
        share_data = param_cfg_data + raw_share

        if len(raw_share) != params.MASTER_KEY_LEN + 1:
            errmsg = f"{len(raw_share)} != {params.MASTER_KEY_LEN + 1}"
            raise ValueError(errmsg)
        elif len(share_data) != params.SHARE_LEN:
            errmsg = f"{len(share_data)} != {params.SHARE_LEN}"
            raise ValueError(errmsg)
        else:
            yield ct.Share(share_data)


def split(
    param_cfg: params.ParamConfig,
    raw_salt : ct.RawSalt,
    brainkey : ct.BrainKey,
    use_gf_p : bool = False,
) -> typ.Sequence[ct.Share]:
    return list(_split(param_cfg, raw_salt, brainkey, use_gf_p))


def join(
    param_cfg: params.ParamConfig,
    shares   : ct.Shares,
    use_gf_p : bool = False,
) -> typ.Tuple[ct.RawSalt, ct.BrainKey]:
    # strip off params
    raw_shares : RawShares = [ct.RawShare(share[params.PARAM_CFG_LEN :]) for share in shares]
    if use_gf_p:
        master_key = _join_gf_p(raw_shares, param_cfg.threshold, param_cfg.prime)
    else:
        master_key = _join_gf_256(raw_shares, param_cfg.threshold)
    key_len = parameters.master_key_len(param_cfg)
    if len(master_key) != key_len:
        errmsg = f"Invaid master_key_len={len(master_key)} (expected {key_len})"
        raise ValueError(errmsg)

    salt_end = params.RAW_SALT_LEN
    bk_start = params.RAW_SALT_LEN

    raw_salt = ct.RawSalt(bytes(master_key)[:salt_end])
    brainkey = ct.BrainKey(bytes(master_key)[bk_start:])

    if len(raw_salt) != params.RAW_SALT_LEN:
        errmsg = f"Invalid raw_salt {len(raw_salt)}"
        raise ValueError(errmsg)
    elif len(brainkey) != params.BRAINKEY_LEN:
        errmsg = f"Invalid brainkey {len(brainkey)}"
        raise ValueError(errmsg)
    else:
        return (raw_salt, brainkey)
