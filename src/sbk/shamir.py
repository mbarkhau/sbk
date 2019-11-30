#!/usr/bin/env python
# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Shamir Share generation."""

import math
import typing as typ

from . import gf
from . import params
from . import gf_poly
from . import enc_util

RawSalt   = bytes
BrainKey  = bytes
MasterKey = bytes

RawShare = bytes  # only the encoded GFPoint
Share    = bytes  # RawShare but prefixed with ParamConfig data


def _split_data_gf_p(
    data: bytes, threshold: int, num_shares: int, prime: int,
) -> typ.Iterable[RawShare]:
    secret_int = enc_util.bytes2int(data)
    assert secret_int < prime

    field    = gf.GFNum.field(prime)
    gfpoints = gf_poly.split(field, secret_int, threshold, num_shares)
    for gfpoint in gfpoints:
        yield enc_util.gfpoint2bytes(gfpoint)


def _join_gf_p(raw_shares: typ.List[RawShare], threshold: int, prime: int) -> MasterKey:
    field      = gf.GFNum.field(order=prime)
    points     = tuple(enc_util.bytes2gfpoint(share, field) for share in raw_shares)
    secret_int = gf_poly.join(field, points, threshold)
    return enc_util.int2bytes(secret_int, zfill_bytes=math.ceil(math.log2(prime) / 8))


#     i=  0   1   2   3   4   5   6   7
# x=1   y01 y11 y12 y13 y14 y15 y16 y17
# x=2   y02 y21 y22 y23 y24 y25 y26 y27
# x=3   y03 y31 y32 y33 y34 y35 y36 y37
Index   = int
XCoord  = int
YCoords = typ.Dict[typ.Tuple[XCoord, Index], int]


def _split_data_gf_256(data: bytes, threshold: int, num_shares: int) -> typ.Iterable[RawShare]:
    field = gf.Field[gf.GF256](256, gf.GF256)

    y_coords: YCoords = {}
    for i, secret_int in enumerate(data):
        assert 0 <= secret_int <= 255, secret_int
        gfpoints = gf_poly.split(field, secret_int, threshold, num_shares)
        for gfpoint in gfpoints:
            y_coords[gfpoint.x.val, i] = gfpoint.y.val

    x_coords = {x_coord for x_coord, _ in y_coords.keys()}
    for x_coord in x_coords:
        y_values  = [y_coords[x_coord, i] for i in range(len(data))]
        raw_share = bytes([x_coord]) + bytes(y_values)
        yield raw_share


def _join_gf_256(raw_shares: typ.List[RawShare], threshold: int) -> MasterKey:
    assert len(raw_shares) >= threshold

    field = gf.Field[gf.GF256](256, gf.GF256)

    y_coords: YCoords = {}
    for raw_share in raw_shares:
        x_coord = raw_share[0]
        for i, y_coord in enumerate(raw_share[1:]):
            y_coords[x_coord, i] = y_coord

    data_len = len(raw_shares[0]) - 1
    x_coords = {x_coord for x_coord, _ in y_coords.keys()}
    assert all(0 < x < 64 for x in x_coords)
    assert len(x_coords) >= threshold

    secret_ints: typ.List[int] = []
    for i in range(data_len):
        gfpoints: typ.List[gf_poly.Point[gf.GF256]] = []
        for x_coord in x_coords:
            y_coord  = y_coords[x_coord, i]
            gf_point = gf_poly.Point(field[x_coord], field[y_coord])
            gfpoints.append(gf_point)
        secret_ints.append(gf_poly.join(field, tuple(gfpoints), threshold=threshold))

    return bytes(secret_ints)


def split(
    param_cfg: params.ParamConfig, raw_salt: RawSalt, brainkey: BrainKey, use_gf_p: bool = False,
) -> typ.Iterable[Share]:
    errmsg = f"{len(raw_salt)} != {params.RAW_SALT_LEN}"
    assert len(raw_salt) == params.RAW_SALT_LEN, errmsg

    shares_input = raw_salt + brainkey
    errmsg       = f"{len(shares_input)} != {param_cfg.master_key_len}"
    assert len(shares_input) == param_cfg.master_key_len, errmsg

    param_cfg_data = params.param_cfg2bytes(param_cfg)
    threshold      = param_cfg.threshold
    num_shares     = param_cfg.num_shares

    if use_gf_p:
        raw_shares = _split_data_gf_p(shares_input, threshold, num_shares, param_cfg.prime)
    else:
        raw_shares = _split_data_gf_256(shares_input, threshold, num_shares)

    for raw_share in raw_shares:
        share_data = param_cfg_data + raw_share

        errmsg = f"{len(raw_share)} != {param_cfg.master_key_len + 1}"
        assert len(raw_share) == param_cfg.master_key_len + 1, errmsg
        errmsg = f"{len(share_data)} != {param_cfg.share_len}"
        assert len(share_data) == param_cfg.share_len, errmsg

        yield share_data


def join(
    param_cfg: params.ParamConfig, shares: typ.List[Share], use_gf_p: bool = False
) -> typ.Tuple[RawSalt, BrainKey]:
    raw_shares = [share[params.PARAM_CFG_LEN :] for share in shares]
    if use_gf_p:
        master_key = _join_gf_p(raw_shares, param_cfg.threshold, param_cfg.prime)
    else:
        master_key = _join_gf_256(raw_shares, param_cfg.threshold)

    assert len(master_key) == param_cfg.master_key_len

    salt_end = param_cfg.raw_salt_len
    bk_start = param_cfg.raw_salt_len

    raw_salt = master_key[:salt_end]
    brainkey = master_key[bk_start:]

    assert len(raw_salt) == param_cfg.raw_salt_len
    assert len(brainkey) == param_cfg.brainkey_len
    return (raw_salt, brainkey)
