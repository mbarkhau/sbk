#!/usr/bin/env python
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Shamir Share generation."""

import math
from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Tuple
from typing import Callable
from typing import Iterator
from typing import Sequence

from . import gf
from . import primes
from . import gf_poly
from . import enc_util
from . import parameters
from . import sbk_random
from . import common_types as ct

RawShares = Sequence[ct.RawShare]


def _gfpoint2bytes(point: gf_poly.Point) -> bytes:
    num_bits  = math.ceil(math.log2(point.y.order))
    num_bytes = num_bits // 8
    y_data    = enc_util.int2bytes(point.y.val, num_bytes)
    assert len(y_data) == num_bytes
    return y_data


def _split_data_gf_p(
    data      : bytes,
    threshold : int,
    num_shares: int,
    prime     : int,
    make_coeff: Callable[[int], int],
) -> Iterator[ct.RawShare]:
    secret_int = enc_util.bytes2int(data)
    assert secret_int < prime

    field    = gf.init_field(prime)
    gfpoints = gf_poly.split(field, secret_int, threshold, num_shares, make_coeff)  # type: ignore
    for gfpoint in gfpoints:
        # NOTE: for x=0 or x=255 the y value may be the secret, which should not be serialized.
        x = gfpoint.x.val
        if not (0 < x < 32):
            errmsg = f"Invalid point with x={x}. Was not (0 < x < 32)"
            raise ValueError(errmsg)

        _raw_share = _gfpoint2bytes(gfpoint)
        yield ct.RawShare(gfpoint.x.val, _raw_share)


def _bytes2gfpoint(raw_share: ct.RawShare, field: gf.FieldGF256) -> gf_poly.Point:
    y = enc_util.bytes2int(raw_share.data)
    if y < field.order:
        return gf_poly.Point(field[raw_share.x_coord], field[y])
    else:
        raise ValueError(f"Invalid data for field with order={field.order}. Too large y={y}")


def _join_gf_p(raw_shares: RawShares, threshold: int, prime: int) -> ct.MasterKey:
    field       = gf.init_field(order=prime)
    points      = tuple(_bytes2gfpoint(raw_share, field) for raw_share in raw_shares)  # type: ignore
    secret_int  = gf_poly.join(field, points, threshold)  # type: ignore
    _master_key = enc_util.int2bytes(secret_int, zfill_bytes=math.ceil(math.log2(prime) / 8))
    return ct.MasterKey(_master_key)


#     i=  0   1   2   3   4   5   6   7
# x=1   y01 y11 y12 y13 y14 y15 y16 y17
# x=2   y02 y21 y22 y23 y24 y25 y26 y27
# x=3   y03 y31 y32 y33 y34 y35 y36 y37
Index   = int
XCoord  = int
YCoords = Dict[Tuple[XCoord, Index], int]


def _split_data_gf_256(
    data      : bytes,
    threshold : int,
    num_shares: int,
    make_coeff: Callable[[int], int],
) -> Iterator[ct.RawShare]:
    field = gf.FieldGF256()

    y_coords_by_x: YCoords = {}
    for i, secret_int in enumerate(data):
        if not 0 <= secret_int <= 255:
            errmsg = f"Value out of gf bounds {secret_int}"
            raise ValueError(errmsg)

        gfpoints = gf_poly.split(field, secret_int, threshold, num_shares, make_coeff)
        for gfpoint in gfpoints:
            y_coords_by_x[gfpoint.x.val, i] = gfpoint.y.val

    x_coords = {x_coord for x_coord, _ in y_coords_by_x}
    for x_coord in x_coords:
        y_values = [y_coords_by_x[x_coord, i] for i in range(len(data))]
        yield ct.RawShare(x_coord, bytes(y_values))


def _join_gf_256(raw_shares: RawShares, threshold: int) -> ct.MasterKey:
    assert len(raw_shares) >= threshold

    field = gf.FieldGF256()

    y_coords: YCoords = {}
    for raw_share in raw_shares:
        for i, y_coord in enumerate(raw_share.data):
            y_coords[raw_share.x_coord, i] = y_coord

    data_len = len(raw_shares[0].data)
    x_coords = {x_coord for x_coord, _ in y_coords}
    assert all(0 < x < 64 for x in x_coords)
    assert len(x_coords) >= threshold

    secret_ints: List[int] = []
    for i in range(data_len):
        gfpoints: List[gf_poly.Point] = []
        for x_coord in x_coords:
            y_coord  = y_coords[x_coord, i]
            gf_point = gf_poly.Point(field[x_coord], field[y_coord])
            gfpoints.append(gf_point)
        secret_ints.append(gf_poly.join(field, tuple(gfpoints), threshold=threshold))

    _master_key = bytes(secret_ints)
    return ct.MasterKey(_master_key)


def split(
    params    : parameters.Parameters,
    raw_bk    : ct.RawBrainKey,
    salt      : ct.Salt,
    make_coeff: Callable[[int], int] = sbk_random.randrange,
    use_gf_p  : bool = False,
) -> List[ct.Share]:
    lens = parameters.raw_secret_lens()

    assert len(raw_bk) == lens.raw_brainkey
    assert len(salt  ) == lens.salt

    master_key = raw_bk + salt

    assert len(master_key) == lens.master_key

    if use_gf_p:
        gf_prime   = primes.get_pow2prime(lens.master_key * 8)
        raw_shares = list(_split_data_gf_p(master_key, params.sss_t, params.sss_n, gf_prime, make_coeff))
    else:
        raw_shares = list(_split_data_gf_256(master_key, params.sss_t, params.sss_n, make_coeff))

    shares: List[ct.Share] = []
    for raw_share in raw_shares:
        assert len(raw_share.data) == lens.raw_share
        share_params = params._replace(sss_x=raw_share.x_coord)
        params_data  = parameters.params2bytes(share_params)
        assert len(params_data) == parameters.SHARE_HEADER_LEN
        shares.append(params_data + raw_share.data)

    return shares


def join(shares: List[ct.Shares], use_gf_p: bool = False) -> Tuple[ct.RawSalt, ct.BrainKey]:
    raw_shares      : List[ct.RawShare          ] = []
    all_share_params: List[parameters.Parameters] = []
    for share in shares:
        # strip off params
        share_data   = share[parameters.SHARE_HEADER_LEN :]
        params_data  = share[: parameters.SHARE_HEADER_LEN]
        share_params = parameters.bytes2params(params_data)

        raw_shares.append(ct.RawShare(share_params.sss_x, share_data))
        all_share_params.append(share_params)

    unique_params = {
        (params.version, params.kdf_p, params.kdf_m, params.kdf_t, params.sss_t)
        for params in all_share_params
    }
    if len(unique_params) > 1:
        errmsg = f"Invalid shares using different parameters {unique_params}"
        raise ValueError(errmsg)

    unique_coords = {share_params.sss_x for share_params in all_share_params}
    params        = all_share_params[0]
    if len(unique_coords) < params.sss_t:
        errmsg = f"Insufficient shares {len(unique_coords)} < {params.sss_t}"
        raise ValueError(errmsg)

    lens = parameters.raw_secret_lens()

    if use_gf_p:
        gf_prime   = primes.get_pow2prime(lens.master_key * 8)
        master_key = _join_gf_p(raw_shares, params.sss_t, gf_prime)
    else:
        master_key = _join_gf_256(raw_shares, params.sss_t)

    bk_params = shares[0][: parameters.BRANKEY_HEADER_LEN]

    assert len(master_key) == lens.master_key
    raw_bk = master_key[: lens.raw_brainkey]
    salt   = master_key[lens.raw_brainkey :]

    return (ct.BrainKey(bk_params + raw_bk), ct.Salt(salt))
