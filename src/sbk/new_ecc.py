# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import os
import random

from . import gf
from . import gf_poly
from . import enc_util

_rand = random.SystemRandom()


def interpolate(points: gf_poly.Points, at_x: gf.Num) -> gf.Num:
    terms = iter(gf_poly._interpolation_terms(points, at_x=at_x))
    accu  = next(terms)
    for term in terms:
        accu += term
    return accu


def old_main() -> None:
    field    = gf.GFNum.field(257)

    for _ in range(100):
        data_in = [255] + list(os.urandom(10)) + [255]

        data_points = [gf_poly.Point(field[x], field[y]) for x, y in enumerate(data_in)]

        ecc_points = []
        for x in range(12, 24):
            y = interpolate(data_points, at_x=field[x])
            ecc_points.append(gf_poly.Point(field[x], y))

        y_vals = [p.y.val for p in ecc_points]
        if not all(0 <= y <= 255 for y in y_vals):
            print("fail!!")
            for y_at_12 in range(0, 255):
                p_at_12       = gf_poly.Point(field[12], field[y_at_12])
                interp_points = data_points + [p_at_12]
                ecc_points    = [p_at_12]
                for x in range(13, 24):
                    y = interpolate(interp_points, at_x=field[x])
                    ecc_points.append(gf_poly.Point(field[x], y))

                y_vals = [p.y.val for p in ecc_points]
                if all(0 <= y <= 255 for y in y_vals):
                    break
                else:
                    print("fail!")

        points      = data_points + ecc_points
        points_data = bytes(p.y.val for p in points)
        print(len(points), enc_util.bytes_repr(points_data))

        for x in range(8):
            y = interpolate(points[11:], at_x=field[x])
            assert y.val == data_in[x]
        #     print(x, y.val == data_in[x], y.val, data_in[x])


def main() -> None:
    field = gf.GF256.field()
    for _ in range(100):
        data_in = [255] + list(os.urandom(10)) + [255]

        data_points = [gf_poly.Point(field[x], field[y]) for x, y in enumerate(data_in)]

        ecc_points = []
        for x in range(12, 24):
            y = interpolate(data_points, at_x=field[x])
            ecc_points.append(gf_poly.Point(field[x], y))

        y_vals = [p.y.val for p in ecc_points]
        assert all(0 <= y <= 255 for y in y_vals)

        points      = data_points + ecc_points
        points_data = bytes(p.y.val for p in points)
        print(len(points), enc_util.bytes_repr(points_data))

        for x in range(8):
            y = interpolate(points[12:], at_x=field[x])
            assert y.val == data_in[x]
            y = interpolate(points[:12], at_x=field[x])
            assert y.val == data_in[x]
            y = interpolate(points[6:18], at_x=field[x])
            assert y.val == data_in[x]
            y = interpolate(points[:6] + points[18:], at_x=field[x])
            assert y.val == data_in[x]
        #     print(x, y.val == data_in[x], y.val, data_in[x])


if __name__ == '__main__':
    main()
