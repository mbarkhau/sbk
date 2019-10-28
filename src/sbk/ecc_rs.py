# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Reed Solomon style (home-grown) Forward Error Correction code.

This may actually be a legitimate Reed Solomon encoding, it's certainly
based on the same ideas, I'm just not sure if it qualifies. If you
can contribute to making this conform to an appropriate standard, please
open an issue or merge request on gitlab.
"""

import sys
import math
import base64
import random
import typing as typ
import itertools
import collections

from . import gf
from . import gf_poly

# Message: Raw Data to be encoded, without ECC data
Message = bytes
# Block: Fully encoded Message including ECC data
Block = bytes
# Packet: Individual byte in a block
Packet  = int
Packets = typ.List[Packet]
# Erasures signified by None
# position in the sequence implies the x-coordinate
MaybePackets = typ.List[typ.Optional[Packet]]


def _nCr(n: int, r: int) -> float:
    f = math.factorial
    return f(n) / f(r) / f(n - r)


class ECCDecodeError(ValueError):
    pass


def _interpolate(points: gf_poly.Points, at_x: gf.Num) -> gf.Num:
    terms = iter(gf_poly._interpolation_terms(points, at_x=at_x))
    accu  = next(terms)
    for term in terms:
        accu += term
    return accu


def _encode(msg: Message, ecc_len: int) -> Block:
    if len(msg) == 0:
        msg = b"\x00\x00"
    if len(msg) == 1:
        # We need at least two points (and hence bytes) to do interpolation
        msg = msg + msg

    field = gf.GF256.field()

    data_points = [gf_poly.Point(field[x], field[y]) for x, y in enumerate(msg)]
    ecc_x_vals  = [field[x] for x in range(len(msg), len(msg) + ecc_len)]
    ecc_points  = [gf_poly.Point(x=x, y=_interpolate(data_points, at_x=x)) for x in ecc_x_vals]
    y_vals      = [p.y.val for p in data_points + ecc_points]
    assert all(0 <= y <= 255 for y in y_vals)
    return bytes(y_vals)


def encode(msg: Message, ecc_len: int) -> Block:
    """Encode message to a Block with RS Code as ECC data."""
    assert ecc_len >= 0
    if ecc_len == 0:
        return msg

    block = _encode(msg, ecc_len=ecc_len)
    assert block.startswith(msg)
    assert decode(block, len(msg)) == msg
    return block


Indexes = typ.Tuple[int, ...]


def _iter_indexes(msg_len: int, num_points: int) -> typ.Iterable[Indexes]:
    assert num_points >= msg_len

    all_indexes = tuple(range(num_points))
    if msg_len == num_points:
        yield all_indexes

    num_combos = _nCr(num_points, msg_len)
    if num_combos < 1000:
        # few enough for exhaustive search
        all_combos = list(itertools.combinations(all_indexes, msg_len))
        assert len(all_combos) == _nCr(num_points, msg_len)
        random.shuffle(all_combos)
        for combo in all_combos:
            yield tuple(combo)
    else:
        sample_combos: typ.Set[Indexes] = set()
        while len(sample_combos) < num_combos / 3:
            sample_combo = tuple(random.sample(all_indexes, msg_len))
            if sample_combo not in sample_combos:
                sample_combos.add(sample_combo)
                yield sample_combo


def decode_packets(packets: MaybePackets, msg_len: int) -> Message:
    field  = gf.GF256.field()
    points = [gf_poly.Point(field[x], field[y]) for x, y in enumerate(packets) if y is not None]

    if len(points) < msg_len:
        raise ECCDecodeError("Not enough data to recover message.")

    msg_x_coords = [field[x] for x in range(msg_len)]
    candidates: typ.Counter[bytes] = collections.Counter()
    for sample_num, point_indexes in enumerate(_iter_indexes(msg_len, len(points))):
        sample_points = [points[idx] for idx in point_indexes]
        msg_bytes     = [_interpolate(sample_points, at_x=x).val for x in msg_x_coords]
        msg_candidate = bytes(msg_bytes)
        candidates[msg_candidate] += 1

        if (sample_num + 1) % 20 == 0:
            if len(candidates) == 1:
                ((top, top_n),) = candidates.most_common(1)
                return top

            (top_0, top_0_n), (top_1, top_1_n) = candidates.most_common(2)
            # print("???", top_0_n, "vs", top_1_n, "of", sample_num)

            if top_0_n > top_1_n * 10:
                return top_0

    if len(set(candidates)) == 1:
        ((top, top_n),) = candidates.most_common(1)
        return top

    # last ditch check
    (top_0, top_0_n), (top_1, top_1_n) = candidates.most_common(2)
    if top_0_n > top_1_n * 2:
        return top_0

    raise ECCDecodeError("Message too corrupt to recover.")


def decode(block: Block, msg_len: int) -> Message:
    ecc_len = len(block) - msg_len
    assert ecc_len >= 0
    if ecc_len == 0:
        return block

    return decode_packets(list(block), msg_len)


def _cli_encode(msg: str) -> str:
    msg_data  = msg.encode("utf-8")
    block     = encode(msg_data, ecc_len=len(msg_data))
    block_str = base64.b16encode(block).decode('ascii').lower()
    return block_str


def _cli_decode(block_b16_str: str) -> str:
    block_b16 = block_b16_str.rstrip("\n").upper().encode("ascii")
    packets: MaybePackets = []
    for i in range(0, len(block_b16), 2):
        packet_b16 = block_b16[i : i + 2]
        try:
            packet = base64.b16decode(packet_b16)[0]
            packets.append(packet)
        except ValueError:
            packets.append(None)

    assert len(packets) == len(block_b16) // 2
    msg_data = decode_packets(packets, msg_len=len(block_b16) // 4)
    return msg_data.decode("utf-8")


CLI_HELP = """CLI to demo recovery using ecc.

Example usage:

    $ echo "Hello, 世界!" | python -m sbk.ecc_rs --encode
    48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428
    $ echo "48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428" | python -m sbk.ecc_rs --decode
    Hello, 世界!
    $ echo "48656c6c6f2c20e4b896e7958c210a                              " | python -m sbk.ecc_rs --decode
    Hello, 世界!
    $ echo "                              51ee32d3ac1bee26daac14d3b95428" | python -m sbk.ecc_rs --decode
    Hello, 世界!
    $ echo "48656c6c6f2c20                              26daac14d3b95428" | python -m sbk.ecc_rs --decode
    Hello, 世界!
"""


def main(args: typ.List[str] = sys.argv[1:]) -> int:
    if "-h" in args or "--help" in args or not args:
        print(main.__doc__)
        return 0

    input_data = sys.stdin.read()

    if "-e" in args or "--encode" in args:
        block_b16 = _cli_encode(input_data)
        sys.stdout.write(block_b16)
        return 0
    elif "-d" in args or "--decode" in args:
        msg = _cli_decode(input_data)
        sys.stdout.write(msg)
        return 0
    else:
        sys.stderr.write("Invalid arguments\n")
        sys.stderr.write(CLI_HELP)
        return 1

    return


main.__doc__ = CLI_HELP


if __name__ == '__main__':
    sys.exit(main())
