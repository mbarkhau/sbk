import os
import time
import collections
import typing as typ
import itertools as it

from . import perflog as pl

from . import enc_util


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return b"".join(enc_util.int2bytes(_a ^ _b) for _a, _b in zip(a, b))


Packet = int


MaybePacket = typ.Optional[Packet]
Packets     = typ.List[MaybePacket]

BlockIndexes = typ.Tuple[int, ...]


class Residual:
    """
    A residual is what remains when a packet has been xored another
    packet. It can be recursively xored together with other residuals
    to generate lower degree residuals.

    A residual with one block index, has the value of the message at
    that index.
    """

    __slots__ = ['val', 'indexes', 'sources']

    val    : int
    indexes: BlockIndexes
    sources: typ.Set[BlockIndexes]

    def __init__(
        self,
        val    : int,
        indexes: BlockIndexes,
        sources: typ.Optional[typ.Set[BlockIndexes]] = None,
    ) -> None:
        self.val     = val
        self.indexes = indexes
        if sources is None:
            self.sources = set([indexes])
        else:
            self.sources = set(sources)

    def __xor__indexes(self, other: 'Residual') -> BlockIndexes:
        return tuple(set(self.indexes) ^ set(other.indexes))

    def __xor__(self, other: 'Residual') -> 'Residual':
        new_val     = self.val ^ other.val
        new_indexes = self.__xor__indexes(other)
        new_sources = self.sources | other.sources
        return Residual(new_val, new_indexes, new_sources)

    def __len__(self) -> int:
        return len(self.indexes)

    def __repr__(self) -> str:
        return f"Residual({self.val:>3}, {sorted(self.indexes)}, {self.sources})"

    def __eq__(self, other: 'Residual') -> bool:
        return (
            self.val         == other.val
            and self.indexes == other.indexes
            and self.sources == other.sources
        )

    def __hash__(self) -> int:
        return (
            hash(self.val)
            ^ hash(self.indexes)
            ^ hash(tuple(sorted(self.sources)))
        )

    def __lt__(self, other: 'Residual') -> bool:
        return (
            len(self.indexes) < len(other.indexes)
            or self.indexes < other.indexes
        )


def _iter_packet_block_indexes(msg_len: int) -> typ.Iterable[BlockIndexes]:
    # For the first packets, the block_index and packet_index are the
    # same. In other words: block[:msg_len] == message[:]
    all_indexes = list(range(msg_len))

    while True:
        for byte_idx in all_indexes:
            yield (byte_idx,)

        for n in range(2, msg_len):
            for subset in it.combinations(all_indexes, n):
                yield tuple(subset)

        yield all_indexes

        for byte_idx in all_indexes:
            yield (byte_idx,)

        # There is probably something better to do than just
        # to repeat the same combinations. We might extend
        # all_indexes after the first set of indexes.


def packet_block_indexes(msg_len: int, ecc_len: int) -> typ.List[BlockIndexes]:
    """Iter over indexes which are combined to produce a packet.

    >>> packet_block_indexes(msg_len=3, ecc_len=0)
    [(0,), (1,), (2,)]

    >>> expected = [
    ...     (0,), (1,), (2,), (3,),
    ...     (0, 1, 2, 3,),
    ...     (0, 1, 2,),
    ...     (0, 1, 3,),
    ...     (0, 2, 3,),
    ...     (1, 2, 3,),
    ... ]
    >>> packet_block_indexes(msg_len=4, ecc_len=0) == expected[:4]
    True
    >>> packet_block_indexes(msg_len=4, ecc_len=1) == expected[:5]
    True
    >>> packet_block_indexes(msg_len=4, ecc_len=3) == expected[:7]
    True
    >>> pbi = packet_block_indexes(msg_len=4, ecc_len=10)
    >>> assert len(pbi) == 14
    >>> assert len(set(pbi)) == 14
    """
    pbi_iter  = _iter_packet_block_indexes(msg_len)
    block_len = msg_len + ecc_len
    return tuple(it.islice(pbi_iter, block_len))


Packet = int


def _iter_lt_encoded(msg: bytes, ecc_len: int) -> typ.Iterable[Packet]:
    msg_len = len(msg)
    for indexes in packet_block_indexes(msg_len, ecc_len):
        packet = 0
        for idx in indexes:
            packet = packet ^ msg[idx]
        yield packet


Message = bytes
Block   = bytes


def encode(msg: Message, ecc_len: int) -> Block:
    r"""Encode message to a block with LT Code as ecc data.

    >>> encode(b'test', ecc_len=0)
    b'test'
    >>> ecc = bytes([ord(b'4') ^ ord(b'2')])
    >>> encode(b'42', ecc_len=1) == b'42' + ecc
    True
    >>> len(encode(b'42', ecc_len=3))
    5
    >>> encode(b'42', ecc_len=3).startswith(b'42')
    True
    """
    if ecc_len == 0:
        return msg

    return bytes(_iter_lt_encoded(msg, ecc_len))


def decode(block: Block, ecc_len: int) -> Message:
    r"""Decode message from block with LT Code for ecc data.

    >>> message = b'123'
    >>> block = encode(message, ecc_len=4)
    >>> decode(block, ecc_len=4) == message
    True
    >>> # Fuzz test
    >>> for msg_len in range(1, 10):
    ...     for ecc_len in range(0, 5):
    ...         data = os.urandom(msg_len)
    ...         decoded = decode(encode(data, ecc_len), ecc_len)
    ...         assert decoded == data
    """
    if ecc_len == 0:
        return block
    else:
        packets = list(block)
        return decode_packets(packets, ecc_len)


def _top_residuals(residuals: typ.List['Residual']) -> typ.Iterable[int]:
    candidate_vals: typ.Dict[int, typ.List[int]] = collections.defaultdict(list)
    for r in residuals:
        if len(r.indexes) == 1:
            candidate_vals[r.indexes[0]].append(r.val)

    for idx, vals in sorted(candidate_vals.items()):
        top_vals = collections.Counter(vals).most_common()
        yield top_vals[0][0]


def _expand_residuals(
    residuals_a: typ.List[Residual], residuals_b: typ.List[Residual], max_degree: int
) -> typ.Iterable[Residual]:
    for a, b in it.product(residuals_a, residuals_b):
        if a == b:
            continue
        # if len(a.sources | b.sources) > max_degree:
        #     continue
        if not (set(a.indexes) & set(b.indexes)):
            continue

        c = a ^ b
        print(f"a {len(a):>2}", a)
        print(f"b {len(b):>2}", b)
        print(f"c {len(c):>2}", c)
        # if len(c) > 0 and len(c) <= len(a) and len(c) <= len(b):
        #     yield c
        if len(c) > 0 and (len(c) < len(a) or len(c) < len(b)):
            yield c


DEBUG = 1


def decode_packets(packets: Packets, ecc_len: int) -> Message:
    """Decode packets
    >>> message = b'123'
    >>> block = encode(message, ecc_len=1)
    >>> packets = list(block)
    >>> for i in range(len(packets)):
    ...     partial_packets = packets[:]
    ...     partial_packets[i] = None
    ...     decoded = decode_packets(partial_packets, ecc_len=1)
    ...     assert decoded == message, f"invalid result: {decoded}"
    >>> decode_packets(packets, ecc_len=4) == message
    True
    >>> # Fuzz test
    >>> for msg_len in range(1, 10):
    ...     for ecc_len in range(0, 5):
    ...         data = os.urandom(msg_len)
    ...         packets = list(encode(data, ecc_len))
    ...         decoded = decode_packets(packets, ecc_len)
    ...         assert decoded == data
    ...         # for err_count in range(0, ecc_len -1):
    ...         #     partial_packets = packets[:]
    ...         #     partial_packets[i] = None
    """
    if ecc_len == 0:
        return bytes(packets)

    msg_len = len(packets) - ecc_len

    with pl.trace("packet_block_indexes"):
        pbi = packet_block_indexes(msg_len, ecc_len)

    with pl.trace("initial_residuals"):
        residuals: typ.Set[Residual] = {
            Residual(val=packet, indexes=indexes)
            for packet, indexes in zip(packets, pbi)
            if packet is not None
        }

    if DEBUG:
        for r in sorted(residuals):
            print("old", r)

    new_residuals = residuals
    while True:
        expanded_residuals = set(_expand_residuals(residuals, new_residuals, 3))
        new_residuals      = expanded_residuals - residuals
        if DEBUG:
            print(
                "old",
                len(residuals),
                "new",
                len(new_residuals),
                "exp",
                len(expanded_residuals),
            )
            for r in sorted(new_residuals):
                print("new", r)
        if len(new_residuals) > 0:
            residuals.update(new_residuals)
        else:
            break

    with pl.trace("_top_residuals"):
        result = bytes(_top_residuals(residuals))

    if len(result) == msg_len:
        return result
    else:
        raise Exception("Message too corrupted, could not decode.")


def main():
    # message = b'1234'
    # block   = encode(message, ecc_len=4)
    # packets = list(block)
    # for i in range(len(packets)):
    #     partial_packets = packets[:]
    #     partial_packets[i] = None
    #     decoded = decode_packets(partial_packets, ecc_len=4)
    #     assert decoded == message, f"invalid result: {decoded}"

    # decode_packets(block, ecc_len=4) == message



    # for msg_len in range(10, 11):
    #     for ecc_len in range(1, 6):
    #         message = os.urandom(msg_len)
    #         with pl.trace(f"encode {msg_len} {ecc_len}"):
    #             block = encode(message, ecc_len)

    #         packets = list(block)
    #         for _ in range(1):
    #             corrupted_index = (os.urandom(1)[0]) % len(packets)
    #             packets[corrupted_index] = None

    #         print(">>", len(message), repr(message), msg_len, ecc_len)
    #         print("??", packets)

    #         with pl.trace(f"decode {msg_len} {ecc_len}"):
    #             decoded = decode_packets(packets, ecc_len)

    #         print("<<", len(decoded), repr(decoded))

    #         assert decoded == message


if __name__ == '__main__':
    main()
