"""Error correction coding.

The encoding scheme here is quite simple and is based on LT-Codes. I'm
not smart enough/don't have the time for a more general implementation
or something based on RS-Codes, so this is the most simple that works.

The data layout is based on the assumption that the provided SBK-Piece
template is used. If that is the case, any half of the SBK-Piece can
be lost/corrupted and it will still be possible to recover the
original data.

The first implementation can correct single byte errors and detect two
byte errors.
"""

import typing as typ
import collections

Seq  = typ.Sequence
Iter = typ.Iterable


def _xor_bytes(a: bytes, b: bytes) -> Iter[int]:
    for _a, _b in zip(a, b):
        yield _a ^ _b


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(_xor_bytes(a, b))


Message = bytes
Packet  = bytes
Block   = bytes
Packets = Seq[Packet]

MaybePackets   = Seq[typ.Optional[Packet]]
IndexedPackets = typ.Dict[int, Packet]


class BlockIndex(typ.NamedTuple):
    start: int
    end  : int

    def apply(self, data: Message) -> Packet:
        return data[self.start : self.end]


BlockIndexes = typ.Tuple[BlockIndex, ...]

PacketBlockIndexes = Seq[BlockIndexes]


def packet_block_indexes(msg_len: int) -> PacketBlockIndexes:
    """List of block indexes used to generate packets of a block.

    n: message length (must be: n % 4 == 0)
    M: the last message byte (index n-1)

    block length = n * 2

    example for n=24  (24 * 8 = 192 bit)

              message data
    a = 0- 5    b = 12-17
    a = 6-11    b = 18-23

               ecc data
    e = a^c^d   g = a^c^d
    f = a^b^d   h = b^c^d

    Phrases are just a different encoding of
    the message data, without any ecc data.

    Note that the format/layout on paper is
    sideways compared to the above.

        Data          Phrases               ECC
    A0: a0 a1    Phrase  0 Phrase  1    C0: e0 e1
    A1: a2 a3    Phrase  2 Phrase  3    C1: e2 e3
    A2: a4 a5    Phrase  4 Phrase  5    C2: e4 e5
    A3: b0 b1    Phrase  6 Phrase  7    C3: f0 f1
    A4: b2 b3    Phrase  8 Phrase  9    C4: f2 f3
    A5: b4 b5    Phrase 10 Phrase 11    C5: f4 f5

    B0: c0 c1    Phrase 12 Phrase 13    D0: g0 g1
    B1: c2 c3    Phrase 14 Phrase 15    D1: g2 g3
    B2: c4 c5    Phrase 16 Phrase 17    D2: g4 g5
    B3: d0 d1    Phrase 18 Phrase 19    D3: h0 h1
    B4: d2 d3    Phrase 20 Phrase 21    D4: h2 h3
    B5: d4 d5    Phrase 22 Phrase 23    D5: h4 h5
    """
    assert msg_len % 4 == 0, msg_len
    pkt_len = msg_len // 4

    a = (BlockIndex(pkt_len * 0, pkt_len * 1),)
    b = (BlockIndex(pkt_len * 1, pkt_len * 2),)
    c = (BlockIndex(pkt_len * 2, pkt_len * 3),)
    d = (BlockIndex(pkt_len * 3, pkt_len * 4),)

    e = a + b + c
    f = a + b + d
    g = a + c + d
    h = b + c + d

    return [a, b, c, d, e, f, g, h]


def _iter_lt_encoded(msg: Message) -> Iter[Packet]:
    msg_len = len(msg)
    pkt_len = msg_len // 4

    empty_packet = b"\x00" * pkt_len

    for indexes in packet_block_indexes(msg_len):
        packet = empty_packet
        for pbi in indexes:
            packet = xor_bytes(packet, pbi.apply(msg))
        yield packet


def encode2packets(msg: Message) -> typ.List[Packet]:
    return list(_iter_lt_encoded(msg))


def encode(msg: Message) -> Block:
    """Encode message to a block with LT Code as ecc data."""
    return b"".join(_iter_lt_encoded(msg))


SourceIndexes = typ.Set[BlockIndexes]


class Residual:
    """Residual: What remains when a packet is xored with another.

    A Residual is recursively xored together with others to get lower
    degree residuals.

    A Residual with only one remaining index has the original data of
    the message at that index.
    """

    __slots__ = ['data', 'indexes', 'sources']

    data   : Packet
    indexes: BlockIndexes
    sources: SourceIndexes

    def __init__(
        self, data: bytes, indexes: BlockIndexes, sources: typ.Optional[SourceIndexes] = None
    ) -> None:
        self.data    = data
        self.indexes = indexes

        if sources is None:
            self.sources = {indexes}
        else:
            self.sources = set(sources)

    def __xor__indexes(self, other: 'Residual') -> BlockIndexes:
        return tuple(set(self.indexes) ^ set(other.indexes))

    def __xor__(self, other: 'Residual') -> 'Residual':
        new_data = xor_bytes(self.data, other.data)
        assert len(new_data) == len(self.data)
        assert len(new_data) == len(other.data)
        new_indexes = self.__xor__indexes(other)
        new_sources = self.sources | other.sources
        return Residual(new_data, new_indexes, new_sources)

    def __len__(self) -> int:
        return len(self.indexes)

    def __repr__(self) -> str:
        indexes = sorted(self.indexes)
        return f"Residual({self.data}, {indexes}, {self.sources})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Residual):
            raise NotImplementedError

        return (
            self.data        == other.data
            and self.indexes == other.indexes
            and self.sources == other.sources
        )

    def __hash__(self) -> int:
        return hash(self.data) ^ hash(self.indexes) ^ hash(tuple(sorted(self.sources)))

    def __lt__(self, other: 'Residual') -> bool:
        return len(self.indexes) < len(other.indexes) or self.indexes < other.indexes


def _maybe_expand(x: Residual, y: Residual) -> typ.Optional[Residual]:
    if x == y:
        return None

    x_idx = set(x.indexes)
    y_idx = set(y.indexes)

    has_intersect = x_idx & y_idx
    if not has_intersect:
        return None

    z = x ^ y
    if len(z) == 0:
        return None

    a = len(z) < len(x) or len(z) < len(y)
    b = len(z) >= len(x) and len(z) >= len(y)
    assert a != b

    if len(z) >= len(x) and len(z) >= len(y):
        return None

    return z


class DecodeError(Exception):
    pass


def _iter_base_residuals(indexed_packets: IndexedPackets) -> Iter[Residual]:
    pkt_len = len(next(iter(indexed_packets.values())))
    msg_len = pkt_len * 4

    pbi = packet_block_indexes(msg_len)

    for idx, pkt in indexed_packets.items():
        assert pkt_len == len(pkt), f"{pkt_len} != {len(pkt)}"
        assert all(pkt_len == idx.end - idx.start for idx in pbi[idx])
        yield Residual(data=pkt, indexes=pbi[idx])


class PacketCandidate(typ.NamedTuple):

    msg_idx: int
    data   : bytes


class MessageCandidate(typ.NamedTuple):
    msg_idx : int
    byte_val: int


def _maybe_candidate(r: Residual) -> typ.Optional[PacketCandidate]:
    is_root_residual = len(r.indexes) == 1
    if is_root_residual:
        idx = r.indexes[0]
        return PacketCandidate(idx.start, r.data)
    else:
        return None


def _iter_packet_candidates(indexed_packets: IndexedPackets) -> Iter[PacketCandidate]:
    residuals = set(_iter_base_residuals(indexed_packets))
    for r in residuals:
        c = _maybe_candidate(r)
        if c:
            yield c

    stack = list(residuals)
    while stack:
        x = stack.pop()
        for y in stack:
            z = _maybe_expand(x, y)
            if z is None:
                continue
            if z in residuals:
                continue

            stack.append(z)
            residuals.add(z)

            c = _maybe_candidate(z)
            if c:
                yield c


TopMessageCandidates = typ.Dict[MessageCandidate, int]

IndexCounts = typ.Dict[int, typ.List[int]]


def _index_counts(top_candidates: TopMessageCandidates) -> IndexCounts:
    idx_counts: IndexCounts = collections.defaultdict(list)
    for (idx, _), count in top_candidates.items():
        idx_counts[idx].append(count)
    return dict(idx_counts.items())


# The fewer packets, the fewer candidates/combinations and the earlier
# we can declare a set of packets as decoded.

CANDIDATE_COUNTS_BY_NUM_PACKETS = {4: 8, 5: 38, 6: 114, 7: 283, 8: 636}


def is_complete(idx_counts: IndexCounts, msg_len: int, num_packets: int) -> bool:
    if len(idx_counts) < msg_len:
        return False

    base_candidate_count = CANDIDATE_COUNTS_BY_NUM_PACKETS[num_packets]
    max_candidate_count  = base_candidate_count / 8 * msg_len
    candidate_count      = sum(sum(c) for c in idx_counts.values())

    if candidate_count < max_candidate_count:
        return False

    if any(len(c) > 1 for c in idx_counts.values()):
        return False

    return True


def is_decidable(idx_counts: IndexCounts, threshold: float) -> bool:
    for counts in idx_counts.values():
        counts.sort()
        if counts[-1] < 50:
            return False

        if len(counts) == 1:
            continue

        if counts[-1] / counts[-2] < threshold:
            return False

    return True


def _candidates_to_message(top_candidates: TopMessageCandidates) -> bytes:
    top_counts: typ.Dict[int, int] = {}
    top_values: typ.Dict[int, int] = {}

    for (idx, byte_val), count in top_candidates.items():
        if top_counts.get(idx, 0) < count:
            top_counts[idx] = count
            top_values[idx] = byte_val

    return bytes(v for _, v in sorted(top_values.items()))


def _top_candidates(indexed_packets: IndexedPackets) -> bytes:
    pkt             = next(iter(indexed_packets.values()))
    msg_len         = 4 * len(pkt)
    num_packets     = len(indexed_packets)
    candidates_iter = _iter_packet_candidates(indexed_packets)

    top_candidates: TopMessageCandidates = collections.Counter()
    for pkt_candidate in candidates_iter:
        for i, data_byte in enumerate(pkt_candidate.data):
            msg_idx       = pkt_candidate.msg_idx + i
            msg_candidate = MessageCandidate(msg_idx, data_byte)
            top_candidates[msg_candidate] += 1

        idx_counts = _index_counts(top_candidates)

        if is_complete(idx_counts, msg_len, num_packets):
            # not gonna get any better
            return _candidates_to_message(top_candidates)

        if is_decidable(idx_counts, threshold=2.0):
            # early exit
            return _candidates_to_message(top_candidates)

    # last ditch attempt
    if is_decidable(idx_counts, threshold=1.2):
        return _candidates_to_message(top_candidates)
    else:
        raise DecodeError("Data too corrupted")


def decode_packets(maybe_packets: MaybePackets) -> Message:
    """Decode packets to original message."""
    if len(maybe_packets) != 8:
        errmsg = f"Invalid argument, len(maybe_packets) must 8 but was: {len(maybe_packets)}"
        raise ValueError(errmsg)

    indexed_packets: IndexedPackets = {
        idx: pkt for idx, pkt in enumerate(maybe_packets) if pkt is not None
    }
    if len(indexed_packets) < 4:
        raise DecodeError("Not enough data")

    return _top_candidates(indexed_packets)


def _iter_packets(block: Block) -> Iter[Packet]:
    msg_len = len(block) // 2
    pkt_len = msg_len // 4
    for i in range(0, len(block), pkt_len):
        yield block[i : i + pkt_len]


def block2packets(block: Block) -> Packets:
    return list(_iter_packets(block))


def decode(block: Block) -> Message:
    r"""Decode Block to Message.

    Convert a Block (which is the message with ecc data) into a the
    original Message.

    This is just for illustration and testing of the api. The api that
    should be used by client code is `decode_packets`, which allows
    individual packets to be marked as missing (None) which leads to
    better error recovery.
    """
    packets = block2packets(block)
    return decode_packets(packets)
