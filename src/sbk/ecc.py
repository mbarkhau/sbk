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

import collections
import typing as typ

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

    n: message length (must be true: n % 4 == 0)
    M: the last message byte (index n-1)

    example for n=20

       message data
    a =  0- 5  b =  5-10
    c = 10-15  d = 15-20

         ecc data
    e = a^b    f = b^c
    g = c^d    h = a^d

    Phrases are just a different encoding of the message data.

    a=0 e=0^1^I    phrase(0) phrase(1)    b=1 f=0^1^J
    a=2 e=...      phrase(2) phrase(3)    b=3 f=...
    ...
    c=I g=0^I^J    phrase(I) phrase(J)    d=J h=1^I^J
    c=K g=...      phrase(K) phrase(M)    d=M h=...
    """
    assert msg_len % 4 == 0
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


def _iter_lt_encoded(msg: bytes) -> Iter[Packet]:
    msg_len = len(msg)
    pkt_len = msg_len // 4

    empty_packet = b"\x00" * pkt_len

    for indexes in packet_block_indexes(msg_len):
        packet = empty_packet
        for pbi in indexes:
            packet = xor_bytes(packet, pbi.apply(msg))
        yield packet


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
        self,
        data   : bytes,
        indexes: BlockIndexes,
        sources: typ.Optional[SourceIndexes] = None,
    ) -> None:
        self.data    = data
        self.indexes = indexes

        if sources is None:
            self.sources = set([indexes])
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
            raise NotImplemented

        return (
            self.data        == other.data
            and self.indexes == other.indexes
            and self.sources == other.sources
        )

    def __hash__(self) -> int:
        return (
            hash(self.data)
            ^ hash(self.indexes)
            ^ hash(tuple(sorted(self.sources)))
        )

    def __lt__(self, other: 'Residual') -> bool:
        return (
            len(self.indexes) < len(other.indexes)
            or self.indexes < other.indexes
        )


def _maybe_expand(x: Residual, y: Residual) -> typ.Optional[Residual]:
    if x == y:
        return

    x_idx = set(x.indexes)
    y_idx = set(y.indexes)

    has_intersect = x_idx & y_idx
    if not has_intersect:
        return

    z = x ^ y
    if len(z) == 0:
        return

    a = len(z) < len(x) or len(z) < len(y)
    b = len(z) >= len(x) and len(z) >= len(y)
    assert a != b

    if len(z) >= len(x) and len(z) >= len(y):
        return

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


def _maybe_candidate(r: Residual) -> typ.Optional[PacketCandidate]:
    is_root_residual = len(r.indexes) == 1
    if is_root_residual:
        idx = r.indexes[0]
        return PacketCandidate(idx.start, r.data)


def _iter_packet_candidates(
    indexed_packets: IndexedPackets
) -> Iter[PacketCandidate]:
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


TopByteCandidates = typ.Dict[PacketCandidate, int]
IndexCounts       = typ.Dict[int            , typ.List[int]]


def _index_counts(top_candidates: TopByteCandidates) -> IndexCounts:
    idx_counts: IndexCounts = collections.defaultdict(list)
    for (idx, _), count in top_candidates.items():
        idx_counts[idx].append(count)
    return dict(idx_counts.items())


# The fewer packets, the fewer candidates/combinations and the earlier
# we can declare a set of packets as decoded.

CANDIDATE_COUNTS_BY_NUM_PACKETS = {4: 8, 5: 38, 6: 114, 7: 283, 8: 636}


def is_complete(
    idx_counts: IndexCounts, msg_len: int, num_packets: int
) -> bool:
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


def _candidates_to_message(top_candidates: TopByteCandidates) -> bytes:
    top_counts: typ.Dict[int, int] = {}
    top_data  : typ.Dict[int, int] = {}

    for (idx, data), count in top_candidates.items():
        if top_counts.get(idx, 0) < count:
            top_counts[idx] = count
            top_data[idx] = data

    return bytes(d for _, d in sorted(top_data.items()))


def _top_candidates(indexed_packets: IndexedPackets) -> bytes:
    pkt             = next(iter(indexed_packets.values()))
    msg_len         = 4 * len(pkt)
    num_packets     = len(indexed_packets)
    candidates_iter = _iter_packet_candidates(indexed_packets)

    top_candidates: TopByteCandidates = collections.Counter()
    for candidate in candidates_iter:
        for i, data_byte in enumerate(candidate.data):
            msg_idx = candidate.msg_idx + i
            top_candidates[msg_idx, data_byte] += 1

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
    assert len(maybe_packets) == 8
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
