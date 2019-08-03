import os
import random
import sbk.ecc
import sbk.enc_util


def test_xor_bytes():
    cases = [
        (b"\x00\x00", b"\x00\x00", b"\x00\x00"),
        (b"\x12\x34", b"\x00\x00", b"\x12\x34"),
        (b"\x00\x00", b"\x12\x34", b"\x12\x34"),
        (b"\x01\x01", b"\x10\x10", b"\x11\x11"),
    ]
    for x, y, z in cases:
        assert sbk.ecc.xor_bytes(x, y) == z


def test_packet_block_indexes():
    _bi = sbk.ecc.BlockIndex
    expected = [
        (_bi( 0,  6),),
        (_bi( 6, 12),),
        (_bi(12, 18),),
        (_bi(18, 24),),
        # (_bi(12, 18), _bi(18, 24)),
        # (_bi( 6, 12), _bi(18, 24)),
        # (_bi( 0,  6), _bi(12, 18)),
        # (_bi( 0,  6), _bi( 6, 12)),
        (_bi( 0,  6), _bi( 6, 12), _bi(12, 18)),
        (_bi( 0,  6), _bi( 6, 12), _bi(18, 24)),
        (_bi( 0,  6), _bi(12, 18), _bi(18, 24)),
        (_bi( 6, 12), _bi(12, 18), _bi(18, 24)),
    ]
    indexes = sbk.ecc.packet_block_indexes(msg_len=24)
    assert indexes == expected


def test_encode():
    message = b'a1b2c3d4'
    block   = sbk.ecc.encode(message)
    assert len(block) == 16
    assert block.startswith(message)
    ecc_data = bytes(
        [
        #     ord(b'c') ^ ord(b'd'),
        #     ord(b'3') ^ ord(b'4'),
        #     ord(b'b') ^ ord(b'd'),
        #     ord(b'2') ^ ord(b'4'),
        #     ord(b'a') ^ ord(b'c'),
        #     ord(b'1') ^ ord(b'3'),
        #     ord(b'a') ^ ord(b'b'),
        #     ord(b'1') ^ ord(b'2'),
            ord(b'a') ^ ord(b'b') ^ ord(b'c'),
            ord(b'1') ^ ord(b'2') ^ ord(b'3'),
            ord(b'a') ^ ord(b'b') ^ ord(b'd'),
            ord(b'1') ^ ord(b'2') ^ ord(b'4'),
            ord(b'a') ^ ord(b'c') ^ ord(b'd'),
            ord(b'1') ^ ord(b'3') ^ ord(b'4'),
            ord(b'b') ^ ord(b'c') ^ ord(b'd'),
            ord(b'2') ^ ord(b'3') ^ ord(b'4'),
        ]
    )
    assert block == b'a1b2c3d4' + ecc_data


def test_block2packets():
    msg     = b'0123456789ABCDEF'
    packets = sbk.ecc.block2packets(msg)
    assert packets == [b'01', b'23', b'45', b'67', b'89', b'AB', b'CD', b'EF']


def test_residual_xor():
    a_bi = sbk.ecc.BlockIndex(0, 2)
    b_bi = sbk.ecc.BlockIndex(2, 4)

    x_pbi = (a_bi,)
    y_pbi = (a_bi, b_bi)

    x = sbk.ecc.Residual(b"\x00\x01", x_pbi)
    y = sbk.ecc.Residual(b"\x02\x03", y_pbi)
    z = x ^ y

    assert len(x) == 1
    assert len(y) == 2
    assert len(z) == 1

    assert len(x.sources) == 1
    assert len(y.sources) == 1
    assert len(z.sources) == 2

    assert z.indexes == (b_bi,)
    assert z.data    == b"\x02\x02"


def test_candidate_counts():
    # TODO
    return
    message          = b'01234567'
    block            = sbk.ecc.encode(message)
    packets          = sbk.ecc.block2packets(block)
    indexed_packets  = {idx: pkt for idx, pkt in enumerate(packets)}
    candidate_counts = {}

    for i in range(5):
        candidates  = list(sbk.ecc._iter_packet_candidates(indexed_packets))
        num_packets = len(indexed_packets)
        candidate_counts[num_packets] = len(candidates)
        del indexed_packets[i]

    assert candidate_counts == sbk.ecc.CANDIDATE_COUNTS_BY_NUM_PACKETS


def test_decode():
    message = b'01234567'
    block   = sbk.ecc.encode(message)
    assert sbk.ecc.decode(block) == message
    # Fuzz test
    for msg_len in range(4, 21, 4):
        message = os.urandom(msg_len)
        block   = sbk.ecc.encode(message)
        decoded = sbk.ecc.decode(block)
        assert decoded == message


def test_decode_packets():
    message = b'01234567'
    block   = sbk.ecc.encode(message)
    packets = sbk.ecc.block2packets(block)
    decoded = sbk.ecc.decode_packets(packets)

    assert decoded == message


def test_decode_packets_corrupted():
    message = b'01234567'
    block   = sbk.ecc.encode(message)
    packets = sbk.ecc.block2packets(block)

    for i in range(len(packets)):
        partial_packets = packets[:]
        partial_packets[i] = None
        decoded = sbk.ecc.decode_packets(partial_packets)
        assert decoded == message, f"invalid result: {decoded}"


def test_decode_packets_missing():
    data    = os.urandom(12)
    block   = sbk.ecc.encode(data)
    packets = sbk.ecc.block2packets(block)

    for o in range(4):
        partial_packets = [
            p if i < 4 + o else None for i, p in enumerate(packets)
        ]
        decoded = sbk.ecc.decode_packets(partial_packets)
        assert decoded == data

    partial_packets = [p if i < 4 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc.decode_packets(partial_packets)
    assert decoded == data

    partial_packets = [p if i >= 4 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc.decode_packets(partial_packets)
    assert decoded == data

    partial_packets = [p if i % 2 == 0 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc.decode_packets(partial_packets)
    assert decoded == data

    partial_packets = [p if i % 2 == 1 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc.decode_packets(partial_packets)
    assert decoded == data


def _fuzz_iter():
    for msg_len in range(4, 21, 4):
        data    = os.urandom(msg_len)
        block   = sbk.ecc.encode(data)
        packets = sbk.ecc.block2packets(block)
        yield data, block, packets


def test_decode_fuzz_basic():
    for data, block, packets in _fuzz_iter():
        assert len(block) == len(data) * 2
        decoded = sbk.ecc.decode(block)
        assert decoded == data
        decoded = sbk.ecc.decode_packets(packets)
        assert decoded == data


def test_decode_fuzz_missing_packets():
    for data, block, packets in _fuzz_iter():
        for packet_err_count in [0, 1, 2, 3]:
            packets         = sbk.ecc.block2packets(block)
            partial_packets = packets[:]
            for _ in range(packet_err_count):
                i = random.randint(0, 7)
                partial_packets[i] = None
            decoded = sbk.ecc.decode_packets(partial_packets)
            assert decoded == data


def _add_bad_symbols(block, num_errs):
    bad_block_data = list(block)
    bad_indexes    = [random.randint(0, len(block) - 1) for _ in range(num_errs)]
    for i in bad_indexes:
        bad_block_data[i] = 0

    bad_block = bytes(bad_block_data)
    return bad_block, bad_indexes


def test_decode_error_detect():
    for num_errs in [1, 2]:
        errors  = 0
        success = 0
        invalid = 0

        for data, block, packets in _fuzz_iter():
            bad_block, bad_indexes = _add_bad_symbols(block, num_errs)
            try:
                decoded = sbk.ecc.decode(bad_block)
                if decoded == data:
                    success += 1
                else:
                    print(">>", sbk.enc_util.bytes_repr(data ))
                    print("!!", sbk.enc_util.bytes_repr(block))
                    print("!!", sbk.enc_util.bytes_repr(bad_block), bad_indexes)
                    print("<<", sbk.enc_util.bytes_repr(decoded))
                    invalid += 1
            except sbk.ecc.DecodeError:
                errors += 1

        if num_errs == 1:
            assert errors == 0

        assert errors + success > 0
        assert invalid == 0
