# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Common parsing, encoding and formatting functions for CLI and GUI."""

import os
import re
import pwd
import time
import base64
import hashlib
import logging
import pathlib as pl
import tempfile
import functools as ft
import threading
import subprocess as sp
from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union
from typing import Generic
from typing import NewType
from typing import TypeVar
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Protocol
from typing import Sequence
from typing import Generator
from typing import NamedTuple

import click
import mypy_extensions as mypyext

from . import kdf
from . import ecc_rs
from . import shamir
from . import gf_poly
from . import enc_util
from . import mnemonic
from . import sys_info
from . import parameters
from . import sbk_random
from . import common_types as ct
from . import electrum_mnemonic

logger = logging.getLogger("sbk.ui_common")


USER_GUIDE_TEXT = """
https://sbk.dev/guide
"""

# python experiments/qr_test.py 'https://sbk.dev/guide'
USER_GUIDE_QR_CODE = """
█▀▀▀▀▀█ ▀▄▄▀▀█  ▄ █▀▀▀▀▀█
█ ███ █   ▀ ██▀ ▄ █ ███ █
█ ▀▀▀ █  ▀▄▀▄▀▀ ▀ █ ▀▀▀ █
▀▀▀▀▀▀▀ █ █▄▀▄▀▄█ ▀▀▀▀▀▀▀
█▀ █▀▄▀▄▄█▀▀▄ █▄█ ▀▄▄▄▄▄▀
 ▄█ ▄▄▀▀▀▄██▄  █ █▀▀ █▄▄█
██▀▀▄ ▀▄▄▀ ▀▀▄▄█▄ ▀ ▄  ▄▀
█▀██▀▀▀█ ▀▄█▀▀▀▀ ▄ ▄▀██▀█
▀     ▀▀██ ▄▄▄▀▀█▀▀▀█ ██
█▀▀▀▀▀█  █▄▀▄ ▄▄█ ▀ █  ▄█
█ ███ █ █▀▄ ▀▀█▀█▀█▀▀  ██
█ ▀▀▀ █ ▄██ ▀ █  ▀ ▄█▀███
▀▀▀▀▀▀▀ ▀ ▀  ▀▀ ▀▀   ▀  ▀
"""


SECURITY_WARNING_TEXT = """
Security Warning

Ideally you can satisfy the following:

 - No other person can see your screen.
 - Your computer is not connected to any network.
 - Your computer is booted using a trusted installation of Linux.

For more information on setting up a secure air-gapped system
see: https://sbk.dev/airgap
"""

# python experiments/qr_test.py 'https://sbk.dev/airgap'
SECURITY_WARNING_QR_CODES = """
                                █████████████████████████████████
                                █████████████████████████████████
  █▀▀▀▀▀█  ▀▀█▄ ▀ ▄ █▀▀▀▀▀█     ████ ▄▄▄▄▄ ██▄▄ ▀█▄█▀█ ▄▄▄▄▄ ████
  █ ███ █ ▄▀██ ▄▀▀▄ █ ███ █     ████ █   █ █▀▄  █▀▄▄▀█ █   █ ████
  █ ▀▀▀ █ ▀▄█ ▀▄▀ █ █ ▀▀▀ █     ████ █▄▄▄█ █▄▀ █▄▀▄█ █ █▄▄▄█ ████
  ▀▀▀▀▀▀▀ ▀▄▀ █ ▀▄█ ▀▀▀▀▀▀▀     ████▄▄▄▄▄▄▄█▄▀▄█ █▄▀ █▄▄▄▄▄▄▄████
  █▀▄▄ ▀▀█ ▀█ ▀▀█▄▄  ▄██▄▄      ████ ▄▀▀█▄▄ █▄ █▄▄ ▀▀██▀  ▀▀█████
  ▀▀▀█ █▀█ ▀▄█▀▀██▄ ▀▀▀█ ▀█     ████▄▄▄ █ ▄ █▄▀ ▄▄  ▀█▄▄▄ █▄ ████
  █▄█▄  ▀█ ▀█ ▄  █▄ ▀▄   ▄▀     ████ ▀ ▀██▄ █▄ █▀██ ▀█▄▀███▀▄████
  █ ▄█▀█▀▄ █▀ ▄  ▀▀▄ █▀█▄▀█     ████ █▀ ▄ ▄▀█ ▄█▀██▄▄▀█ ▄ ▀▄ ████
  ▀ ▀   ▀▀██▀ ▀▀█▀█▀▀▀█ ▀       ████▄█▄███▄▄  ▄█▄▄ ▄ ▄▄▄ █▄██████
  █▀▀▀▀▀█ ██▀▄▀▀▀▄█ ▀ █   ▀     ████ ▄▄▄▄▄ █  ▄▀▄▄▄▀ █▄█ ███▄████
  █ ███ █  ▄█▀▄▄▄▀█▀█▀▀ ▀██     ████ █   █ ██▀ ▄▀▀▀▄ ▄ ▄▄█▄  ████
  █ ▀▀▀ █ ▄▄▄ ▄█▀ ▄▄ ▄▄▀▀ █     ████ █▄▄▄█ █▀▀▀█▀ ▄█▀▀█▀▀▄▄█ ████
  ▀▀▀▀▀▀▀ ▀  ▀▀▀  ▀▀   ▀  ▀     ████▄▄▄▄▄▄▄█▄██▄▄▄██▄▄███▄██▄████
                                █████████████████████████████████
                                ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""


SECURITY_WARNING_QR_CODE = """
            █▀▀▀▀▀█  ▀▀█▄ ▀ ▄ █▀▀▀▀▀█
            █ ███ █ ▄▀██ ▄▀▀▄ █ ███ █
            █ ▀▀▀ █ ▀▄█ ▀▄▀ █ █ ▀▀▀ █
            ▀▀▀▀▀▀▀ ▀▄▀ █ ▀▄█ ▀▀▀▀▀▀▀
            █▀▄▄ ▀▀█ ▀█ ▀▀█▄▄  ▄██▄▄
            ▀▀▀█ █▀█ ▀▄█▀▀██▄ ▀▀▀█ ▀█
            █▄█▄  ▀█ ▀█ ▄  █▄ ▀▄   ▄▀
            █ ▄█▀█▀▄ █▀ ▄  ▀▀▄ █▀█▄▀█
            ▀ ▀   ▀▀██▀ ▀▀█▀█▀▀▀█ ▀
            █▀▀▀▀▀█ ██▀▄▀▀▀▄█ ▀ █   ▀
            █ ███ █  ▄█▀▄▄▄▀█▀█▀▀ ▀██
            █ ▀▀▀ █ ▄▄▄ ▄█▀ ▄▄ ▄▄▀▀ █
            ▀▀▀▀▀▀▀ ▀  ▀▀▀  ▀▀   ▀  ▀
"""


SALT_INFO_TEXT = """
You will need the salt to load your wallet with your brainkey.
Write down the salt in clear writing and keep it secure.

"""

SBK_KEYGEN_TEXT = """
The Master Key is derived using the computationally and memory
intensive Argon2 KDF (Key Derivation Function). This ensures that your
brainkey is secure even if an attacker has access to the salt.

    (Salt + Brainkey) -> Master Key
"""


SHARE_INFO_TEXT = """
Keep this Share hidden in a safe place or give it to a trustee
for them to keep safe. A trustee must trustworthy in two senses:

  1. You must trust them to not collude with others and steal from you.
  2. You must trust that they are competent to keep this "Share" safe and secure.
"""

SHARE_PROMPT_TMPL = """
When you have copied Share {share_no}/{num_shares}, press enter to continue.
"""

BRAINKEY_INFO_TEXT = """
Your Salt and Brainkey are combined to produce your wallet seed.
As long as you remember Salt and Brainkey, you will can recover
your wallet.

It is important that you:
 - MEMORIZE YOUR BRAINKEY.
 - KEEP IT SECRET. Never tell your Brainkey to anybody, ever.
 - DO SPACED REPETITION: Regularly recite your Brainkey so you don't forget it.
"""

BRAINKEY_LAST_CHANCE_WARNING_TEXT = """
This is the ONLY TIME your Brainkey will be shown.

If you don't yet feel confident in your memory:

 1. Write down the brainkey as a temporary memory aid.
 2. Do not use the generated wallet until you feel
    comfortable that you have have memorized your brainkey.
 3. Destroy the memory aid before you use the wallet.

When you have copied your Brainkey, press enter to continue
"""

# https://regex101.com/r/iQKt5L/6
FORMATTED_LINE_PATTERN = r"""
[AB0-9]\d:[ ]
    (\d{3}-\d{3})
    \s+
    ([A-Za-z]+)\s+([A-Za-z]+)
    \s+
[CD0-9]\d:[ ]
    (\d{3}-\d{3})
"""


FORMATTED_LINE_RE = re.compile(FORMATTED_LINE_PATTERN, flags=re.VERBOSE)


Lines = Iterable[str]

PhraseLines = Sequence[str]

PartIndex = int
PartVal   = bytes
PartVals  = Sequence[PartVal]
# A PartVal can be b"" to mark its value is not known yet.


BYTES_PER_INTCODE = 2

IntCode       = str
IntCodes      = Sequence[IntCode]
MaybeIntCode  = Optional[IntCode]
MaybeIntCodes = Sequence[MaybeIntCode]


def bytes2intcode_parts(data: bytes, idx_offset: int = 0) -> Iterator[IntCode]:
    if len(data) % 2 != 0:
        errmsg = f"Invalid data, must be divisible by 2, got: {len(data)}"
        raise ValueError(errmsg)

    for i in range(len(data) // 2):
        idx     = idx_offset + i
        chk_idx = idx % 13

        byte0 = enc_util.char_at(data, i * 2 + 0)
        byte1 = enc_util.char_at(data, i * 2 + 1)

        bits = chk_idx << 16
        bits |= byte0 << 8
        bits |= byte1
        assert bits <= 999999
        intcode = f"{bits:06}"
        yield intcode[:3] + "-" + intcode[3:]


def bytes2incode_part(data: bytes, idx_offset: int = 0) -> IntCode:
    """Parse a single intcode from two bytes.

    idx_offset: The intcode index offset (2*bytes index offset)
    """
    assert len(data) == 2
    intcodes = list(bytes2intcode_parts(data, idx_offset))
    assert len(intcodes) == 1
    return intcodes[0]


def bytes2intcodes(data: bytes) -> IntCodes:
    """Encode data to intcode.

    The main purpose of the intcode format is to be
    compact, redundant and resilient to input errors.
    """
    _total_len = len(data) * 2
    while _total_len % 4 != 0:
        _total_len += 1

    ecc_len       = _total_len - len(data)
    data_with_ecc = ecc_rs.encode(data, ecc_len=ecc_len)
    intcodes      = list(bytes2intcode_parts(data_with_ecc))

    decoded_data = intcodes2bytes(intcodes, msg_len=len(data))
    if decoded_data == data:
        return intcodes
    else:
        errmsg = "Round trip failed: intcodes2bytes(bytes2intcodes(...))"
        raise AssertionError(errmsg)


def intcodes2parts(intcodes: MaybeIntCodes, idx_offset: int = 0) -> PartVals:
    """Decode and and validate intcodes to PartVals."""
    expected_chk_idx = idx_offset % 13
    chk_idx_offset   = idx_offset - expected_chk_idx

    part_vals = [b""] * (len(intcodes) * 2)

    for idx, intcode in enumerate(intcodes):
        if intcode:
            intcode = intcode.replace("-", "").replace(" ", "")

        if intcode:
            bits = int(intcode, 10)

            chk_idx = bits >> 16
            byte0   = (bits >> 8) & 0xFF
            byte1   = bits & 0xFF

            if chk_idx != expected_chk_idx:
                raise ValueError("Invalid code: Bad order.")

            part_vals[idx * 2 + 0] = bytes([byte0])
            part_vals[idx * 2 + 1] = bytes([byte1])

        next_chk_idx = (expected_chk_idx + 1) % 13
        if next_chk_idx < expected_chk_idx:
            # Since the range for part numbers is
            # limited, we assume consecutive input
            # to validate chk_idx.
            #
            # chk_idx  ... 11, 12,  0,  1,  2 ...
            # part_idx ... 11, 12, 13, 14, 15 ...
            chk_idx_offset += 13

        expected_chk_idx = next_chk_idx

    return part_vals


def intcodes2mnemonics(intcodes: Sequence[str]) -> Sequence[str]:
    data_with_ecc = intcodes2parts(intcodes)
    parts         = data_with_ecc[: len(data_with_ecc) // 2]
    return mnemonic.bytes2phrase(b"".join(parts)).split()


def maybe_intcodes2bytes(intcodes: MaybeIntCodes, msg_len: int) -> bytes:
    data_with_ecc = intcodes2parts(intcodes)

    assert all(len(part) <= 1 for part in data_with_ecc)
    maybe_packets = tuple(part[0] if part else None for part in data_with_ecc)
    return ecc_rs.decode_packets(maybe_packets, msg_len)


def intcodes2bytes(intcodes: IntCodes, msg_len: int) -> bytes:
    return maybe_intcodes2bytes(intcodes, msg_len=msg_len)


class ParsedSecret(NamedTuple):
    words     : Tuple[str    , ...]
    data_codes: Tuple[IntCode, ...]
    ecc_codes : Tuple[IntCode, ...]


def parse_formatted_secret(text: str, strict: bool = True) -> ParsedSecret:
    words     : List[str    ] = []
    data_codes: List[IntCode] = []
    ecc_codes : List[IntCode] = []

    for i, line in enumerate(text.splitlines()):
        line = line.strip().lower()
        if not line or line.startswith("data"):
            continue

        match = FORMATTED_LINE_RE.match(line.strip())
        if match is None:
            if strict:
                line_no = i + 1
                err_msg = f"Invalid input at line {line_no}: {repr(line)}"
                raise ValueError(err_msg)
            else:
                continue

        (data, w1, w2, ecc) = match.groups()

        data_codes.append(data)
        words.extend([w1, w2])
        ecc_codes.append(ecc)

    return ParsedSecret(tuple(words), tuple(data_codes), tuple(ecc_codes))


class Scheme(NamedTuple):

    threshold : int
    num_shares: int
    # sss_t: int
    # sss_n: int


def parse_scheme(scheme_arg: str) -> Scheme:
    if not re.match(r"^\d+of\d+$", scheme_arg):
        errmsg = f"Invalid parameter for --scheme={scheme_arg}. Try something like '3of5'"
        raise click.Abort(errmsg)

    threshold, num_shares = map(int, scheme_arg.split("of"))
    if threshold > num_shares:
        errmsg = f"Invalid parameter for --scheme={scheme_arg}"
        errmsg += ", num_shares must be larger than threshold"
        raise click.Abort(errmsg)

    if not threshold <= 16:
        errmsg = f"Invalid parameter for --scheme={scheme_arg}"
        errmsg += f", threshold must be <= 16, but was {threshold}"
        raise click.Abort(errmsg)

    if not num_shares < 64:
        errmsg = f"Invalid parameter for --scheme={scheme_arg}"
        errmsg += f", num_shares must be < 64, but was {num_shares}"
        raise click.Abort(errmsg)

    return Scheme(threshold, num_shares)


T = TypeVar('T')


class ThreadRunner(threading.Thread, Generic[T]):

    _exception: Optional[Exception]
    _return   : Optional[T]

    def __init__(self, target: Callable[[], T]) -> None:
        threading.Thread.__init__(self, target=target)
        self._target    = target
        self._exception = None
        self._return    = None
        # daemon means the thread is killed if user hits Ctrl-C
        self.daemon = True

    def run(self) -> None:
        tgt = self._target
        assert tgt is not None
        try:
            self._return = tgt()
        except Exception as ex:
            self._exception = ex
            raise

    def join(self, *args) -> None:
        threading.Thread.join(self, *args)

        if self._exception:
            errmsg = f"Thread failed with {type(self._exception)}: {self._exception}"
            raise Exception(errmsg) from self._exception

        if self._return is None:
            raise Exception("Missing return value after Thread.join")

    @property
    def retval(self) -> T:
        rv = self._return
        # mypy pacification (join would already have raised Exception)
        assert rv is not None
        return rv

    def start_and_join(self) -> T:
        self.start()
        self.join()
        return self.retval


DEFAULT_WALLET_NAME = "empty"

SEED_DATA_LEN = 16


class ProgressbarUpdater(Protocol):
    def update(self, n_steps: int) -> None:
        ...

    def __enter__(self) -> Any:
        ...

    def __exit__(self, exc_type, exc_value, tb) -> None:
        ...


InitProgressbar = Callable[[mypyext.NamedArg(int, 'length')], ProgressbarUpdater]  # noqa: F821


class DummyProgressbar(ProgressbarUpdater):
    def __init__(self, length: int) -> None:
        super().__init__()

    def update(self, n_steps: int) -> None:
        pass

    def __enter__(self) -> Any:
        return self

    def __exit__(self, exc_type, exc_value, tb) -> None:
        pass


def fallback_progressbar(label: str) -> InitProgressbar:
    if os.getenv('SBK_PROGRESS_BAR', "1") == '1':
        return ft.partial(click.progressbar, label=label, show_eta=True)
    else:
        return DummyProgressbar


def derive_seed(
    label           : str,
    kdf_params      : Union[parameters.Parameters, parameters.KDFParams],
    brainkey        : ct.BrainKey,
    salt            : ct.Salt,
    wallet_name     : str = DEFAULT_WALLET_NAME,
    init_progressbar: Optional[InitProgressbar] = None,
) -> ct.WalletSeed:
    if init_progressbar is None:
        _init_progressbar = fallback_progressbar(label)
    else:
        _init_progressbar = init_progressbar

    master_key       = salt + brainkey
    wallet_name_data = wallet_name.encode('utf-8')
    kdf_input        = master_key + wallet_name_data

    digester_fn = ft.partial(
        kdf.digest,
        data=kdf_input,
        kdf_params=kdf_params,
        hash_len=SEED_DATA_LEN,
    )
    if os.getenv('SBK_PROGRESS_BAR', "1") == '1':
        with _init_progressbar(length=100) as pg_bar:
            digester_fn = ft.partial(digester_fn, progress_cb=pg_bar.update)
            runner      = ThreadRunner[bytes](digester_fn)
            wallet_seed = runner.start_and_join()
    else:
        # Always the ThreadRunner so that Ctrl-C is not blocked.
        runner      = ThreadRunner[bytes](digester_fn)
        wallet_seed = runner.start_and_join()
    return ct.WalletSeed(wallet_seed)


def run_with_progress_bar(
    target          : Callable[[], T],
    eta_sec         : float,
    init_progressbar: InitProgressbar,
) -> T:
    runner = ThreadRunner[T](target)
    runner.start()
    if os.getenv('SBK_PROGRESS_BAR', "1") == '0':
        runner.join()
        return runner.retval

    total_ms = int(eta_sec * 1000)
    step_ms  = 100

    with init_progressbar(length=total_ms) as pg_bar:
        tzero = time.time()
        while runner.is_alive():
            time.sleep(step_ms / 1000)

            done_ms  = (time.time() - tzero) * 1000
            rest_ms  = max(0, total_ms - done_ms)
            rest_pct = 100 * rest_ms / total_ms if total_ms > 0 else 50

            # Lies, damn lies, and progress bars
            if rest_pct > 10:
                pg_bar.update(step_ms)  # default
            elif rest_pct > 3:
                pg_bar.update(step_ms // 2)  # slower step
            else:
                pg_bar.update(step_ms // 10)  # just nudge

        pg_bar.update(total_ms)

    runner.join()
    return runner.retval


def parse_kdf_params(
    target_duration : ct.Seconds,
    memory_cost     : Optional[ct.MebiBytes],
    time_cost       : Optional[ct.Iterations],
    init_progressbar: InitProgressbar,
) -> parameters.KDFParams:
    nfo           = sys_info.load_sys_info()
    target_memory = nfo.usable_mb * parameters.DEFAULT_KDF_M_PERCENT / 1500

    kdf_m = int((memory_cost or target_memory) / 1500) * 1500
    kdf_t = time_cost or 1

    kdf_params = parameters.init_kdf_params(kdf_m=kdf_m, kdf_t=kdf_t)

    if time_cost is None:
        # time_cost estimated based on duration
        kdf_pfd_fn = ft.partial(kdf.kdf_params_for_duration, kdf_params, target_duration)
        return run_with_progress_bar(kdf_pfd_fn, eta_sec=8.5, init_progressbar=init_progressbar)
    else:
        return kdf_params


def init_params(
    target_duration : ct.Seconds,
    memory_cost     : Optional[ct.MebiBytes],
    time_cost       : Optional[ct.Iterations],
    threshold       : int,
    num_shares      : int,
    init_progressbar: Optional[InitProgressbar] = None,
) -> parameters.Parameters:
    if init_progressbar is None:
        _init_progressbar = fallback_progressbar("KDF Calibration")
    else:
        _init_progressbar = init_progressbar

    kdf_params = parse_kdf_params(
        target_duration,
        memory_cost,
        time_cost,
        init_progressbar=_init_progressbar,
    )
    return parameters.init_parameters(
        kdf_m=kdf_params.kdf_m,
        kdf_t=kdf_params.kdf_t,
        sss_x=1,
        sss_t=threshold,
        sss_n=num_shares,
    )


def validate_wallet_name(wallet_name: str) -> None:
    invalid_char_match = re.search(r"[^a-z0-9\-]", wallet_name)
    if invalid_char_match is None:
        return

    invalid_char = invalid_char_match.group(0)
    errmsg       = (
        f"\n\tInvalid value for --wallet-name='{wallet_name}'."
        + f"\n\tFirst Invalid character: '{invalid_char}'. "
        + "\n\tValid characters are a-z, 0-9 and '-'"
        + "\n"
    )
    raise ValueError(errmsg)


def encode_header_text(params: parameters.Parameters) -> str:
    params_data = parameters.validated_param_data(params)
    bk_header   = params_data[: parameters.BRANKEY_HEADER_LEN]
    return base64.b16encode(bk_header).decode("ascii")


def decode_header_text(header_text: str) -> parameters.Parameters:
    bk_header = base64.b16decode(header_text.lower().encode("ascii"))
    return parameters.bytes2params(bk_header)


def _check_entropy(raw_salt: bytes, brainkey: bytes) -> None:
    salt_min_entropy     = len(raw_salt) * 0.19 + 0.3
    brainkey_min_entropy = len(brainkey) * 0.19 + 0.3

    if sbk_random.entropy(raw_salt) < salt_min_entropy:
        entropy_avail = sbk_random.get_entropy_pool_size()
        errmsg        = f"Entropy check failed for salt. entropy_avail={entropy_avail}"
        raise AssertionError(errmsg)

    if sbk_random.entropy(brainkey) < brainkey_min_entropy:
        entropy_avail = sbk_random.get_entropy_pool_size()
        errmsg        = f"Entropy check failed for brainkey. entropy_avail={entropy_avail}"
        raise AssertionError(errmsg)


class Secrets(NamedTuple):

    brainkey: ct.BrainKey
    salt    : ct.Salt
    shares  : List[ct.Share]


def derive_salt(salt_phrase: str) -> ct.Salt:
    salt_data = sbk_random.argon2digest(
        salt_phrase.encode("utf-8"),
        hash_len=parameters.DEFAULT_RAW_SALT_LEN,
    )
    return ct.Salt(salt_data)


def derive_shares(
    params  : parameters.Parameters,
    salt    : ct.Salt,
    brainkey: ct.BrainKey,
    shareset: int,
) -> List[ct.Share]:
    shareset_data          = str(shareset).encode("ascii")
    shares_coeff_seed      = salt + shareset_data
    shares_coeff_generator = sbk_random.init_randrange(shares_coeff_seed)

    lens   = parameters.raw_secret_lens()
    raw_bk = brainkey[parameters.BRANKEY_HEADER_LEN :]

    shares = list(shamir.split(params, raw_bk, salt, make_coeff=shares_coeff_generator))

    brainkey_recovered, raw_salt_recovered = shamir.join(shares)

    # test encoding and recovery before we display secrets

    ic_brainkey = bytes2intcodes(brainkey)
    ic_shares   = [bytes2intcodes(share) for share in shares]

    phrase_brainkey = " ".join(intcodes2mnemonics(ic_brainkey))
    phrase_shares   = [" ".join(intcodes2mnemonics(ic_share)) for ic_share in ic_shares]

    checks = [
        brainkey == intcodes2bytes(ic_brainkey, lens.brainkey),
        brainkey == mnemonic.phrase2bytes(phrase_brainkey, lens.brainkey),
        brainkey == brainkey_recovered,
        salt     == raw_salt_recovered,
        shares   == [intcodes2bytes(ic_share, lens.share) for ic_share in ic_shares],
        shares   == [mnemonic.phrase2bytes(phrase_share, lens.share) for phrase_share in phrase_shares],
    ]

    is_recovery_ok = all(checks)

    if is_recovery_ok:
        return shares
    else:
        errmsg = "CRITICAL ERROR - Please report this at sbk.dev"
        raise ValueError(errmsg)


def create_secrets(
    params     : parameters.Parameters,
    salt_phrase: str,
    shareset   : int,
    *,
    gen_shares: bool = True,
) -> Secrets:
    params_data    = parameters.validated_param_data(params)
    bk_header_data = params_data[: parameters.BRANKEY_HEADER_LEN]

    bk_header = base64.b16encode(bk_header_data).decode('ascii')

    lens = parameters.raw_secret_lens()

    raw_bk   = sbk_random.urandom(lens.raw_brainkey)
    brainkey = ct.BrainKey(bk_header_data + raw_bk)

    salt = derive_salt(salt_phrase)

    if gen_shares:
        shares = derive_shares(params, salt, brainkey, shareset)
    else:
        shares = []

    return Secrets(brainkey, salt, shares)


def mk_tmp_wallet_fpath() -> pl.Path:
    # pylint: disable=broad-except; we log it, so it's ok :-P

    tempdir = tempfile.tempdir
    try:
        uid     = pwd.getpwnam(os.environ['USER']).pw_uid
        uid_dir = pl.Path(f"/run/user/{uid}")
        if uid_dir.exists():
            tempdir = str(uid_dir)
    except Exception as ex:
        logger.warning(f"Error creating temp directory in /run/user/ : {ex}")

    _fd, wallet_fpath_str = tempfile.mkstemp(prefix="sbk_electrum_wallet_", dir=tempdir)
    wallet_fpath = pl.Path(wallet_fpath_str)
    return wallet_fpath


def clean_wallet(wallet_fpath: pl.Path) -> None:
    if not os.path.exists(wallet_fpath):
        return

    garbage = os.urandom(4096)
    # On HDDs this may serve some marginal purpose.
    # On SSDs this may be pointless, because wear leveling means that these
    # write operations go to totally different blocks than the original file.
    size = wallet_fpath.stat().st_size
    with wallet_fpath.open(mode="wb") as fobj:
        for _ in range(0, size, 4096):
            fobj.write(garbage)
    wallet_fpath.unlink()
    assert not wallet_fpath.exists()


Command = List[str]


def seed_data2phrase(wallet_seed: ct.WalletSeed) -> ct.ElectrumSeed:
    seed_int = enc_util.bytes2int(wallet_seed)
    return electrum_mnemonic.raw_seed2phrase(seed_int)


def wallet_commands(wallet_seed: ct.WalletSeed, offline: bool = True) -> Tuple[pl.Path, Command, Command]:
    wallet_fpath = mk_tmp_wallet_fpath()

    restore_cmd = [
        "electrum",
        "restore",
        "--forgetconfig",
        "--wallet",
        str(wallet_fpath),
        "--offline",
        seed_data2phrase(wallet_seed),
    ]
    load_cmd = ["electrum", "gui", "--forgetconfig", "--wallet", str(wallet_fpath)]

    if offline:
        load_cmd.append("--offline")

    return (wallet_fpath, restore_cmd, load_cmd)


def load_wallet(wallet_seed: ct.WalletSeed, offline: bool = False) -> None:
    wallet_fpath, restore_cmd, load_cmd = wallet_commands(wallet_seed, offline)
    try:
        wallet_fpath.unlink()
        retcode = sp.call(restore_cmd)
        if retcode != 0:
            cmd_str = " ".join(restore_cmd[:-1] + ["<wallet seed hidden>"])
            errmsg  = f"Error calling '{cmd_str}' retcode: {retcode}"
            raise RuntimeError(errmsg)

        retcode = sp.call(load_cmd)
        if retcode != 0:
            cmd_str = " ".join(load_cmd)
            errmsg  = f"Error calling '{cmd_str}' retcode: {retcode}"
            raise RuntimeError(errmsg)
    finally:
        clean_wallet(wallet_fpath)
