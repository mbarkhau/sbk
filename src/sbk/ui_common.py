# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Common parsing, encoding and formatting functions for CLI and GUI."""

import os
import re
import pwd
import math
import time
import typing as typ
import logging
import pathlib as pl
import tempfile
import functools as ft
import threading
import subprocess as sp
import collections

import click
import mypy_extensions as mypyext

from . import kdf
from . import ecc_rs
from . import params
from . import shamir
from . import enc_util
from . import mnemonic
from . import sys_info
from . import common_types as ct
from . import electrum_mnemonic

logger = logging.getLogger("sbk.ui_common")


SECURITY_WARNING_TEXT = """
Security Warning

Please make sure:

 - You are the only person who can currently view your screen.
 - Your computer is not connected to any network.
 - Your computer is booted using a trusted installation of Linux.

For more information on setting up a secure air-gapped system
see: https://sbk.dev/airgap
"""

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

# NOTE (mb 2021-05-14): Probably not needed now that we have docs
RECOVERY_TEXT = r"""
Your Master Key is recovered by collecting a minimum of
{threshold} shares.

                 Split Master Key
             Split                 . Join
                   \.-> Share 1 -./
        Master Key -O-> Share 2  +-> Master Key
                    +-> Share 3 -|
                    +-> Share 4 -'
                    '-> Share 5

   argon2_kdf(Master Key, Wallet Name) -> Wallet
"""


SHARE_PROMPT_TMPL = """
When you have copied Share {share_no}/{num_shares}, press enter to continue.
"""

BRAINKEY_INFO_TEXT = """
Your Salt and Brainkey are combined to produce your wallet seed.
As long as you have access to your Salt and as long as you can
remember your Brainkey, you will can recover your wallet.

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


Lines = typ.Iterable[str]

PhraseLines = typ.Sequence[str]

PartIndex = int
PartVal   = bytes
PartVals  = typ.Sequence[PartVal]
# A PartVal can be b"" to mark its value is not known yet.


BYTES_PER_INTCODE = 2

IntCode       = str
IntCodes      = typ.Sequence[IntCode]
MaybeIntCode  = typ.Optional[IntCode]
MaybeIntCodes = typ.Sequence[MaybeIntCode]


def bytes2intcode_parts(data: bytes, idx_offset: int = 0) -> typ.Iterable[IntCode]:
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


def intcodes2mnemonics(intcodes: typ.Sequence[str]) -> typ.Sequence[str]:
    data_with_ecc = intcodes2parts(intcodes)
    parts         = data_with_ecc[: len(data_with_ecc) // 2]
    return mnemonic.bytes2phrase(b"".join(parts)).split()


def maybe_intcodes2bytes(intcodes: MaybeIntCodes, msg_len: int) -> bytes:
    data_with_ecc = intcodes2parts(intcodes)

    assert all(len(part) <= 1 for part in data_with_ecc)
    maybe_packets = [part[0] if part else None for part in data_with_ecc]
    return ecc_rs.decode_packets(maybe_packets, msg_len)


def intcodes2bytes(intcodes: IntCodes, msg_len: int) -> bytes:
    return maybe_intcodes2bytes(intcodes, msg_len=msg_len)


class ParsedSecret(typ.NamedTuple):
    words     : typ.Tuple[str    , ...]
    data_codes: typ.Tuple[IntCode, ...]
    ecc_codes : typ.Tuple[IntCode, ...]


def parse_formatted_secret(text: str, strict: bool = True) -> ParsedSecret:
    words     : typ.List[str    ] = []
    data_codes: typ.List[IntCode] = []
    ecc_codes : typ.List[IntCode] = []

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


class Scheme(typ.NamedTuple):

    threshold : int
    num_shares: int


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


T = typ.TypeVar('T')


class ThreadRunner(threading.Thread, typ.Generic[T]):

    _exception: typ.Optional[Exception]
    _return   : typ.Optional[T]

    def __init__(self, target: typ.Callable[[], T]) -> None:
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


Seconds = typ.NewType('Seconds', float)

DEFAULT_WALLET_NAME = "empty"

SEED_DATA_LEN = 16


class ProgressbarUpdater(typ.Protocol):
    def update(self, n_steps: int) -> None:
        ...

    def __enter__(self) -> typ.Any:
        ...

    def __exit__(self, exc_type, exc_value, tb) -> None:
        ...


InitProgressbar = typ.Callable[[mypyext.NamedArg(int, 'length')], ProgressbarUpdater]


class DummyProgressbar(ProgressbarUpdater):
    def __init__(self, length: int) -> None:
        super().__init__()

    def update(self, n_steps: int) -> None:
        pass

    def __enter__(self) -> typ.Any:
        return self

    def __exit__(self, exc_type, exc_value, tb) -> None:
        pass


def fallback_progressbar(label: str) -> InitProgressbar:
    if os.getenv('SBK_PROGRESS_BAR', "1") == '1':
        return ft.partial(click.progressbar, label=label, show_eta=True)
    else:
        return DummyProgressbar


def derive_seed(
    kdf_params      : kdf.KDFParams,
    salt            : ct.Salt,
    brainkey        : ct.BrainKey,
    label           : str,
    wallet_name     : str = DEFAULT_WALLET_NAME,
    init_progressbar: typ.Optional[InitProgressbar] = None,
) -> ct.SeedData:
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
            seed_data   = runner.start_and_join()
    else:
        # Always the ThreadRunner so that Ctrl-C is not blocked.
        runner    = ThreadRunner[bytes](digester_fn)
        seed_data = runner.start_and_join()
    return ct.SeedData(seed_data)


def run_with_progress_bar(
    target          : typ.Callable[[], T],
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
    target_duration : kdf.Seconds,
    parallelism     : typ.Optional[kdf.NumThreads],
    memory_cost     : typ.Optional[kdf.MebiBytes],
    time_cost       : typ.Optional[kdf.Iterations],
    init_progressbar: InitProgressbar,
) -> kdf.KDFParams:
    nfo        = sys_info.load_sys_info()
    kdf_params = kdf.init_kdf_params(
        p=parallelism or nfo.initial_p, m=memory_cost or nfo.initial_m, t=time_cost or 1
    )

    if time_cost is None:
        # time_cost estimated based on duration
        kdf_pfd_fn = ft.partial(kdf.kdf_params_for_duration, kdf_params, target_duration)
        return run_with_progress_bar(kdf_pfd_fn, eta_sec=5.5, init_progressbar=init_progressbar)
    else:
        return kdf_params


def init_param_config(
    target_duration  : kdf.Seconds,
    parallelism      : typ.Optional[kdf.NumThreads],
    memory_per_thread: typ.Optional[kdf.MebiBytes],
    time_cost        : typ.Optional[kdf.Iterations],
    threshold        : int,
    num_shares       : int,
    init_progressbar : typ.Optional[InitProgressbar] = None,
) -> params.ParamConfig:
    if init_progressbar is None:
        _init_progressbar = fallback_progressbar("KDF Calibration")
    else:
        _init_progressbar = init_progressbar

    kdf_params = parse_kdf_params(
        target_duration,
        parallelism,
        memory_per_thread,
        time_cost,
        init_progressbar=_init_progressbar,
    )
    param_cfg = params.init_param_config(
        threshold=threshold,
        num_shares=num_shares,
        kdf_params=kdf_params,
    )
    return param_cfg


def get_entropy_pool_size() -> int:
    path_linux = pl.Path("/proc/sys/kernel/random/entropy_avail")
    if path_linux.exists():
        with path_linux.open() as fobj:
            return int(fobj.read().strip())
    return -1


def urandom(size: int) -> bytes:
    if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
        # https://xkcd.com/221/
        return b"4" * size
    else:
        return os.urandom(size)


# https://stackoverflow.com/a/47348423/62997
def entropy(data: bytes) -> float:
    probabilities     = [n_x / len(data) for x, n_x in collections.Counter(data).items()]
    entropy_fractions = [-p_x * math.log(p_x, 2) for p_x in probabilities]
    return sum(entropy_fractions)


def _check_entropy(raw_salt: bytes, brainkey: bytes) -> None:
    # sanity check
    if entropy(raw_salt) < params.RAW_SALT_MIN_ENTROPY:
        entropy_avail = get_entropy_pool_size()
        errmsg        = f"Entropy check failed for salt. entropy_avail={entropy_avail}"
        raise AssertionError(errmsg)

    if entropy(brainkey) < params.BRAINKEY_MIN_ENTROPY:
        entropy_avail = get_entropy_pool_size()
        errmsg        = f"Entropy check failed for brainkey. entropy_avail={entropy_avail}"
        raise AssertionError(errmsg)


def validated_param_data(param_cfg: params.ParamConfig) -> bytes:
    # validate encoding round trip before we use param_cfg
    param_cfg_data    = params.param_cfg2bytes(param_cfg)
    decoded_param_cfg = params.bytes2param_cfg(param_cfg_data)
    checks            = {
        'threshold' : param_cfg.threshold  == decoded_param_cfg.threshold,
        'version'   : param_cfg.version    == decoded_param_cfg.version,
        'kdf_params': param_cfg.kdf_params == decoded_param_cfg.kdf_params,
    }
    bad_checks = [name for name, is_ok in checks.items() if not is_ok]
    if any(bad_checks):
        raise ValueError(bad_checks)
    else:
        return param_cfg_data


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


def create_secrets(param_cfg: params.ParamConfig) -> typ.Tuple[ct.Salt, ct.BrainKey, ct.Shares]:
    param_cfg_data = validated_param_data(param_cfg)

    raw_salt = ct.RawSalt(urandom(params.RAW_SALT_LEN))
    salt     = ct.Salt(param_cfg_data + raw_salt)
    brainkey = ct.BrainKey(urandom(params.BRAINKEY_LEN))

    if os.getenv('SBK_DEBUG_RANDOM') is None:
        _check_entropy(raw_salt, brainkey)

    shares = list(shamir.split(param_cfg, raw_salt, brainkey))

    raw_salt_recovered, brainkey_recovered = shamir.join(param_cfg, shares)

    is_recovery_ok = raw_salt_recovered == raw_salt and brainkey_recovered == brainkey
    if is_recovery_ok:
        return (salt, brainkey, shares)
    else:
        errmsg = "CRITICAL ERROR - Please report this at sbk.dev"
        raise ValueError(errmsg)


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


Command = typ.List[str]


def seed_data2phrase(seed_data: ct.SeedData) -> ct.ElectrumSeed:
    seed_int = enc_util.bytes2int(seed_data)
    return electrum_mnemonic.raw_seed2phrase(seed_int)


def wallet_commands(seed_data: ct.SeedData, offline: bool = True) -> typ.Tuple[pl.Path, Command, Command]:
    wallet_fpath = mk_tmp_wallet_fpath()

    restore_cmd = [
        "electrum",
        "restore",
        "--forgetconfig",
        "--wallet",
        str(wallet_fpath),
        "--offline",
        seed_data2phrase(seed_data),
    ]
    load_cmd = ["electrum", "gui", "--forgetconfig", "--wallet", str(wallet_fpath)]

    if offline:
        load_cmd.append("--offline")

    return (wallet_fpath, restore_cmd, load_cmd)


def load_wallet(seed_data: ct.SeedData, offline: bool = False) -> None:
    wallet_fpath, restore_cmd, load_cmd = wallet_commands(seed_data, offline)
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


def _debug_entropy_check() -> None:
    """Determine params.RAW_SALT_MIN_ENTROPY and params.BRAINKEY_MIN_ENTROPY ."""
    print(" N   MIN_E   low_e   headroom")

    a = 0.3
    b = 0.19

    for n in range(2, 13):
        min_e    = a + n * b
        fails    = 0
        low_e    = entropy(urandom(n))
        headroom = 999.0
        for _ in range(10_000):
            e = entropy(urandom(n))
            if e < low_e:
                low_e = (low_e + e) / 2
            if e < min_e:
                fails += 1

        headroom = low_e - min_e

        print(f"{n:>2} {min_e:7.3f} {low_e:7.3f} {headroom:7.3f} {fails:>6}")


if __name__ == '__main__':
    _debug_entropy_check()
