# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI input/output reading/printing functions."""

import re
import typing as typ

import click

from . import ecc_rs
from . import params
from . import cli_util
from . import enc_util
from . import mnemonic


def _echo(msg: str = "") -> bool:
    """Write message to stdout.

    The boolean return value is only to pacify mypy. To supress output when using the -y --yes-all,
    the following idiom is often used: `yes_all or _echo(message)`
    """
    click.echo(msg)
    return True


def _clear() -> bool:
    click.clear()
    return True


def _prompt(text: str, default: typ.Optional[str] = None) -> str:
    return click.prompt(text, default=default, show_default=False)


InputType = str


DATA_TYPE_SALT     = 'salt'
DATA_TYPE_SHARE    = 'share'
DATA_TYPE_BRAINKEY = 'brainkey'


MESSAGES = {
    DATA_TYPE_SALT    : {'header': 'Enter "Salt"'},
    DATA_TYPE_SHARE   : {'header': 'Enter "Share"'},
    DATA_TYPE_BRAINKEY: {'header': 'Enter "Brainkey"'},
}


MaybeCommand = typ.Optional[str]


def _parse_command(in_val: str) -> MaybeCommand:
    in_val = in_val.strip().lower()
    if in_val in ('a', 'accept'):
        return 'accept'
    elif in_val in ('d', 'delete'):
        return 'delete'
    elif in_val in ('c', 'cancel', 'e', 'exit'):
        return 'cancel'
    elif in_val in ('p', 'prev'):
        return 'prev'
    elif in_val in ('n', 'next'):
        return 'next'
    else:
        return None


# Decoded inputs
Inputs      = typ.List[cli_util.MaybeIntCode]
MaybeInputs = typ.Optional[Inputs]

# Markers for which inputs were entered/accepted by user
Accepted = typ.List[bool]


def _init_blank_inputs(
    data_type: str, data_len: typ.Optional[int] = None,
) -> typ.Tuple[Inputs, int]:
    assert not (data_type == DATA_TYPE_BRAINKEY and data_len is None)

    num_inputs: int = 0
    if data_len is None:
        if data_type == DATA_TYPE_SALT:
            data_len_guess = params.SALT_LEN
        elif data_type == DATA_TYPE_SHARE:
            data_len_guess = params.DEFAULT_SHARE_LEN
        else:
            errmsg = f"PromtState.data_len not implemented for data_type={data_type}"
            raise NotImplementedError(errmsg)
    else:
        data_len_guess = data_len

    # round up if there are an uneven number of inputs (eg for shares)
    num_inputs = ((data_len_guess + 1) // 2) * 2
    assert num_inputs > 0
    assert num_inputs % 2 == 0

    blank_inputs: Inputs = [None] * num_inputs
    return (blank_inputs, data_len_guess)


def _parse_share_len(inputs: Inputs) -> int:
    # parse data_len from first field of param_cfg
    parts = cli_util.intcodes2parts(inputs[:1])
    data  = b"".join(parts)
    assert len(data) == 2
    dummy_kdf_data = b"\x00\x00"
    param_cfg      = params.bytes2param_cfg(data + dummy_kdf_data)
    return (
        params.PARAM_CFG_LEN
        + params.SHARE_X_COORD_LEN
        + params.RAW_SALT_LEN
        + param_cfg.brainkey_len
    )


def _newline_mod(num_lines: int) -> int:
    if num_lines < 6:
        newline_mod = 99
    else:
        newline_mod = (num_lines + 1) // 2
        # newline_mod = 3
        # for n in range(3, 6):
        #     if num_lines % n == 0 or 0 < num_lines % newline_mod < num_lines % n:
        #         newline_mod = n
    return newline_mod


class PromptState:

    data_type: InputType
    data_len : int
    inputs   : Inputs
    accepted : Accepted
    cursor   : int

    def __init__(
        self,
        data_type: InputType,
        data_len : int,
        inputs   : Inputs,
        cursor   : int = 0,
        accepted : typ.Optional[Accepted] = None,
    ) -> None:
        self.data_type = data_type
        self.data_len  = data_len
        assert len(inputs) % 2 == 0

        if accepted is None:
            _accepted = [False] * len(inputs)
        else:
            _accepted = accepted

        self.inputs = inputs
        self.cursor = max(0, min(len(self.inputs) - 1, cursor))
        assert len(_accepted) == len(self.inputs)
        self.accepted = _accepted

    @property
    def is_cursor_at_ecc(self) -> bool:
        return self.cursor >= len(self.inputs) // 2

    @property
    def is_completable(self) -> bool:
        return all(self.inputs)

    @property
    def is_complete(self) -> bool:
        return all(self.inputs) and all(self.accepted)

    @property
    def result(self) -> bytes:
        assert self.is_complete
        return cli_util.maybe_intcodes2bytes(self.inputs, msg_len=self.data_len)

    def _line_marker(self, idx: int) -> str:
        return f"{idx + 1:02}"

    def message(self, key: str) -> str:
        if key == 'prompt':
            cursor_marker = self._line_marker(idx=self.cursor)
            if self.is_completable:
                if self.is_cursor_at_ecc:
                    return f"Enter code at {cursor_marker} (or Enter to Accept)"
                else:
                    return f"Enter code/words at {cursor_marker}"
            else:
                if self.is_cursor_at_ecc:
                    return f"Enter code at {cursor_marker}"
                else:
                    return f"Enter code/words at {cursor_marker}"

        return MESSAGES[self.data_type][key]

    def _formatted_lines(self) -> typ.List[str]:
        num_lines = len(self.inputs) // 2
        lines     = [""] * num_lines

        # data intcodes
        for line_index, maybe_intcode in enumerate(self.inputs[:num_lines]):
            if maybe_intcode is None:
                intcode = "___-___"
            else:
                intcode = maybe_intcode

            marker = self._line_marker(line_index)
            lines[line_index] += marker + ": " + intcode

        for line_index, maybe_intcode in enumerate(self.inputs[:num_lines]):
            if maybe_intcode is None:
                dummy_word = "_" * 9
                words      = dummy_word + " " + dummy_word
            else:
                parts = cli_util.intcodes2parts([maybe_intcode], idx_offset=line_index)
                words = mnemonic.bytes2phrase(b"".join(parts))

            lines[line_index] += "   " + words + "   "

        # ecc intcodes
        for line_index, maybe_intcode in enumerate(self.inputs[num_lines:]):
            idx_offset = num_lines + line_index
            if maybe_intcode is None:
                intcode = "___-___"
            else:
                intcode = maybe_intcode

            marker = self._line_marker(idx_offset)
            lines[line_index] += marker + ": " + intcode + " "

        return lines

    def _iter_out_lines(self, show_cursor: bool) -> typ.Iterator[str]:
        lines       = self._formatted_lines()
        newline_mod = _newline_mod(len(lines))

        for line_index, line in enumerate(lines):
            if line_index > 0 and line_index % newline_mod == 0:
                yield ""

            prefix = "   "
            suffix = ""

            if show_cursor:
                if line_index == self.cursor:
                    prefix = "=> "
                elif line_index == (self.cursor % len(lines)):
                    suffix = "<="

            yield prefix + line + suffix

    def formatted_input_lines(self, show_cursor: bool = True) -> typ.List[str]:
        header = f"       {'Data':^7}   {'Mnemonic':^18}        {'ECC':^7}"
        if show_cursor:
            header = "   " + header

        return [header] + list(self._iter_out_lines(show_cursor))

    def _copy(self, **overrides) -> 'PromptState':
        return PromptState(
            data_type=overrides.get('data_type', self.data_type),
            data_len=overrides.get('data_len', self.data_len),
            cursor=overrides.get('cursor', self.cursor),
            inputs=overrides.get('inputs', self.inputs),
            accepted=overrides.get('accepted', self.accepted),
        )

    def resize_to(self, data_len: int) -> 'PromptState':
        if self.data_len == data_len:
            return self

        new_inputs, _ = _init_blank_inputs(self.data_type, data_len)
        new_accepted = [False] * len(new_inputs)

        # copy over as many previous inputs as possible
        for i in range(min(len(new_inputs), len(self.inputs))):
            new_inputs[i] = self.inputs[i]
            new_accepted[i] = self.accepted[i]

        return self._copy(data_len=data_len, inputs=new_inputs, accepted=new_accepted)

    def _eval_cmd(self, cmd: str) -> 'PromptState':
        if cmd == 'accept':
            return self._copy(accepted=[True] * len(self.inputs))
        if cmd == 'delete':
            new_inputs   = list(self.inputs)
            new_accepted = list(self.accepted)
            new_inputs[self.cursor] = None
            new_accepted[self.cursor] = False
            return self._copy(cursor=self.cursor + 1, inputs=new_inputs, accepted=new_accepted)

        if cmd == 'next':
            return self._copy(cursor=self.cursor + 1)
        if cmd == 'prev':
            return self._copy(cursor=self.cursor - 1)
        if cmd == 'cancel':
            raise click.Abort()

        raise Exception(f"Invalid command {cmd}")

    def parse_input(self, in_val: str) -> typ.Optional['PromptState']:
        in_val, _ = re.subn(r"[^\w\s]", "", in_val.lower().strip())
        cmd: MaybeCommand = None

        try:
            if re.match(r"^[\d\s]+$", in_val):
                parts   = list(re.findall(r"\d{6}", in_val))
                in_data = b"".join(cli_util.intcodes2parts(parts, idx_offset=self.cursor))
            else:
                if len(in_val.strip()) == 0 and self.is_completable and self.is_cursor_at_ecc:
                    cmd = 'accept'
                else:
                    cmd = _parse_command(in_val)
                if cmd is None:
                    in_data = mnemonic.phrase2bytes(in_val)
                else:
                    return self._eval_cmd(cmd)
        except ValueError as err:
            _echo()
            errmsg = getattr(err, 'args', [str(err)])[0]
            _echo(f"    Error - {errmsg}")
            return None

        if len(in_data) < 2:
            _echo("Invalid data length")
            return None

        if len(in_data) % 2 != 0:
            in_data = in_data[:-1]

        new_inputs, new_accepted = self._updated_input_data(in_data)
        new_cursor = self.cursor + (len(in_data) // 2)
        assert isinstance(new_inputs, list)
        assert all(elem is None or isinstance(elem, str) for elem in new_inputs)

        return self._copy(cursor=new_cursor, inputs=new_inputs, accepted=new_accepted)

    def _updated_input_data(self, in_data: bytes) -> typ.Tuple[Inputs, Accepted]:
        new_accepted = list(self.accepted)
        new_inputs   = [
            (input_value if accepted else None)
            for input_value, accepted in zip(self.inputs, self.accepted)
        ]
        pairs = [in_data[i : i + 2] for i in range(0, len(in_data), 2)]
        for i, pair in enumerate(pairs):
            if self.cursor + i >= len(self.inputs):
                _echo("Warning, too many inputs.")
                break

            in_intcode = cli_util.bytes2incode_part(pair, self.cursor + i)
            new_inputs[self.cursor + i] = in_intcode
            new_accepted[self.cursor + i] = True

        input_data_len = sum(2 for maybe_intcode in new_inputs if maybe_intcode)
        is_recoverable = input_data_len >= self.data_len

        if not is_recoverable:
            return (new_inputs, new_accepted)

        try:
            recovered_data     = cli_util.maybe_intcodes2bytes(new_inputs, msg_len=self.data_len)
            recovered_intcodes = cli_util.bytes2intcodes(recovered_data)

            new_inputs = [
                (new_input if accepted else recovered)
                for accepted, new_input, recovered in zip(
                    new_accepted, new_inputs, recovered_intcodes
                )
            ]
        except ecc_rs.ECCDecodeError as err:
            _echo(f"Recovery failed, possibly invalid inputs. {err}")

        return (new_inputs, new_accepted)


def format_secret_lines(data_type: str, data: bytes) -> typ.Sequence[str]:
    intcodes     = list(cli_util.bytes2intcodes(data))
    inputs       = typ.cast(Inputs, intcodes)
    prompt_state = PromptState(data_type, len(data), inputs)
    return prompt_state.formatted_input_lines(show_cursor=False)


def format_secret(data_type: str, data: bytes) -> str:
    return "\n".join(format_secret_lines(data_type, data))


def prompt(
    data_type: str, header_text: typ.Optional[str] = None, data_len: typ.Optional[int] = None,
) -> bytes:
    blank_inputs, data_len_guess = _init_blank_inputs(data_type, data_len)
    current_ps = PromptState(data_type, data_len_guess, blank_inputs)

    if header_text is None:
        _header_text = current_ps.message('header')
    else:
        _header_text = header_text

    while True:
        _clear()
        _echo(f"{_header_text:^50}")
        _echo()
        _echo("\n".join(current_ps.formatted_input_lines()))
        _echo()
        _echo("Available commands:")
        _echo()
        _echo("    C/Cancel: Cancel recovery")
        _echo("    P/Prev  : Move to previous code/words")
        _echo("    N/Next  : Move to next code/words")

        if current_ps.inputs[current_ps.cursor]:
            _echo("    D/Delete: Delete current input")
        if current_ps.is_completable:
            _echo()
            _echo("    A/Accept: Accept input and continue")

        new_ps: typ.Optional[PromptState] = None
        while new_ps is None:
            _echo()
            in_val = _prompt(current_ps.message('prompt'), default="")
            new_ps = current_ps.parse_input(in_val)

        if new_ps.is_complete:
            return new_ps.result

        if data_type == DATA_TYPE_SHARE and new_ps.inputs[0]:
            share_data_len = _parse_share_len(new_ps.inputs)
            new_ps         = new_ps.resize_to(share_data_len)

        current_ps = new_ps


def main() -> None:
    data = prompt(DATA_TYPE_SHARE)
    print("<<<<", enc_util.bytes_repr(data))

    data = prompt(DATA_TYPE_SALT)
    print("<<<<", enc_util.bytes_repr(data))
    _prompt("...", default="")

    data = prompt(DATA_TYPE_BRAINKEY, data_len=params.DEFAULT_BRAINKEY_LEN)
    print("<<<<", enc_util.bytes_repr(data))
    _prompt("...", default="")


if __name__ == '__main__':
    main()
