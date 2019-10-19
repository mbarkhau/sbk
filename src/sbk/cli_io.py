# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI input/output reading/printing functions."""

import re
import typing as typ

import click

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


def _prompt(text: str) -> str:
    return click.prompt(text)


InputType = str


INPUT_TYPE_PARAMS   = 'params'
INPUT_TYPE_SALT     = 'salt'
INPUT_TYPE_SHARE    = 'share'
INPUT_TYPE_BRAINKEY = 'brainkey'


MESSAGES = {
    INPUT_TYPE_PARAMS  : {'header': ""},
    INPUT_TYPE_SALT    : {'header': "Enter your 'Salt'"},
    INPUT_TYPE_SHARE   : {'header': ""},
    INPUT_TYPE_BRAINKEY: {'header': """Step 2 of 2: Enter your "Brainkey".\n\tEnter BrainKey"""},
}


def _parse_command(in_val: str) -> typ.Optional[str]:
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
Inputs = typ.List[cli_util.MaybeIntCode]
# Markers for which inputs were entered/accepted by user
Accepted = typ.List[bool]


class PromptState:

    input_type: InputType
    # data_len does not include ecc data
    data_len  : int
    num_inputs: int
    inputs    : Inputs
    accepted  : Accepted
    cursor    : int

    def __init__(
        self,
        input_type: InputType,
        data_len  : int,
        cursor    : int = 0,
        inputs    : typ.Optional[Inputs  ] = None,
        accepted  : typ.Optional[Accepted] = None,
    ) -> None:
        self.input_type: InputType = input_type
        self.data_len   = data_len
        self.num_inputs = data_len if self.has_intcode_inputs else data_len // 2
        self.cursor     = max(0, min(self.num_inputs - 1, cursor))

        if inputs is None:
            self.inputs = [None] * self.num_inputs
        else:
            assert len(inputs) == self.num_inputs
            self.inputs = inputs

        if accepted is None:
            self.accepted = [False] * self.num_inputs
        else:
            assert len(accepted) == self.num_inputs
            self.accepted = accepted

    @property
    def has_intcode_inputs(self) -> bool:
        return self.input_type != INPUT_TYPE_BRAINKEY

    @property
    def is_cursor_at_ecc(self) -> bool:
        return self.has_intcode_inputs and self.cursor >= self.num_inputs // 2

    @property
    def is_completable(self) -> bool:
        return all(self.inputs)

    @property
    def is_complete(self) -> bool:
        return all(self.inputs) and all(self.accepted)

    def result(self) -> bytes:
        assert self.is_complete
        if self.has_intcode_inputs:
            return cli_util.maybe_intcodes2bytes(self.inputs)
        else:
            return b"".join(cli_util.intcodes2parts(self.inputs))

    def _line_marker(self, idx: int) -> str:
        if self.has_intcode_inputs:
            marker_mod = self.num_inputs // 4
        else:
            marker_mod = self.num_inputs // 2

        marker_char = "ABCD"[idx // marker_mod]
        marker_id   = idx % marker_mod
        return f"{marker_char}{marker_id}"

    def message(self, key: str) -> str:
        if key == 'prompt':
            cursor_marker = self._line_marker(idx=self.cursor)
            if self.is_cursor_at_ecc:
                return f"Enter command or ecc code at {cursor_marker}"
            else:
                return f"Enter command, data code or words at {cursor_marker}"

        return MESSAGES[self.input_type][key]

    def _formatted_lines(self) -> typ.List[str]:
        num_lines = self.num_inputs // 2 if self.has_intcode_inputs else self.num_inputs
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

        if self.has_intcode_inputs:
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

    def formatted_inputs(self) -> str:
        lines = self._formatted_lines()
        out_lines: typ.List[str] = []

        for line_index, line in enumerate(lines):
            if line_index == len(lines) // 2:
                out_lines.append("")

            prefix = "   "
            suffix = ""
            if line_index == self.cursor:
                prefix = "=> "
            elif line_index == (self.cursor % len(lines)):
                suffix = " <="

            out_lines.append(prefix + line + suffix)

        return "\n".join(out_lines)

    def _copy(self, **overrides) -> 'PromptState':
        return PromptState(
            input_type=overrides.get('input_type', self.input_type),
            data_len=overrides.get('data_len', self.data_len),
            cursor=overrides.get('cursor', self.cursor),
            inputs=overrides.get('inputs', self.inputs),
            accepted=overrides.get('accepted', self.accepted),
        )

    def parse_input(self, in_val: str) -> 'PromptState':
        in_val, _ = re.subn(r"[^\w\s]", "", in_val.lower().strip())

        try:
            if re.match(r"^[\d\s]+$", in_val):
                in_data = b"".join(cli_util.intcodes2parts(in_val.split(), idx_offset=self.cursor))
            else:
                cmd = _parse_command(in_val)
                if cmd == 'accept':
                    return self._copy(accepted=[True] * self.num_inputs)
                if cmd == 'delete':
                    new_inputs   = list(self.inputs)
                    new_accepted = list(self.accepted)
                    new_inputs[self.cursor] = None
                    new_accepted[self.cursor] = False
                    return self._copy(
                        cursor=self.cursor + 1, inputs=new_inputs, accepted=new_accepted
                    )

                if cmd == 'next':
                    return self._copy(cursor=self.cursor + 1)
                if cmd == 'prev':
                    return self._copy(cursor=self.cursor - 1)
                if cmd == 'cancel':
                    raise click.Abort()

                in_data = mnemonic.phrase2bytes(in_val)
        except ValueError as err:
            _echo(f"{err}")
            return None

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
            if self.cursor + i >= self.num_inputs:
                _echo("Warning, too many inputs.")
                break

            in_intcode = cli_util.bytes2incode_part(pair, self.cursor + i)
            new_inputs[self.cursor + i] = in_intcode
            new_accepted[self.cursor + i] = True

        packet_len = self.data_len // 4

        packet0 = new_inputs[0 * packet_len : 1 * packet_len]
        packet1 = new_inputs[1 * packet_len : 2 * packet_len]
        packet2 = new_inputs[2 * packet_len : 3 * packet_len]
        packet3 = new_inputs[3 * packet_len : 4 * packet_len]

        is_ecc_deducable = (
            self.has_intcode_inputs
            and sum([all(packet0), all(packet1), all(packet2), all(packet3)]) >= 2
        )

        if is_ecc_deducable:
            try:
                recovered_data = cli_util.maybe_intcodes2bytes(new_inputs)
            except Exception as ex:
                _echo(f"Recovery failed, possibly invalid inputs. {ex}")
                return (new_inputs, new_accepted)

            expanded_intcodes = cli_util.bytes2intcodes(recovered_data)
            new_inputs        = [
                (new_input if accepted else expanded)
                for accepted, new_input, expanded in zip(
                    new_accepted, new_inputs, expanded_intcodes
                )
            ]

        return (new_inputs, new_accepted)


def prompt(input_type: str, data_len: int) -> bytes:
    prompt_state = PromptState(input_type, data_len)

    while True:
        _clear()
        _echo(prompt_state.message('header'))
        _echo()
        _echo(prompt_state.formatted_inputs())
        _echo()
        _echo("Available commands:")
        _echo()
        _echo("    C/Cancel: Cancel recovery")
        _echo("    P/Prev  : Move to previous code/words")
        _echo("    N/Next  : Move to next code/words")

        if prompt_state.inputs[prompt_state.cursor]:
            _echo("    D/Delete: Delete current input")
        if prompt_state.is_completable:
            _echo()
            _echo("    A/Accept: Accept input and continue")

        new_prompt_state: typ.Optional[PromptState] = None
        while new_prompt_state is None:
            _echo()
            in_val           = _prompt(prompt_state.message('prompt'))
            new_prompt_state = prompt_state.parse_input(in_val)

        if new_prompt_state.is_complete:
            return new_prompt_state.result()

        prompt_state = new_prompt_state


def main() -> None:
    data = prompt(INPUT_TYPE_BRAINKEY, 8)
    print("<<<<", enc_util.bytes_repr(data))
    _prompt("...")
    data = prompt(INPUT_TYPE_SALT, 12)
    print("<<<<", enc_util.bytes_repr(data))


if __name__ == '__main__':
    main()
