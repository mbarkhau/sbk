#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

# messy ui code is messy ...
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-return-statements

"""GUI Baseclasses for Panels of SBK."""
import os
import time
import typing as typ
import logging

import PyQt5.Qt as qt
import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc
import PyQt5.QtWidgets as qtw
import typing_extensions as typext

from . import cli_io
from . import ecc_rs
from . import params
from . import mnemonic
from . import sys_info
from . import ui_common
from . import common_types as ct

logger = logging.getLogger("sbk.gui_panels")

PanelState = typext.TypedDict(
    'PanelState',
    {
        'panel_index': int,
        'salt'       : typ.Optional[ct.Salt],
        'brainkey'   : typ.Optional[ct.BrainKey],
        'shares'     : ct.Shares,
        'param_cfg'  : typ.Optional[params.ParamConfig],
        'seed_data'  : typ.Optional[ct.SeedData],
        # options
        'sys_info'         : typ.Optional[sys_info.SystemInfo],
        'offline'          : bool,
        'wallet_name'      : str,
        'threshold'        : int,
        'num_shares'       : int,
        'target_memory'    : int,
        'target_duration'  : int,
        'max_parallelism'  : int,
        'parallelism'      : int,
        'max_memory'       : int,
        'memory_per_thread': int,
    },
)

shared_panel_state: PanelState = {
    'panel_index': 0,
    'salt'       : None,
    'brainkey'   : None,
    'shares'     : [],
    'param_cfg'  : None,
    'seed_data'  : None,
    # options
    'sys_info'         : None,
    'offline'          : True,
    'wallet_name'      : "empty",
    'threshold'        : params.DEFAULT_THRESHOLD,
    'num_shares'       : params.DEFAULT_NUM_SHARES,
    'target_memory'    : -1,
    'target_duration'  : params.DEFAULT_KDF_TARGET_DURATION,
    'max_parallelism'  : -1,
    'parallelism'      : -1,
    'max_memory'       : -1,
    'memory_per_thread': -1,
}


def has_secrets() -> bool:
    return bool(shared_panel_state['salt'] and shared_panel_state['brainkey'])


def get_param_cfg() -> typ.Optional[params.ParamConfig]:
    return shared_panel_state['param_cfg']


def get_state() -> PanelState:
    state = shared_panel_state
    if state['sys_info'] is None:
        _sys_info = sys_info.init_sys_info()
        state['sys_info'] = _sys_info
        parallelism    = _sys_info.num_cores * 2
        default_memory = _sys_info.initial_m * _sys_info.initial_p

        state['parallelism'      ] = parallelism
        state['max_parallelism'  ] = _sys_info.num_cores * 4
        state['target_memory'    ] = default_memory
        state['memory_per_thread'] = round(default_memory / parallelism)
        state['max_memory'       ] = _sys_info.total_mb
    return state


class CurrentSecret(typ.NamedTuple):

    secret_len : int
    secret_type: str
    secret_data: bytes


def get_label_text() -> str:
    num_shares  = len(shared_panel_state['shares'])
    panel_index = shared_panel_state['panel_index']
    if panel_index < num_shares:
        share_no = panel_index + 1
        return f"Verify Share {share_no}/{num_shares}"
    elif panel_index == num_shares:
        return "Verify Salt"
    else:
        return "Verify Brainkey"


def get_current_secret() -> CurrentSecret:
    shares     = shared_panel_state['shares']
    num_shares = len(shares)

    panel_index = shared_panel_state['panel_index']
    if panel_index < num_shares:
        return CurrentSecret(
            secret_len=params.SHARE_LEN,
            secret_type=cli_io.SECRET_TYPE_SHARE,
            secret_data=shares[panel_index],
        )
    elif panel_index == num_shares:
        return CurrentSecret(
            secret_len=params.SALT_LEN,
            secret_type=cli_io.SECRET_TYPE_SALT,
            secret_data=shared_panel_state['salt'],  # type: ignore
        )
    else:
        return CurrentSecret(
            secret_len=params.BRAINKEY_LEN,
            secret_type=cli_io.SECRET_TYPE_BRAINKEY,
            secret_data=shared_panel_state['brainkey'],  # type: ignore
        )


def get_padded_secret() -> bytes:
    # NOTE (mb 2021-06-11): In the case of secrets with odd length, we must
    #   go through the ecc generation (part of bytes2intcodes) so that we
    #   can get ecc data that is used as padding in the mnemonic phrase.
    secret       = get_current_secret()
    intcodes     = ui_common.bytes2intcodes(secret.secret_data)
    data_and_ecc = b"".join(ui_common.intcodes2parts(intcodes))
    if data_and_ecc[: secret.secret_len] == secret.secret_data:
        return data_and_ecc
    else:
        raise AssertionError("Integrity check failed")


FIXED_FONT = qtg.QFontDatabase.systemFont(qtg.QFontDatabase.FixedFont)


class Panel(qtw.QWidget):
    def __init__(self, index: int):
        super().__init__()
        self.index = index

    def switch(self) -> None:
        self.parent().setWindowTitle(self.title)
        self.parent().setCurrentIndex(self.index)

    def trace(self, message: str) -> None:
        instance_idx = self.index
        panel_idx    = shared_panel_state['panel_index']
        prefix       = f"{type(self).__name__:>30}[{instance_idx}, {panel_idx}] - "
        logger.debug(prefix + message)


class NavigablePanel(Panel):

    # self.back_panel_clazz
    # self.next_panel_clazz

    def __init__(self, index: int):
        self.back_button = qtw.QPushButton("&Back")
        self.next_button = qtw.QPushButton("&Next")
        self.back_button.clicked.connect(self.nav_handler('back'))
        self.next_button.clicked.connect(self.nav_handler('next'))

        self.nav_layout = qtw.QHBoxLayout()
        self.nav_layout.addWidget(self.back_button)
        self.nav_layout.addWidget(self.next_button)

        super().__init__(index)

    def destroy_panel(self) -> None:
        # optionally override in subclass
        pass

    def is_final_panel(self) -> bool:
        # pylint: disable=no-self-use   # ABC default implementation
        return False

    def nav_handler(self, eventtype: str) -> typ.Callable:
        def handler() -> None:
            self.destroy_panel()
            p = self.parent()
            if eventtype == 'back':
                p.get_or_init_panel(self.back_panel_clazz).switch()
            elif eventtype == 'next':
                next_panel = p.get_or_init_panel(self.next_panel_clazz)
                if isinstance(next_panel, NavigablePanel):
                    if next_panel.is_final_panel():
                        next_panel.next_button.setText("&Finish")
                    else:
                        next_panel.next_button.setText("&Next")
                next_panel.switch()
            else:
                raise NotImplementedError(f"Invalid eventtype: {eventtype}")

        return handler

    def set_nav(self, pack_enabled: bool, next_enabled: bool) -> None:
        self.back_button.setEnabled(pack_enabled)
        self.next_button.setEnabled(next_enabled)


class IntCodeEdit(qtw.QLineEdit):
    def event(self, event) -> bool:
        if self.hasSelectedText():
            return super().event(event)

        if event.type() != qtc.QEvent.KeyPress:
            return super().event(event)

        mod = event.modifiers()
        if mod & (qtc.Qt.ControlModifier | qtc.Qt.AltModifier | qtc.Qt.ShiftModifier):
            return super().event(event)

        key  = event.key()
        text = self.text().strip()
        if key == qtc.Qt.Key_Backspace:
            super().setText(text[:-1])
            return True

        num_val = event.text().strip()
        if len(num_val) == 1 and num_val.isdigit():
            self.setText(text + num_val)
            return True

        is_accepted = key in (qtc.Qt.Key_Enter, qtc.Qt.Key_Return, qtc.Qt.Key_Tab)
        if is_accepted and self.is_valid():
            self.parent().autofill(accept_intcode=self.idx())

        return super().event(event)

    def setText(self, text) -> None:
        text = text.replace("-", "")
        if len(text) >= 3:
            return super().setText(text[:3] + "-" + text[3:])
        else:
            return super().setText(text)

    def idx(self) -> int:
        try:
            parent: EnterSecretPanel = self.parent()  # type: ignore
            return parent.intcode_widgets.index(self)
        except ValueError:
            # may happen during panel switch
            return -1

    def is_valid(self) -> bool:
        text = self.text().replace("-", "")
        return len(text) == 0 or (len(text) == 6 and text.isdigit())

    def focusOutEvent(self, event) -> None:
        self.parent().autofill(accept_intcode=self.idx())
        return super().focusOutEvent(event)

    def focusInEvent(self, event) -> None:
        self.parent().track_focus('intcode', self.idx())
        self.setStyleSheet("")
        return super().focusInEvent(event)


class MnemonicEdit(qtw.QLineEdit):
    def event(self, event) -> bool:
        if event.type() != qtc.QEvent.KeyPress:
            p = self.parent()
            return super().event(event)

        key = event.key()

        if key == qtc.Qt.Key_Backtab:
            p = self.parent()
            if self is p.mnemonic_widgets[0]:
                p.intcode_widgets[0].setFocus(True)
                return True

        is_accepted = key in (qtc.Qt.Key_Enter, qtc.Qt.Key_Return, qtc.Qt.Key_Tab)
        if is_accepted and len(self.text().strip()) > 0:
            completer = self.completer()
            popup     = completer.popup()

            completer_val = completer.currentIndex().data()
            popup_val     = popup.currentIndex().data()
            if popup_val is None:
                selected_val = completer_val
            else:
                selected_val = popup_val

            if selected_val:
                p = self.parent()
                self.setText(selected_val)
                next_idx = p.mnemonic_widgets.index(self) + 1
                if next_idx < len(p.mnemonic_widgets):
                    p.mnemonic_widgets[next_idx].setFocus(True)
                    return True

        return super().event(event)

    def idx(self) -> int:
        try:
            parent: EnterSecretPanel = self.parent()  # type: ignore
            return parent.mnemonic_widgets.index(self)
        except ValueError:
            # may happen during panel switch
            return -1

    def is_valid(self) -> bool:
        p   = self.parent()
        idx = p.mnemonic_widgets.index(self)

        try:
            expected_byte = p.current_secret().secret_data[idx : idx + 1]
            expected_word = mnemonic.byte2word(expected_byte)
        except ValueError:
            return False

        word = self.text().strip()
        return len(word) == 0 or word == expected_word

    def focusOutEvent(self, event) -> None:
        self.parent().autofill(accept_mnemonic=self.idx())
        return super().focusOutEvent(event)

    def focusInEvent(self, event) -> None:
        self.parent().track_focus('mnemonic', self.idx())
        self.setStyleSheet("")
        return super().focusInEvent(event)


def _label_widget(parent: Panel, text: str) -> qtw.QLabel:
    label = qtw.QLabel(text, parent)
    label.setAlignment(qtc.Qt.AlignCenter)
    label.setFont(FIXED_FONT)
    return label


def _set_styles(line_edit: qtw.QLineEdit, max_length: int) -> None:
    line_edit.setAlignment(qtc.Qt.AlignCenter)
    line_edit.setFont(FIXED_FONT)
    line_edit.setMaxLength(max_length)
    line_edit.setFixedWidth(max_length * 22)
    # line_edit.setStyleSheet("background-color: #F44;")


def _intcode_widget(parent: Panel, initial_text: str) -> IntCodeEdit:
    widget = IntCodeEdit(parent)
    widget.setText(initial_text)
    widget.setPlaceholderText("000-000")

    regexp    = qt.QRegExp(r"([0-9]{,4}|[0-9]{3}-[0-9]{,3})", qt.Qt.CaseInsensitive)
    validator = qtg.QRegExpValidator(regexp, widget)
    widget.setValidator(validator)

    _set_styles(widget, max_length=7)
    return widget


def _mnemonic_widget(parent: Panel, initial_text: str) -> MnemonicEdit:
    widget = MnemonicEdit(parent)
    widget.setText(initial_text)
    widget.setPlaceholderText("-")

    regexp    = qt.QRegExp(r"[a-zA-Z]{5,8}", qt.Qt.CaseInsensitive)
    validator = qtg.QRegExpValidator(regexp, widget)
    widget.setValidator(validator)

    completer = qtw.QCompleter(mnemonic.WORDLIST, parent=widget)
    completer.setCaseSensitivity(qt.Qt.CaseInsensitive)
    completer.setFilterMode(qt.Qt.MatchContains)
    widget.setCompleter(completer)
    if initial_text:
        completer.setCompletionPrefix(initial_text)

    _set_styles(widget, max_length=8)
    return widget


def header_widget() -> qtw.QLabel:
    header = qtw.QLabel()
    font   = header.font()
    font.setPointSize(14)
    font.setBold(True)
    header.setFont(font)
    header.setAlignment(qtc.Qt.AlignCenter)
    return header


MaybeBytes = typ.Union[bytes, None]


def _parse_intcodes(datas: typ.Sequence[MaybeBytes]) -> typ.Iterable[ui_common.MaybeIntCode]:
    for i in range(0, len(datas), 2):
        idx = i // 2
        if i + 2 <= len(datas):
            d1, d2 = datas[i : i + 2]
            if d1 and d2:
                intcode = ui_common.bytes2incode_part(d1 + d2, idx_offset=idx)
                yield intcode
            else:
                yield None
        else:
            yield None


def _parse_mnemonics(datas: typ.Sequence[MaybeBytes]) -> typ.Iterable[typ.Optional[str]]:
    for data in datas:
        if data:
            yield mnemonic.byte2word(data)
        else:
            yield None


def _recover_datas(valid_datas: typ.Sequence[MaybeBytes], msg_len: int) -> typ.Sequence[MaybeBytes]:
    valid_data_len = sum(1 for vd in valid_datas if vd)
    is_recoverable = valid_data_len >= msg_len

    if is_recoverable:
        try:
            maybe_packets = [part[0] if part else None for part in valid_datas]
            result        = ecc_rs.decode_packets(maybe_packets, msg_len)
            return [result[i : i + 1] for i in range(len(result))]
        except ecc_rs.ECCDecodeError as err:
            logger.error(f"Recovery failed, possibly invalid inputs. {err}")
            return valid_datas
    else:
        return valid_datas


class EnterSecretPanel(NavigablePanel):

    widget_states   : typ.Dict[int, typ.Dict[str, typ.Any]]
    grid_widgets    : typ.List[qtw.QWidget]
    intcode_widgets : typ.List[IntCodeEdit]
    mnemonic_widgets: typ.List[MnemonicEdit]

    def __init__(self, index: int):
        super().__init__(index)

        self.widget_states = {}

        self.grid_widgets     = []
        self.intcode_widgets  = []
        self.mnemonic_widgets = []

        self.header      = header_widget()
        self.grid_layout = qtw.QGridLayout()

        column_headers = qtw.QHBoxLayout()
        column_headers.addStretch(6 + 9)
        column_headers.addWidget(_label_widget(self, "Data"    ), 21 - 9)
        column_headers.addWidget(_label_widget(self, "Mnemonic"), 24 * 2)
        column_headers.addWidget(_label_widget(self, "ECC"     ), 21 - 1)
        column_headers.addStretch(6 + 1)

        self._layout = qtw.QVBoxLayout()
        self._layout.addWidget(self.header)
        self._layout.addStretch(1)
        self._layout.addLayout(column_headers)
        self._layout.addLayout(self.grid_layout)
        self._layout.addStretch(3)

        self._layout.addLayout(self.nav_layout)
        self.setLayout(self._layout)

    def track_focus(self, widget_type: str, widget_index: int) -> None:
        self.trace(f"track_focus {type(self).__name__} {widget_type} {widget_index}")
        state = self.get_or_init_state()
        state['widget_type' ] = widget_type
        state['widget_index'] = widget_index

    def label_text(self) -> str:
        raise NotImplementedError()

    def secret_len(self) -> int:
        raise NotImplementedError()

    def get_or_init_state(self) -> typ.Dict[str, typ.Any]:
        # NOTE (mb 2021-06-04): This whole state business may well be an artifact
        #   of (ab)using the Panel classes in NavigablePanel.nav_handler
        idx = shared_panel_state['panel_index']
        if idx in self.widget_states:
            return self.widget_states[idx]
        else:
            msg_len    = self.secret_len()
            num_inputs = msg_len
            if num_inputs % 2 != 0:
                num_inputs += 1

            self.widget_states[idx] = {
                'header_text'   : self.label_text(),
                'num_inputs'    : num_inputs,
                'msg_len'       : msg_len,
                'widget_type'   : 'mnemonic',
                'widget_index'  : 0,
                'intcode_texts' : [""] * num_inputs,
                'mnemonic_texts': [""] * num_inputs,
                # widget index -> timestamp
                'intcodes_accepted' : [0] * num_inputs,
                'mnemonics_accepted': [0] * num_inputs,
            }
            self.trace(f"init widgets state: {self.widget_states[idx]}")
            return self.widget_states[idx]

    def switch(self) -> None:
        self.trace(f"switch {type(self).__name__} {shared_panel_state['panel_index']}")
        state = self.get_or_init_state()

        self.header.setText(state['header_text'])

        # initialize state from packious usage
        for i in range(state['num_inputs']):
            if state['intcode_texts']:
                initial_intcode_text = state['intcode_texts'][i]
            else:
                initial_intcode_text = ""

            if state['mnemonic_texts']:
                initial_mnemonic_text = state['mnemonic_texts'][i]
            else:
                initial_mnemonic_text = ""

            intcode_widget  = _intcode_widget(self, initial_intcode_text)
            mnemonic_widget = _mnemonic_widget(self, initial_mnemonic_text)

            self.intcode_widgets.append(intcode_widget)
            self.mnemonic_widgets.append(mnemonic_widget)

        for i in range(1, state['num_inputs']):
            iw1 = self.intcode_widgets[i - 1]
            iw2 = self.intcode_widgets[i]
            self.setTabOrder(iw1, iw2)

        for i in range(1, state['num_inputs']):
            mw1 = self.mnemonic_widgets[i - 1]
            mw2 = self.mnemonic_widgets[i]
            self.setTabOrder(mw1, mw2)

        num_rows = state['num_inputs'] // 2
        for row in range(num_rows):
            row_num_left  = (row % num_rows) + 1
            row_num_right = (row % num_rows) + num_rows + 1

            row_widgets = [
                _label_widget(self, ""),  # 0
                _label_widget(self, f"{row_num_left:02}:"),  # 1
                self.intcode_widgets[row],  # 2
                _label_widget(self, ""),  # 3
                self.mnemonic_widgets[row * 2],  # 4
                _label_widget(self, ""),  # 5
                self.mnemonic_widgets[row * 2 + 1],  # 6
                _label_widget(self, ""),  # 7
                _label_widget(self, f"{row_num_right:02}:"),  # 8
                self.intcode_widgets[row + num_rows],  # 9
                _label_widget(self, ""),  # 10
            ]

            for col, widget in enumerate(row_widgets):
                self.grid_layout.addWidget(widget, row, col)

            # for cleanup later
            self.grid_widgets.extend(row_widgets)

        self.grid_layout.setColumnStretch( 0,  2)
        self.grid_layout.setColumnStretch( 1,  0)
        self.grid_layout.setColumnStretch( 2, 21)
        self.grid_layout.setColumnStretch( 3,  1)
        self.grid_layout.setColumnStretch( 4, 24)
        self.grid_layout.setColumnStretch( 5,  0)
        self.grid_layout.setColumnStretch( 6, 24)
        self.grid_layout.setColumnStretch( 7,  1)
        self.grid_layout.setColumnStretch( 8,  0)
        self.grid_layout.setColumnStretch( 9, 21)
        self.grid_layout.setColumnStretch(10,  2)

        super().switch()

        widget_type  = state['widget_type']
        widget_index = state['widget_index']

        if widget_type == 'mnemonic':
            self.mnemonic_widgets[widget_index].setFocus()
        elif widget_type == 'intcode':
            self.intcode_widgets[widget_index].setFocus()
        else:
            errmsg = f"Invalid widget_type='{widget_type}'"
            raise ValueError(errmsg)

        self.autofill()

    def destroy_panel(self) -> None:
        self.back_button.setFocus()  # trigger focusOut of current edit widget

        idx = shared_panel_state['panel_index']
        self.trace(f"destroy widgets {idx}")
        state = self.get_or_init_state()

        intcode_texts = [widget.text() for widget in self.intcode_widgets]
        if intcode_texts:
            state['intcode_texts'] = intcode_texts

        mnemonic_texts = [widget.text() for widget in self.mnemonic_widgets]
        if mnemonic_texts:
            state['mnemonic_texts'] = mnemonic_texts

        for widget in self.grid_widgets:
            self.grid_layout.removeWidget(widget)
            widget.deleteLater()

        del self.grid_widgets[:]
        del self.intcode_widgets[:]
        del self.mnemonic_widgets[:]

    def _known_secret_iter_valid_intcode_datas(self) -> typ.Iterable[MaybeBytes]:
        expected_data_and_ecc = get_padded_secret()
        data_unpadded         = get_current_secret().secret_data
        expected_intcodes     = ui_common.bytes2intcodes(data_unpadded)
        assert len(self.intcode_widgets) == len(expected_intcodes)

        for i, widget in enumerate(self.intcode_widgets):
            idx = i * 2

            intcode_text = widget.text().strip()

            if len(intcode_text) > 0 and intcode_text != expected_intcodes[i]:
                widget.setStyleSheet("background-color: #F66;")
            else:
                widget.setStyleSheet("")

            if intcode_text == expected_intcodes[i]:
                yield expected_data_and_ecc[idx + 0 : idx + 1]
                yield expected_data_and_ecc[idx + 1 : idx + 2]
            else:
                yield None
                yield None

    def _unknown_secret_iter_valid_intcode_datas(self) -> typ.Iterable[MaybeBytes]:
        for idx, widget in enumerate(self.intcode_widgets):
            widget.setStyleSheet("")

            intcode = widget.text().strip().replace("-", "")
            if len(intcode) == 0:
                yield None
                yield None
            else:
                try:
                    parts = ui_common.intcodes2parts([intcode], idx_offset=idx)
                    yield parts[0]
                    yield parts[1]
                except ValueError:
                    widget.setStyleSheet("background-color: #F66;")
                    yield None
                    yield None

    def _known_secret_iter_valid_mnemonic_datas(self) -> typ.Iterable[MaybeBytes]:
        expected_data_and_ecc = get_padded_secret()
        expected_data_padded  = expected_data_and_ecc[: len(expected_data_and_ecc) // 2]
        expected_words        = mnemonic.bytes2phrase(expected_data_padded).split()

        for i, widget in enumerate(self.mnemonic_widgets):
            word = widget.text().strip()
            if len(word) > 0 and word != expected_words[i]:
                widget.setStyleSheet("background-color: #F66;")
            else:
                widget.setStyleSheet("")

            if word == expected_words[i]:
                yield expected_data_padded[i : i + 1]
            else:
                yield None

    def _unknown_secret_iter_valid_mnemonic_datas(self) -> typ.Iterable[MaybeBytes]:
        for widget in self.mnemonic_widgets:
            widget.setStyleSheet("")
            word = widget.text().strip()
            if word:
                try:
                    yield mnemonic.phrase2bytes(word)
                except ValueError:
                    widget.setStyleSheet("background-color: #F66;")
                    yield None
            else:
                yield None

    def iter_valid_intcode_datas(self) -> typ.Iterable[MaybeBytes]:
        if has_secrets():
            return self._known_secret_iter_valid_intcode_datas()
        else:
            return self._unknown_secret_iter_valid_intcode_datas()

    def iter_valid_mnemonic_datas(self) -> typ.Iterable[MaybeBytes]:
        if has_secrets():
            return self._known_secret_iter_valid_mnemonic_datas()
        else:
            return self._unknown_secret_iter_valid_mnemonic_datas()

    def parse_accepted_datas(self) -> typ.Iterable[MaybeBytes]:
        valid_intcode_datas : typ.Sequence[MaybeBytes] = list(self.iter_valid_intcode_datas())
        valid_mnemonic_datas: typ.Sequence[MaybeBytes] = list(self.iter_valid_mnemonic_datas())

        state    = self.get_or_init_state()
        data_len = state['num_inputs']
        ecc_len  = state['num_inputs']
        assert len(valid_intcode_datas) == len(valid_mnemonic_datas) * 2
        assert len(valid_intcode_datas) == data_len + ecc_len

        for i in range(data_len + ecc_len):
            intcode_accept_ts = state['intcodes_accepted'][i // 2]
            is_valid_intcode  = valid_intcode_datas[i] is not None

            if i < len(state['mnemonics_accepted']):
                mnemonic_accept_ts = state['mnemonics_accepted'][i]
                is_valid_mnemonic  = valid_mnemonic_datas[i] is not None
            else:
                mnemonic_accept_ts = 0
                is_valid_mnemonic  = False

            if is_valid_intcode and intcode_accept_ts > mnemonic_accept_ts:
                yield valid_intcode_datas[i]
            elif is_valid_mnemonic and mnemonic_accept_ts > intcode_accept_ts:
                yield valid_mnemonic_datas[i]
            else:
                yield None

    def recover_datas(self) -> typ.Sequence[MaybeBytes]:
        valid_datas = list(self.parse_accepted_datas())
        state       = self.get_or_init_state()
        return list(_recover_datas(valid_datas, msg_len=state['msg_len']))

    def autofill(self, accept_intcode: int = -1, accept_mnemonic: int = -1) -> None:
        state = self.get_or_init_state()
        if accept_intcode >= 0:
            state['intcodes_accepted'][accept_intcode] = time.time()
        elif accept_mnemonic >= 0:
            state['mnemonics_accepted'][accept_mnemonic] = time.time()
        # else:
        #     # may happen during panel switch
        #     return

        recovered_datas = self.recover_datas()
        if shared_panel_state['param_cfg'] is None and all(recovered_datas[:3]):
            _recover_data = b"".join(recovered_datas[:3])  # type: ignore
            try:
                param_cfg = params.bytes2param_cfg(_recover_data)
                shared_panel_state['param_cfg'] = param_cfg

                idx = shared_panel_state['panel_index']
                self.widget_states[idx]['header_text'] = self.label_text()
                self.header.setText(state['header_text'])
            except ValueError as err:
                logger.error(f"Error parsing params {err}")
                if "Unsupported Version" in str(err):
                    self.mnemonic_widgets[0].setStyleSheet("background-color: #F66;")

        maybe_intcodes : typ.Sequence[typ.Optional[str]]
        maybe_mnemonics: typ.Sequence[typ.Optional[str]]

        if all(recovered_datas):
            _recover_data = b"".join(recovered_datas)  # type: ignore
            self.set_nav(True, True)
            maybe_intcodes  = ui_common.bytes2intcodes(_recover_data)
            data_and_ecc    = list(ui_common.intcodes2parts(maybe_intcodes))
            maybe_mnemonics = list(_parse_mnemonics(data_and_ecc))
        else:
            self.set_nav(True, False)
            maybe_intcodes  = list(_parse_intcodes(recovered_datas))
            maybe_mnemonics = list(_parse_mnemonics(recovered_datas))

        for i, intcode in enumerate(maybe_intcodes[: state['num_inputs']]):
            if intcode:
                self.intcode_widgets[i].setText(intcode)

        for i, word in enumerate(maybe_mnemonics[: state['num_inputs']]):
            if word:
                self.mnemonic_widgets[i].setText(word)
