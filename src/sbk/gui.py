#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

# ui code is messy ...
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-return-statements

"""GUI for SBK.

PyQT docs:
- https://realpython.com/python-pyqt-gui-calculator/
- https://zetcode.com/gui/pyqt5/
"""
import os
import sys
import time
import typing as typ
import logging
import pathlib as pl

import PyQt5.Qt as qt
import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc
import PyQt5.QtWidgets as qtw

from . import kdf
from . import cli_io
from . import ecc_rs
from . import params
from . import mnemonic
from . import sys_info
from . import ui_common

logger = logging.getLogger("sbk.gui")


ICON_PATH = pl.Path("logo_256.png")


class Panel(qtw.QWidget):
    def __init__(self, index: int):
        super().__init__()
        self.index = index

    def switch(self) -> None:
        self.parent().setWindowTitle(self.title)
        self.parent().setCurrentIndex(self.index)


class SelectCommandPanel(Panel):
    def __init__(self, index: int):
        self.title = "SBK"

        super().__init__(index)

        self.layout = qtw.QVBoxLayout()

        create_button = qtw.QPushButton("&Create New Wallet")
        create_button.setDefault(True)
        create_button.clicked.connect(self.init_button_handler('create'))
        self.layout.addWidget(create_button)

        load_button = qtw.QPushButton("&Load from Salt+Brainkey")
        load_button.setDefault(True)
        load_button.clicked.connect(self.init_button_handler('load'))
        self.layout.addWidget(load_button)

        recover_button = qtw.QPushButton("&Recover from Shares")
        recover_button.setDefault(True)
        recover_button.clicked.connect(self.init_button_handler('recover'))
        self.layout.addWidget(recover_button)

        self.layout.addStretch(1)
        self.setLayout(self.layout)

    def init_button_handler(self, button_name: str) -> typ.Callable:
        def handler(*args, **kwargs):
            logger.info(f"handle button {button_name=} {args} {kwargs}")
            p = self.parent()

            if button_name == 'create':
                p.get_or_init_panel(CreateWalletParamsPanel).switch()
            elif button_name == 'load':
                p.get_or_init_panel(LoadWalletPanel).switch()
            elif button_name == 'recover':
                p.get_or_init_panel(RecoverWalletPanel).switch()
            else:
                raise NotImplementedError()

        return handler


class NavigablePanel(Panel):
    def __init__(self, index: int):
        self.prev_button = qtw.QPushButton("&Prev")
        self.next_button = qtw.QPushButton("&Next")
        self.prev_button.clicked.connect(self.nav_handler('prev'))
        self.next_button.clicked.connect(self.nav_handler('next'))

        self.nav_layout = qtw.QHBoxLayout()
        self.nav_layout.addWidget(self.prev_button)
        self.nav_layout.addWidget(self.next_button)

        super().__init__(index)

    def nav_handler(self, event: str) -> typ.Callable:
        def handler() -> None:
            p = self.parent()
            if event == 'prev':
                p.get_or_init_panel(self.prev_panel_clazz).switch()
            elif event == 'next':
                p.get_or_init_panel(self.next_panel_clazz).switch()
            else:
                raise NotImplementedError(f"Invalid event: {event}")

        return handler


class ProgressStatus(typ.NamedTuple):

    current: int
    length : int


def init_progres_status_emitter_clazz(signal) -> typ.Callable:
    """Create a class that can be used with ui_common.run_with_progress_bar."""

    class _ProgressStatusEmitter:
        def __init__(self, length: int) -> None:
            self.current = 0
            self.length  = length

        def __enter__(self) -> '_ProgressStatusEmitter':
            return self

        def update(self, n_steps: int) -> None:
            self.current += n_steps
            status = ProgressStatus(self.current, self.length)
            signal.emit(status)

        def __exit__(self, exc_type, exc_value, tb) -> None:
            status = ProgressStatus(self.length, self.length)
            signal.emit(status)

    return _ProgressStatusEmitter


class CreateWalletParamsPanel(NavigablePanel):
    def __init__(self, index: int):
        self.title            = "SBK - Create New Wallet"
        self.prev_panel_clazz = SelectCommandPanel
        self.next_panel_clazz = SeedDerivationPanel

        super().__init__(index)

        form = qtw.QFormLayout()

        self.threshold = qtw.QSpinBox()
        self.threshold.setRange(2, 5)
        self.threshold.setValue(params.DEFAULT_THRESHOLD)
        form.addRow("&Threshold", self.threshold)

        self.num_shares = qtw.QSpinBox()
        self.num_shares.setRange(3, 63)
        self.num_shares.setValue(params.DEFAULT_NUM_SHARES)
        form.addRow("&Shares", self.num_shares)

        self.wallet_name = qtw.QLineEdit()
        self.wallet_name.setPlaceholderText("empty")
        form.addRow("&Wallet Name", self.wallet_name)

        def constrain_threshold():
            threshold = min(self.num_shares.value(), params.MAX_THRESHOLD)
            self.threshold.setMaximum(threshold)

        def constrain_num_shares():
            self.num_shares.setMinimum(self.threshold.value())

        self.num_shares.valueChanged.connect(constrain_threshold)
        self.threshold.valueChanged.connect(constrain_num_shares)

        self.sys_info = sys_info.init_sys_info()
        num_cores     = len(os.sched_getaffinity(0))

        max_parallelism = num_cores * 4
        max_sys_memory  = self.sys_info.total_mb

        default_parallelism = num_cores               * 2
        default_memory      = self.sys_info.initial_m * self.sys_info.initial_p

        self.parallelism = qtw.QSpinBox()
        self.parallelism.setRange(1, max_parallelism)
        self.parallelism.setValue(default_parallelism)
        form.addRow("&Parallelism [Threads]", self.parallelism)

        self.target_memory = qtw.QSpinBox()
        self.target_memory.setRange(10, max_sys_memory)
        self.target_memory.setValue(default_memory)
        self.target_memory.setSingleStep(10)
        form.addRow("&Memory Usage [MB]", self.target_memory)

        self.target_duration = qtw.QSpinBox()
        self.target_duration.setRange(1, 600)
        self.target_duration.setValue(params.DEFAULT_KDF_TARGET_DURATION)
        form.addRow("&Duration [Seconds]", self.target_duration)

        self.layout = qtw.QVBoxLayout()
        self.layout.addLayout(form)
        self.layout.addStretch(1)

        self.layout.addLayout(self.nav_layout)
        self.setLayout(self.layout)


WARNING_TEXT = f"""
<html><head/><body style="white-space:pre-wrap;">
<p>
{ui_common.SECURITY_WARNING_TEXT.strip()}
</p>
<p style="font-family:monospace;line-height:100%;">
{ui_common.SECURITY_WARNING_QR_CODE}
<p>
</body></html>
"""

SECRET_TMPL = """
<html><head/><body>
<p style="font-family:monospace;white-space:pre-wrap;">
{content}
<p>
</body></html>
"""


class SecurityWarningPanel(NavigablePanel):
    def __init__(self, index: int):
        self.title            = "SBK - Create New Wallet"
        self.prev_panel_clazz = SelectCommandPanel
        self.next_panel_clazz = ShowSecretPanel

        super().__init__(index)

        label      = qtw.QLabel(WARNING_TEXT.strip())
        label_wrap = qtw.QHBoxLayout()
        label_wrap.addStretch(1)
        label_wrap.addWidget(label)
        label_wrap.addStretch(1)

        self.layout = qtw.QVBoxLayout()
        self.layout.addLayout(label_wrap)
        self.layout.addStretch(2)

        self.layout.addLayout(self.nav_layout)
        self.setLayout(self.layout)


class SecretsResult(typ.NamedTuple):
    errmsg   : str
    salt     : bytes
    brainkey : bytes
    shares   : typ.List[bytes]
    seed_data: bytes


class CurrentSecret(typ.NamedTuple):

    label_text : str
    secret_type: str
    secret_data: bytes


_shared_panel_state = {'index': 0}


class SecretPanel(NavigablePanel):
    def param_cfg(self) -> params.ParamConfig:
        derivation_panel = self.parent().findChild(SeedDerivationPanel)
        return derivation_panel.param_cfg

    def secrets(self) -> SecretsResult:
        derivation_panel = self.parent().findChild(SeedDerivationPanel)
        return derivation_panel.secrets

    def current_secret(self) -> CurrentSecret:
        secrets    = self.secrets()
        num_shares = len(secrets.shares)

        panel_index = _shared_panel_state['index']
        if panel_index < num_shares:
            share_no = panel_index + 1
            return CurrentSecret(
                label_text=f"Verify Share {share_no}/{num_shares}",
                secret_type=cli_io.SECRET_TYPE_SHARE,
                secret_data=secrets.shares[panel_index],
            )
        elif panel_index == num_shares:
            return CurrentSecret(
                label_text="Verify Salt",
                secret_type=cli_io.SECRET_TYPE_SALT,
                secret_data=secrets.salt,
            )
        else:
            return CurrentSecret(
                label_text="Verify Brainkey",
                secret_type=cli_io.SECRET_TYPE_BRAINKEY,
                secret_data=secrets.brainkey,
            )


def _header_widget():
    header = qtw.QLabel()
    font   = header.font()
    font.setPointSize(14)
    font.setBold(True)
    header.setFont(font)
    header.setAlignment(qtc.Qt.AlignCenter)
    return header


class ShowSecretPanel(SecretPanel):
    def __init__(self, index: int):
        self.title = "SBK - Create New Wallet"

        super().__init__(index)

        self.header = _header_widget()
        self.text   = qtw.QLabel()

        text_wrap = qtw.QHBoxLayout()
        text_wrap.addStretch(1)
        text_wrap.addWidget(self.text)
        text_wrap.addStretch(1)

        self.layout = qtw.QVBoxLayout()
        self.layout.addWidget(self.header)
        self.layout.addStretch(1)
        self.layout.addLayout(text_wrap)
        self.layout.addStretch(3)

        self.layout.addLayout(self.nav_layout)
        self.setLayout(self.layout)

    @property
    def prev_panel_clazz(self) -> Panel:
        logger.info(f"prev show {_shared_panel_state['index']}")
        if _shared_panel_state['index'] == 0:
            return ShowSecretPanel
        else:
            _shared_panel_state['index'] = max(_shared_panel_state['index'] - 1, 0)
            return VerifySecretPanel

    @property
    def next_panel_clazz(self) -> Panel:
        logger.info(f"next show {_shared_panel_state['index']}")
        return VerifySecretPanel

    def switch(self) -> None:
        secret = self.current_secret()
        self.header.setText(secret.label_text)

        output_lines = cli_io.format_secret_lines(secret.secret_type, secret.secret_data)

        content = "\n".join(output_lines) + "\n"
        text    = SECRET_TMPL.format(content=content)
        self.text.setText(text)

        super().switch()


FIXED_FONT = qtg.QFontDatabase.systemFont(qtg.QFontDatabase.FixedFont)


def _label_widget(parent: Panel, text: str) -> qtw.QLabel:
    label = qtw.QLabel(text, parent)
    label.setAlignment(qtc.Qt.AlignCenter)
    label.setFont(FIXED_FONT)
    return label


class IntCodeEdit(qtw.QLineEdit):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def event(self, event) -> bool:
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

        return super().event(event)

    def setText(self, text) -> None:
        text = text.replace("-", "")
        if len(text) >= 3:
            return super().setText(text[:3] + "-" + text[3:])
        else:
            return super().setText(text)

    def idx(self) -> int:
        try:
            return self.parent().intcode_widgets.index(self)
        except ValueError:
            # may happen during panel switch
            return -1

    def is_valid(self) -> bool:
        text = self.text().replace("-", "")
        return len(text) == 0 or (len(text) == 6 and text.isdigit())

    def focusOutEvent(self, event) -> None:
        logger.info("focusOutEvent intcode")
        self.parent().autofill(accept_intcode=self.idx())
        return super().focusOutEvent(event)

    def focusInEvent(self, event) -> None:
        self.parent().track_focus('intcode', self.idx())
        self.setStyleSheet("")
        return super().focusInEvent(event)


class MnemonicEdit(qtw.QLineEdit):
    def event(self, event) -> bool:
        if event.type() != qtc.QEvent.KeyPress:
            return super().event(event)

        key = event.key()

        if key == qtc.Qt.Key_Backtab:
            p = self.parent()
            if self is p.mnemonic_widgets[0]:
                p.intcode_widgets[0].setFocus(True)
                return True

        is_enter = key in (qtc.Qt.Key_Enter, qtc.Qt.Key_Return, qtc.Qt.Key_Tab)
        word     = self.text().strip()

        if is_enter and len(word) >= 1:
            c              = self.completer()
            top_completion = c.currentCompletion()
            if top_completion:
                p = self.parent()
                self.setText(top_completion)
                next_idx = p.mnemonic_widgets.index(self) + 1
                if next_idx < len(p.mnemonic_widgets):
                    p.mnemonic_widgets[next_idx].setFocus(True)
                    return True

        return super().event(event)

    def idx(self) -> int:
        try:
            return self.parent().mnemonic_widgets.index(self)
        except ValueError:
            # may happen during panel switch
            return -1

    def is_valid(self) -> bool:
        p   = self.parent()
        idx = p.mnemonic_widgets.index(self)

        try:
            expected_byte = p.current_secret().secret_data[idx : idx + 1]
            expected_word = mnemonic.decode_word(expected_byte)
        except ValueError:
            return False

        word = self.text().strip()
        return len(word) == 0 or word == expected_word

    def focusOutEvent(self, event) -> None:
        logger.info("focusOutEvent mnemonic")
        self.parent().autofill(accept_mnemonic=self.idx())
        return super().focusOutEvent(event)

    def focusInEvent(self, event) -> None:
        self.parent().track_focus('mnemonic', self.idx())
        self.setStyleSheet("")
        return super().focusInEvent(event)


def _input_widget(parent: Panel, input_type: str, initial_text: str) -> qtw.QLineEdit:
    if input_type == 'intcode':
        max_length = 7
    elif input_type == 'mnemonic':
        max_length = 8
    else:
        errmsg = f"Invalid {input_type=}"
        raise ValueError(errmsg)

    if input_type == 'intcode':
        line_edit = IntCodeEdit(parent)
        line_edit.setText(initial_text)
        line_edit.setPlaceholderText("000-000")

        regexp    = qt.QRegExp(r"([0-9]{,4}|[0-9]{3}-[0-9]{,3})", qt.Qt.CaseInsensitive)
        validator = qtg.QRegExpValidator(regexp, line_edit)
        line_edit.setValidator(validator)
    else:
        line_edit = MnemonicEdit(parent)
        line_edit.setText(initial_text)
        line_edit.setPlaceholderText("-")

        regexp    = qt.QRegExp(r"[a-zA-Z]{5,8}", qt.Qt.CaseInsensitive)
        validator = qtg.QRegExpValidator(regexp, line_edit)
        line_edit.setValidator(validator)

        completer = qtw.QCompleter(mnemonic.WORDLIST, parent=line_edit)
        completer.setCaseSensitivity(qt.Qt.CaseInsensitive)
        completer.setFilterMode(qt.Qt.MatchContains)
        line_edit.setCompleter(completer)
        if initial_text:
            completer.setCompletionPrefix(initial_text)

    line_edit.setAlignment(qtc.Qt.AlignCenter)
    line_edit.setFont(FIXED_FONT)
    line_edit.setMaxLength(max_length)
    line_edit.setFixedWidth(max_length * 22)
    # line_edit.setStyleSheet("background-color: #F44;")

    return line_edit


MaybeBytes = typ.Union[bytes, None]


def _parse_intcodes(datas: typ.List[MaybeBytes]) -> ui_common.MaybeIntCodes:
    maybe_intcodes = []
    pairs          = [datas[i : i + 2] for i in range(0, len(datas), 2)]
    for i, (d1, d2) in enumerate(pairs):
        if d1 and d2:
            intcode = ui_common.bytes2incode_part(d1 + d2, idx_offset=i)
            maybe_intcodes.append(intcode)
        else:
            maybe_intcodes.append(None)
    return maybe_intcodes


def _recover_datas(accepted_datas: typ.List[MaybeBytes]) -> typ.List[MaybeBytes]:
    maybe_intcodes = _parse_intcodes(accepted_datas)

    # recover
    msg_len           = len(accepted_datas) // 2
    accepted_data_len = sum(2 for maybe_intcode in maybe_intcodes if maybe_intcode)
    is_recoverable    = accepted_data_len >= msg_len

    if is_recoverable:
        try:
            recovered_data = ui_common.maybe_intcodes2bytes(maybe_intcodes, msg_len=msg_len)
            return [recovered_data[i : i + 1] for i in range(len(recovered_data))]
        except ecc_rs.ECCDecodeError as err:
            logger.error(f"Recovery failed, possibly invalid inputs. {err}")
            return accepted_datas
    else:
        return accepted_datas


class VerifySecretPanel(SecretPanel):
    def __init__(self, index: int):
        self.title = "SBK - Create New Wallet"

        self.widget_states = {}

        self.grid_widgets     = []
        self.intcode_widgets  = []
        self.mnemonic_widgets = []

        super().__init__(index)

        self.header      = _header_widget()
        self.grid_layout = qtw.QGridLayout()

        column_headers = qtw.QHBoxLayout()
        column_headers.addStretch(6 + 9)
        column_headers.addWidget(_label_widget(self, "Data"    ), 21 - 9)
        column_headers.addWidget(_label_widget(self, "Mnemonic"), 24 * 2)
        column_headers.addWidget(_label_widget(self, "ECC"     ), 21 - 1)
        column_headers.addStretch(6 + 1)

        self.layout = qtw.QVBoxLayout()
        self.layout.addWidget(self.header)
        self.layout.addStretch(1)
        self.layout.addLayout(column_headers)
        self.layout.addLayout(self.grid_layout)
        self.layout.addStretch(3)

        self.layout.addLayout(self.nav_layout)
        self.setLayout(self.layout)

    def get_or_init_state(self) -> typ.Dict[str, typ.Any]:
        # NOTE (mb 2021-06-04): This whole state business may well be an artifact
        #   of (ab)using the Panel classes in NavigablePanel.nav_handler
        idx = _shared_panel_state['index']
        if idx not in self.widget_states:
            current_secret = self.current_secret()
            num_inputs     = len(current_secret.secret_data)
            if num_inputs % 2 != 0:
                num_inputs += 1

            self.widget_states[idx] = {
                'header_text'   : current_secret.label_text,
                'num_inputs'    : num_inputs,
                'widget_type'   : 'mnemonic',
                'widget_index'  : 0,
                'intcode_texts' : [""] * num_inputs,
                'mnemonic_texts': [""] * num_inputs,
                # widget index -> timestamp
                'intcodes_accepted' : [0] * num_inputs,
                'mnemonics_accepted': [0] * num_inputs,
            }
            logger.debug(f"init widgets state: {self.widget_states[idx]}")

        return self.widget_states[idx]

    def track_focus(self, widget_type: str, widget_index: int) -> None:
        state = self.get_or_init_state()
        state['widget_type' ] = widget_type
        state['widget_index'] = widget_index

    def switch(self) -> None:
        logger.info(f"switch {_shared_panel_state['index']}")
        state = self.get_or_init_state()

        self.header.setText(state['header_text'])

        # initialize state from previous usage
        for i in range(state['num_inputs']):
            if state['intcode_texts']:
                initial_intcode_text = state['intcode_texts'][i]
            else:
                initial_intcode_text = ""

            if state['mnemonic_texts']:
                initial_mnemonic_text = state['mnemonic_texts'][i]
            else:
                initial_mnemonic_text = ""

            intcode_widget  = _input_widget(self, 'intcode' , initial_intcode_text)
            mnemonic_widget = _input_widget(self, 'mnemonic', initial_mnemonic_text)

            self.intcode_widgets.append(intcode_widget)
            self.mnemonic_widgets.append(mnemonic_widget)

        for i in range(1, state['num_inputs']):
            w1 = self.intcode_widgets[i - 1]
            w2 = self.intcode_widgets[i]
            self.setTabOrder(w1, w2)

        for i in range(1, state['num_inputs']):
            w1 = self.mnemonic_widgets[i - 1]
            w2 = self.mnemonic_widgets[i]
            self.setTabOrder(w1, w2)

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

    def destroy_widgets(self) -> None:
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

    def _iter_incode_datas(self) -> typ.Iterable[MaybeBytes]:
        expected_data     = self.current_secret().secret_data
        expected_intcodes = ui_common.bytes2intcodes(expected_data)

        for i, widget in enumerate(self.intcode_widgets):
            intcode_text = widget.text().strip()
            if intcode_text:
                print("III", intcode_text)

            if len(intcode_text) > 0 and intcode_text != expected_intcodes[i]:
                widget.setStyleSheet("background-color: #F66;")
            else:
                widget.setStyleSheet("")

            if intcode_text == expected_intcodes[i]:
                idx = i * 2
                yield expected_data[idx + 0 : idx + 1]
                yield expected_data[idx + 1 : idx + 2]
            else:
                yield None
                yield None

    def _iter_mnemonic_datas(self) -> typ.Iterable[MaybeBytes]:
        expected_data = self.current_secret().secret_data
        if len(expected_data) % 2 != 0:
            expected_data += b"\x00"

        expected_words = mnemonic.bytes2phrase(expected_data).split()

        for i, widget in enumerate(self.mnemonic_widgets):
            word = widget.text().strip()
            if len(word) > 0 and word != expected_words[i]:
                widget.setStyleSheet("background-color: #F66;")
            else:
                widget.setStyleSheet("")

            if word == expected_words[i]:
                yield expected_data[i : i + 1]
            else:
                yield None

    def _parse_accepted_datas(self) -> typ.Iterable[MaybeBytes]:
        state = self.get_or_init_state()

        intcode_datas : typ.List[MaybeBytes] = list(self._iter_incode_datas())
        mnemonic_datas: typ.List[MaybeBytes] = list(self._iter_mnemonic_datas())

        data_len = state['num_inputs']
        ecc_len  = state['num_inputs']
        assert len(intcode_datas) == len(mnemonic_datas) * 2
        assert len(intcode_datas) == data_len + ecc_len

        for i in range(data_len + ecc_len):
            intcode_accept_ts = state['intcodes_accepted'][i // 2]
            is_valid_intcode  = intcode_datas[i] is not None

            if i < len(state['mnemonics_accepted']):
                mnemonic_accept_ts = state['mnemonics_accepted'][i]
                is_valid_mnemonic  = mnemonic_datas[i] is not None
            else:
                mnemonic_accept_ts = 0
                is_valid_mnemonic  = False

            if is_valid_intcode and intcode_accept_ts > mnemonic_accept_ts:
                yield intcode_datas[i]
            elif is_valid_mnemonic and mnemonic_accept_ts > intcode_accept_ts:
                yield mnemonic_datas[i]
            else:
                yield None

    def autofill(self, accept_intcode: int = -1, accept_mnemonic: int = -1) -> None:
        state = self.get_or_init_state()
        if accept_intcode >= 0:
            state['intcodes_accepted'][accept_intcode] = time.time()
        elif accept_mnemonic >= 0:
            state['mnemonics_accepted'][accept_mnemonic] = time.time()
        else:
            # may happen during panel switch
            return

        accepted_datas = list(self._parse_accepted_datas())
        recoverd_datas = list(_recover_datas(accepted_datas))

        if all(recoverd_datas):
            maybe_intcodes = ui_common.bytes2intcodes(b"".join(recoverd_datas))
        else:
            maybe_intcodes = _parse_intcodes(recoverd_datas)

        for i, intcode in enumerate(maybe_intcodes):
            if intcode:
                self.intcode_widgets[i].setText(intcode)

        for i, data in enumerate(recoverd_datas[: state['num_inputs']]):
            if data:
                word = mnemonic.decode_word(data)
                self.mnemonic_widgets[i].setText(word)

    def keyPressEvent(self, event) -> None:
        super().keyPressEvent(event)

    @property
    def prev_panel_clazz(self) -> Panel:
        self.destroy_widgets()
        logger.info(f"prev test {_shared_panel_state['index']}")
        return ShowSecretPanel

    @property
    def next_panel_clazz(self) -> Panel:
        self.destroy_widgets()
        logger.info(f"next test {_shared_panel_state['index']}")
        num_shares  = len(self.secrets().shares)
        num_secrets = num_shares + 2
        if _shared_panel_state['index'] < num_secrets:
            _shared_panel_state['index'] = max(_shared_panel_state['index'] + 1, 0)
            return ShowSecretPanel
        else:
            return LoadWalletPanel


class LoadWalletPanel(Panel):
    def __init__(self, index: int):
        self.title = "SBK - Load Wallet"

        super().__init__(index)


class RecoverWalletPanel(Panel):
    def __init__(self, index: int):
        self.title = "SBK - Recover Wallet"

        super().__init__(index)


class SeedDerivationWorker(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(SecretsResult)

    def __init__(
        self,
        param_cfg: params.ParamConfig,
    ) -> None:
        super().__init__()
        self.param_cfg = param_cfg

    def run(self) -> None:
        n = 0
        while True:
            entropy = ui_common.get_entropy_pool_size()
            if entropy < params.MIN_ENTROPY and n < params.MAX_ENTROPY_WAIT:
                logger.warning(f"low on entropy ({entropy}), waiting a bit for it to accumulate")
                time.sleep(1)
                n += 1
            else:
                break

        if entropy < params.MIN_ENTROPY:
            errmsg = f"Not enough entropy: {entropy} < {params.MIN_ENTROPY}"
            logger.error(errmsg)
            result = SecretsResult(errmsg, b"", b"", b"", b"")
            self.finished.emit(result)
            return

        try:
            ui_common.validated_param_data(self.param_cfg)
        except ValueError as err:
            if err.args and isinstance(err.args[0], list):
                bad_checks = err.args[0]
                errmsg     = "\n".join(bad_checks)
            else:
                errmsg = str(err)

            result = SecretsResult(errmsg, b"", b"", b"", b"")
            self.finished.emit(result)
            return

        salt, brainkey, shares = ui_common.create_secrets(self.param_cfg)

        seed_data = ui_common.derive_seed(
            self.param_cfg.kdf_params,
            salt,
            brainkey,
            label="KDF Validation ",
            init_progressbar=init_progres_status_emitter_clazz(self.progress),
        )

        result = SecretsResult(
            errmsg="",
            salt=salt,
            brainkey=brainkey,
            shares=shares,
            seed_data=seed_data,
        )
        self.finished.emit(result)


def progressbar_updater(progressbar: qtw.QProgressBar) -> typ.Callable[[ProgressStatus], None]:
    def update_progressbar(status: ProgressStatus) -> None:
        progressbar.setRange(0, status.length)
        progressbar.setValue(round(status.current))

    return update_progressbar


class ParamConfigWorker(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(params.ParamConfig)

    def __init__(
        self,
        threshold        : int,
        num_shares       : int,
        parallelism      : kdf.NumThreads,
        memory_per_thread: kdf.MebiBytes,
        target_duration  : kdf.Seconds,
    ) -> None:
        super().__init__()
        self.threshold         = threshold
        self.num_shares        = num_shares
        self.parallelism       = parallelism
        self.memory_per_thread = memory_per_thread
        self.target_duration   = target_duration

    def run(self) -> None:
        param_cfg = ui_common.init_param_config(
            target_duration=self.target_duration,
            parallelism=self.parallelism,
            memory_per_thread=self.memory_per_thread,
            time_cost=None,  # auto from target_duration
            threshold=self.threshold,
            num_shares=self.num_shares,
            init_progressbar=init_progres_status_emitter_clazz(self.progress),
        )
        self.finished.emit(param_cfg)


class SeedDerivationPanel(Panel):
    def __init__(self, index: int):
        self.title = "SBK - Key Derivation ..."

        self.param_cfg = None
        self.secrets   = None

        super().__init__(index)

        self.layout = qtw.QVBoxLayout()

        label1 = qtw.QLabel("KDF Calibration")
        label2 = qtw.QLabel("Key Derivation")

        self.progressbar1 = qtw.QProgressBar()
        self.progressbar1.setRange(0, 5000)
        self.progressbar1.setValue(0)

        self.progressbar2 = qtw.QProgressBar()
        self.progressbar2.setRange(0, 90000)
        self.progressbar2.setValue(0)

        # Instantiated in switch(), because we want fresh parameters
        # from create_panel every time.
        self.worker1 = None
        self.worker2 = None

        self.layout.addWidget(label1)
        self.layout.addWidget(self.progressbar1)
        self.layout.addWidget(label2)
        self.layout.addWidget(self.progressbar2)

        self.layout.addStretch(1)
        self.setLayout(self.layout)

    def switch(self) -> None:
        # get previous panel
        create_panel = self.parent().findChild(CreateWalletParamsPanel)

        threshold  = create_panel.threshold.value()
        num_shares = create_panel.num_shares.value()

        parallelism     = create_panel.parallelism.value()
        target_memory   = create_panel.target_memory.value()
        target_duration = create_panel.target_duration.value()

        memory_per_thread = round(target_memory / parallelism)

        _kdf_info = f"{parallelism=}, {memory_per_thread=}, {target_duration=}"
        logger.info(f"KDF Params: {threshold=} / {num_shares=}, {_kdf_info}")

        self.progressbar1.setValue(0)
        self.progressbar2.setValue(0)

        self.worker1 = ParamConfigWorker(
            threshold, num_shares, parallelism, memory_per_thread, target_duration
        )
        self.worker1.progress.connect(progressbar_updater(self.progressbar1))
        self.worker1.finished.connect(self.on_param_config_done)

        super().switch()

        self.worker1.start()

    def on_param_config_done(self, param_cfg: params.ParamConfig) -> None:
        logger.info("SeedDerivationPanel.on_param_config_done")

        self.param_cfg = param_cfg

        self.worker2 = SeedDerivationWorker(param_cfg)
        self.worker2.progress.connect(progressbar_updater(self.progressbar2))
        self.worker2.finished.connect(self.on_key_dervation_done)

        self.worker2.start()

    def on_key_dervation_done(self, secrets: SecretsResult) -> None:
        if secrets.errmsg:
            qtw.QMessageBox.critical(self, 'Error', secrets.errmsg)
            self.parent().close()
        else:
            logger.info("SeedDerivationPanel.on_key_dervation_done")
            self.secrets = secrets
            self.parent().get_or_init_panel(SecurityWarningPanel).switch()


class MainGUI(qtw.QStackedWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SBK")
        self.setWindowIcon(qtg.QIcon(str(ICON_PATH)))
        self.setFixedSize(1200, 1000)
        # self.setGeometry(200, 200, 800, 600)
        self.setGeometry(2200, 200, 800, 600)

        select_command_panel = SelectCommandPanel(0)
        self.addWidget(select_command_panel)
        select_command_panel.switch()

    def get_or_init_panel(self, clazz) -> Panel:
        panel = self.findChild(clazz)
        if panel is None:
            logger.info(f"get_or_init_panel init: {clazz.__name__}")
            index = self.count()
            panel = clazz(index)
            self.addWidget(panel)
        else:
            logger.info(f"get_or_init_panel get : {clazz.__name__}")
        return panel

    def keyPressEvent(self, e):
        val     = e.key()
        mod     = e.modifiers()
        is_ctrl = mod & qt.Qt.ControlModifier
        is_alt  = mod & qt.Qt.AltModifier
        if val == qt.Qt.Key_Q and (is_ctrl or is_alt):
            self.close()

    def set_nav(self, prev_enabled: bool, next_enabled: bool) -> None:
        self.prev_button.setDisabled(not prev_enabled)
        self.next_button.setDisabled(not next_enabled)
        if prev_enabled or next_enabled:
            self.prev_button.setHidden(False)
            self.next_button.setHidden(False)
        else:
            self.prev_button.setHidden(True)
            self.next_button.setHidden(True)


def _screen_size(app: qtw.QApplication) -> typ.Tuple[int, int]:
    screen = app.primaryScreen()
    size   = screen.size()
    return (size.width(), size.height())


def gui() -> None:
    app = qtw.QApplication([])
    # w, h = _screen_size(app)

    sbk_dialog = MainGUI()
    sbk_dialog.show()
    sys.exit(app.exec())


def selftest() -> None:
    import sbk.cli

    sbk.cli._configure_logging(verbosity=2)

    try:
        import pretty_traceback

        pretty_traceback.install(envvar='ENABLE_PRETTY_TRACEBACK')
    except ImportError:
        pass  # no need to fail because of missing dev dependency

    gui()


if __name__ == '__main__':
    selftest()
