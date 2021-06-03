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
import sys
import time
import typing as typ
import logging
import pathlib as pl

import PyQt5.Qt as qt
import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc
import PyQt5.QtWidgets as qtw

from . import cli_io
from . import params
from . import mnemonic
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
            print("handle button", button_name, args, kwargs)
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


class CreateWalletParamsPanel(NavigablePanel):
    def __init__(self, index: int):
        self.title            = "SBK - Create New Wallet"
        self.prev_panel_clazz = SelectCommandPanel
        self.next_panel_clazz = SeedDerivationPanel

        super().__init__(index)

        form = qtw.QFormLayout()

        self.threshold = qtw.QSpinBox()
        self.threshold.setRange(2, 5)
        self.threshold.setValue(3)
        form.addRow("&Threshold", self.threshold)

        self.num_shares = qtw.QSpinBox()
        self.num_shares.setRange(3, 63)
        self.num_shares.setValue(5)
        form.addRow("&Shares", self.num_shares)

        self.wallet_name = qtw.QLineEdit()
        self.wallet_name.setPlaceholderText("empty")
        form.addRow("&Shares", self.wallet_name)

        def constrain_threshold():
            self.threshold.setMaximum(min(self.num_shares.value(), 16))

        def constrain_num_shares():
            self.num_shares.setMinimum(self.threshold.value())

        self.num_shares.valueChanged.connect(constrain_threshold)
        self.threshold.valueChanged.connect(constrain_num_shares)

        self.kdf_memory = qtw.QSpinBox()
        self.kdf_memory.setRange(100, 15)
        self.kdf_memory.setValue(6)
        form.addRow("&Memory Usage", self.kdf_memory)

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


class CurrentSecret(typ.NamedTuple):

    secret_type: str
    label_text : str
    secret_data: bytes


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


_secrets_state = {
    'index': 0,
}


class SecretsResult(typ.NamedTuple):
    errmsg   : str
    raw_salt : bytes
    brainkey : bytes
    shares   : typ.List[bytes]
    seed_data: bytes


class SecretPanel(NavigablePanel):
    def param_cfg(self) -> params.ParamConfig:
        derivation_panel = self.parent().findChild(SeedDerivationPanel)
        return derivation_panel.param_cfg

    def secrets(self) -> SecretsResult:
        derivation_panel = self.parent().findChild(SeedDerivationPanel)
        return derivation_panel.secrets

    def current_secret(self) -> CurrentSecret:
        idx        = _secrets_state['index']
        secrets    = self.secrets()
        num_shares = len(secrets.shares)

        if idx < num_shares:
            share_no = idx + 1
            return CurrentSecret(
                secret_type=cli_io.SECRET_TYPE_SHARE,
                label_text=f"Share {share_no}/{num_shares}",
                secret_data=secrets.shares[idx],
            )
        elif idx == num_shares:
            return CurrentSecret(
                secret_type=cli_io.SECRET_TYPE_SALT,
                label_text="Salt",
                secret_data=secrets.raw_salt,
            )
        else:
            return CurrentSecret(
                secret_type=cli_io.SECRET_TYPE_BRAINKEY,
                label_text="Brainkey",
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
        _secrets_state['index'] = max(_secrets_state['index'] - 1, 0)
        if _secrets_state['index'] == 0:
            return ShowSecretPanel
        else:
            return ValidateSecretPanel

    @property
    def next_panel_clazz(self) -> Panel:
        return ValidateSecretPanel

    def switch(self) -> None:
        secret = self.current_secret()
        self.header.setText(secret.label_text)

        output_lines = cli_io.format_secret_lines(
            secret.secret_type,
            secret.secret_data,
        )

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

        if key == qtc.Qt.Key_Tab and len(text) == 0:
            p = self.parent()
            if self == p.intcode_widgets[0]:
                p.mnemonic_widgets[0].setFocus(True)
                return True

        is_enter = key == qtc.Qt.Key_Enter or key == qtc.Qt.Key_Return
        if is_enter:
            p   = self.parent()
            idx = p.intcode_widgets.index(self)
            if idx + 1 < len(p.intcode_widgets):
                p.mnemonic_widgets[idx + 1].setFocus(True)
                return True

        return super().event(event)

    def setText(self, text) -> None:
        text = text.replace("-", "")
        if len(text) >= 3:
            return super().setText(text[:3] + "-" + text[3:])
        else:
            return super().setText(text)

    def focusInEvent(self, event) -> None:
        self.setStyleSheet("")
        return super().focusInEvent(event)

    def focusOutEvent(self, event) -> None:
        text = self.text().replace("-", "")
        if len(text) == 0 or (len(text) == 6 and text.isdigit()):
            self.setStyleSheet("")
            self.parent().autofill()
        else:
            self.setStyleSheet("background-color: #F66;")
        return super().focusOutEvent(event)


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

    def focusOutEvent(self, event) -> None:
        self.parent().autofill()
        return super().focusOutEvent(event)


def _input_widget(parent: Panel, input_type: str) -> qtw.QLineEdit:
    if input_type == 'intcode':
        max_length = 7
    elif input_type == 'mnemonic':
        max_length = 8
    else:
        errmsg = f"Invalid {input_type=}"
        raise ValueError(errmsg)

    if input_type == 'intcode':
        line_edit = IntCodeEdit(parent)
        regexp    = qt.QRegExp(r"([0-9]{,4}|[0-9]{3}-[0-9]{,3})", qt.Qt.CaseInsensitive)
        line_edit.setPlaceholderText("000-000")
        validator = qtg.QRegExpValidator(regexp, line_edit)
        line_edit.setValidator(validator)
    else:
        line_edit = MnemonicEdit(parent)
        regexp    = qt.QRegExp(r"[a-zA-Z]{,8}", qt.Qt.CaseInsensitive)
        validator = qtg.QRegExpValidator(regexp, line_edit)
        line_edit.setValidator(validator)
        completer = qtw.QCompleter(mnemonic.WORDLIST, line_edit)
        completer.setCaseSensitivity(qt.Qt.CaseInsensitive)
        line_edit.setCompleter(completer)

    line_edit.setAlignment(qtc.Qt.AlignCenter)
    line_edit.setFont(FIXED_FONT)
    line_edit.setMaxLength(max_length)
    line_edit.setFixedWidth(max_length * 22)
    # line_edit.setStyleSheet("background-color: #F44;")

    return line_edit


class ValidateSecretPanel(SecretPanel):
    def __init__(self, index: int):
        self.title = "SBK - Create New Wallet"

        super().__init__(index)

        self.header = _header_widget()

        class InputWidgets(typ.NamedTuple):
            row    : int
            widgets: typ.List

        num_inputs = params.SHARE_LEN
        num_rows   = num_inputs // 2

        self.intcode_widgets  = []
        self.mnemonic_widgets = []

        for _ in range(num_inputs):
            intcode_widget  = _input_widget(self, 'intcode')
            mnemonic_widget = _input_widget(self, 'mnemonic')

            self.intcode_widgets.append(intcode_widget)
            self.mnemonic_widgets.append(mnemonic_widget)

        for i in range(1, num_inputs):
            w1 = self.intcode_widgets[i - 1]
            w2 = self.intcode_widgets[i]
            self.setTabOrder(w1, w2)

        for i in range(1, num_inputs):
            w1 = self.mnemonic_widgets[i - 1]
            w2 = self.mnemonic_widgets[i]
            self.setTabOrder(w1, w2)

        grid_layout = qtw.QGridLayout()

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
                grid_layout.addWidget(widget, row, col)

        grid_layout.setColumnStretch( 0,  2)
        grid_layout.setColumnStretch( 1,  0)
        grid_layout.setColumnStretch( 2, 21)
        grid_layout.setColumnStretch( 3,  1)
        grid_layout.setColumnStretch( 4, 24)
        grid_layout.setColumnStretch( 5,  0)
        grid_layout.setColumnStretch( 6, 24)
        grid_layout.setColumnStretch( 7,  1)
        grid_layout.setColumnStretch( 8,  0)
        grid_layout.setColumnStretch( 9, 21)
        grid_layout.setColumnStretch(10,  2)

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
        self.layout.addLayout(grid_layout)
        self.layout.addStretch(3)

        self.layout.addLayout(self.nav_layout)
        self.setLayout(self.layout)

    def autofill(self) -> None:
        intcode_texts  = [iw.text().strip() for iw in self.intcode_widgets]
        mnemonic_texts = [mw.text().strip() for mw in self.mnemonic_widgets]

        intcode_datas : typ.List[typ.Union[bytes, None]] = []
        mnemonic_datas: typ.List[typ.Union[bytes, None]] = []

        for i, intcode_text in enumerate(intcode_texts):
            maybe_intcode_data = None
            try:
                if intcode_text:
                    data               = ui_common.intcodes2parts([intcode_text], idx_offset=i)
                    maybe_intcode_data = b"".join(data)
            except ValueError as err:
                logger.error(str(err))

            intcode_datas.append(maybe_intcode_data)

        for w1, w2 in zip(mnemonic_texts[::2], mnemonic_texts[1::2]):
            if w1 and w2:
                data = mnemonic.phrase2bytes(w1 + " " + w2)
                mnemonic_datas.append(data)
            else:
                mnemonic_datas.append(None)

        print("??I", len(intcode_datas ))
        print("??M", len(mnemonic_datas))

        ecc_datas = intcode_datas[len() :]  # noqa
        datas     = [(di or dm) for di, dm in zip(intcode_datas, mnemonic_datas)]

        # for i, (d1, d2) in enumerate(zip(datas[::2], datas[1::2])):
        #     phrase = mnemonic.bytes2phrase(d1 + d2)

        for i, data in enumerate(datas):
            if data is None:
                continue

            phrase  = mnemonic.bytes2phrase(data)
            intcode = ui_common.bytes2incode_part(data, idx_offset=i)
            print("???", (i, data, phrase, intcode))

            w1, w2 = phrase.split()
            self.mnemonic_widgets[i * 2].setText(w1)
            self.mnemonic_widgets[i * 2 + 1].setText(w2)

            self.intcode_widgets[i].setText(intcode)

        print()

    def keyPressEvent(self, event) -> None:
        super().keyPressEvent(event)

    @property
    def prev_panel_clazz(self) -> Panel:
        return ShowSecretPanel

    @property
    def next_panel_clazz(self) -> Panel:
        _secrets_state['index'] = max(_secrets_state['index'] + 1, 0)
        num_shares = len(self.secrets().shares)
        if _secrets_state['index'] < num_shares + 2:
            return ShowSecretPanel
        else:
            return LoadWalletPanel

    def switch(self) -> None:
        secret = self.current_secret()
        self.header.setText("Verify " + secret.label_text)

        # intcodes = list(ui_common.bytes2intcodes(secret.secret_data))

        super().switch()

        self.mnemonic_widgets[0].setFocus()


class LoadWalletPanel(Panel):
    def __init__(self, index: int):
        self.title = "SBK - Load Wallet"

        super().__init__(index)


class RecoverWalletPanel(Panel):
    def __init__(self, index: int):
        self.title = "SBK - Recover Wallet"

        super().__init__(index)


class ProgressStatus(typ.NamedTuple):

    current: int
    length : int


def progres_status_emitter(signal) -> typ.Callable:
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


class ParamConfigWorker(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(params.ParamConfig)

    def __init__(
        self,
        threshold      : int,
        num_shares     : int,
        target_duration: float,
    ) -> None:
        super().__init__()
        self.threshold       = threshold
        self.num_shares      = num_shares
        self.target_duration = target_duration

    def run(self) -> None:
        param_cfg = ui_common.init_param_config(
            target_duration=self.target_duration,
            parallelism=None,
            memory_cost=None,
            time_cost=None,
            threshold=self.threshold,
            num_shares=self.num_shares,
            init_progressbar=progres_status_emitter(self.progress),
        )
        self.finished.emit(param_cfg)


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

        raw_salt, brainkey, shares = ui_common.create_secrets(self.param_cfg)

        seed_data = ui_common.derive_seed(
            self.param_cfg.kdf_params,
            raw_salt,
            brainkey,
            label="KDF Validation ",
            init_progressbar=progres_status_emitter(self.progress),
        )

        result = SecretsResult(
            errmsg="",
            raw_salt=raw_salt,
            brainkey=brainkey,
            shares=shares,
            seed_data=seed_data,
        )
        self.finished.emit(result)


def progressbar_updater(progressbar: qtw.QProgressBar) -> typ.Callable[[ProgressStatus], None]:
    def update_progressbar(status: ProgressStatus) -> None:
        progressbar.setRange(0, status.length)
        progressbar.setValue(status.current)

    return update_progressbar


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

        threshold       = create_panel.threshold.value()
        num_shares      = create_panel.num_shares.value()
        target_duration = create_panel.target_duration.value()

        logger.info(f"KDF Params: {threshold=} / {num_shares=}, {target_duration=}")

        self.progressbar1.setValue(0)
        self.progressbar2.setValue(0)

        self.worker1 = ParamConfigWorker(threshold, num_shares, target_duration)
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
        self.setGeometry(200, 200, 800, 600)

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
