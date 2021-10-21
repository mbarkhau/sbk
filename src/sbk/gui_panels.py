#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

# messy ui code is messy ...
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-return-statements

"""GUI Panels for SBK."""
import os
import time
import typing as typ
import logging
import pathlib as pl
import threading

import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc
import PyQt5.QtWidgets as qtw

from . import shamir
from . import gui_tasks as gt
from . import ui_common
from . import parameters
from . import common_types as ct
from . import package_data
from . import gui_panels_base as gpb

logger = logging.getLogger("sbk.gui_panels")


class SelectCommandPanel(gpb.Panel):

    buttons: typ.Dict[str, qtw.QPushButton]

    def __init__(self, index: int):
        self.title = "SBK"

        super().__init__(index)

        self._layout = qtw.QVBoxLayout()

        pixmap = qtg.QPixmap()
        pixmap.loadFromData(package_data.read_binary("nostroke_logo_64.png"))
        icon_label = qtw.QLabel(self)
        icon_label.setPixmap(pixmap.scaledToWidth(64))
        icon_label.setAlignment(qtc.Qt.AlignCenter)

        self._layout.addStretch(1)
        self._layout.addWidget(icon_label)
        self._layout.addStretch(1)

        self.buttons = {}

        def add_button(label: str, button_id: str, *, enabled: bool = True) -> qtw.QPushButton:
            button = qtw.QPushButton(label)
            button.clicked.connect(self.init_button_handler(button_id))
            button.setEnabled(enabled)
            self.buttons[button_id] = button
            self._layout.addWidget(button)
            return button

        add_button("Open &Wallet", 'open', enabled=False)
        add_button("&Show Keys"  , 'show', enabled=False)
        # add_button("&Derive GPG Keypair", 'derive_gpg', enabled=False)

        self._layout.addStretch(1)

        add_button("&Generate Keys"         , 'generate').setDefault(True)
        add_button("&Load Salt and Brainkey", 'load')
        add_button("&Recover from Shares"   , 'recover')
        self._layout.addStretch(1)

        # add_button("&Debug", 'debug', enabled=False)
        # self._layout.addStretch(1)
        add_button("&Options", 'options')

        self._layout.addStretch(8)
        self.setLayout(self._layout)

    def switch(self) -> None:
        state = gpb.get_state()

        self.trace("switch " + str((state['salt'], state['brainkey'], state['params'])))

        state['panel_index'] = 0
        if state['salt'] and state['brainkey'] and state['params']:
            self.buttons['open'].setEnabled(True)
            self.buttons['show'].setEnabled(True)
        else:
            self.buttons['open'].setEnabled(False)
            self.buttons['show'].setEnabled(False)

        super().switch()

    def init_button_handler(self, button_name: str) -> typ.Callable:
        def handler(*args, **kwargs):
            self.trace(f"handle button {button_name=} {args} {kwargs}")
            p = self.parent()

            if button_name in ('generate', 'load', 'recover'):
                state = gpb.get_state()
                state['salt'    ] = None
                state['brainkey'] = None
                state['shares'  ] = []
                # state['params'  ] = None

            if button_name == 'generate':
                p.get_or_init_panel(SeedGenerationPanel).switch()
            elif button_name == 'load':
                p.get_or_init_panel(LoadKeysPanel).switch()
            elif button_name == 'recover':
                p.get_or_init_panel(RecoverKeysPanel).switch()
            elif button_name == 'options':
                p.get_or_init_panel(OptionsPanel).switch()
            elif button_name == 'open':
                p.get_or_init_panel(OpenWalletPanel).switch()
            elif button_name == 'show':
                p.get_or_init_panel(ShowKeysPanel).switch()
            elif button_name == 'debug':
                params = parameters.bytes2params(b"\x11\x00\x00")
                state  = gpb.get_state()
                state['params'] = params
                p.get_or_init_panel(OpenWalletPanel).switch()
            else:
                raise NotImplementedError()

        return handler


class OptionsPanel(gpb.NavigablePanel):
    def __init__(self, index: int):
        self.title            = "SBK - Options"
        self.back_panel_clazz = SelectCommandPanel
        self.next_panel_clazz = SelectCommandPanel

        super().__init__(index)

        self.next_button.setText("&Save")

        form = qtw.QFormLayout()

        state = gpb.get_state()

        self.offline = qtw.QCheckBox()
        self.offline.setTristate(False)
        form.addRow("&Offline", self.offline)

        # NOTE (mb 2021-09-24): Reserve wallet name function to cli
        #   for now. It might be added to the gui later if we can
        #   communicae the usage caveats to the user.
        #
        # self.wallet_name = qtw.QLineEdit()
        # if state['wallet_name'] == ui_common.DEFAULT_WALLET_NAME:
        #     self.wallet_name.setPlaceholderText(ui_common.DEFAULT_WALLET_NAME)
        # else:
        #     self.wallet_name.setText(state['wallet_name'])
        # form.addRow("&Wallet Name", self.wallet_name)

        self.sss_t = qtw.QSpinBox()
        self.sss_t.setRange(2, 5)
        form.addRow("&Threshold", self.sss_t)

        self.sss_n = qtw.QSpinBox()
        self.sss_n.setRange(3, 63)
        form.addRow("Shares", self.sss_n)

        def constrain_threshold():
            threshold = min(self.sss_n.value(), parameters.MAX_THRESHOLD)
            self.sss_t.setMaximum(threshold)

        def constrain_num_shares():
            self.sss_n.setMinimum(self.sss_t.value())

        self.sss_n.valueChanged.connect(constrain_threshold)
        self.sss_t.valueChanged.connect(constrain_num_shares)

        self.target_memory = qtw.QSpinBox()
        self.target_memory.setRange(10, state['max_memory'])
        self.target_memory.setSingleStep(10)
        form.addRow("&Memory Usage [MB]", self.target_memory)

        self.target_duration = qtw.QSpinBox()
        self.target_duration.setRange(1, 600)
        form.addRow("&Duration [Seconds]", self.target_duration)

        self._layout = qtw.QVBoxLayout()
        self._layout.addLayout(form)
        self._layout.addStretch(1)

        self._layout.addLayout(self.nav_layout)
        self.setLayout(self._layout)

    def switch(self) -> None:
        super().switch()
        state = gpb.get_state()
        self.offline.setCheckState(qtc.Qt.Checked if state['offline'] else qtc.Qt.Unchecked)
        self.sss_t.setValue(state['params'].sss_t)
        self.sss_n.setValue(state['params'].sss_n)
        self.target_memory.setValue(state['target_memory'])
        self.target_duration.setValue(state['target_duration'])

    def nav_handler(self, eventtype: str) -> typ.Callable:
        super_handler = super().nav_handler(eventtype)

        def handler() -> None:
            if eventtype == 'next':
                state = gpb.shared_panel_state
                state['offline'] = self.offline.checkState() == qtc.Qt.Checked

                state['sss_t'] = self.sss_t.value()
                state['sss_n'] = self.sss_n.value()

                target_memory = self.target_memory.value()

                state['target_memory'  ] = target_memory
                state['target_duration'] = self.target_duration.value()
            return super_handler()

        return handler


class SeedGenerationPanel(gpb.Panel):

    task1: typ.Optional[gt.ParametersWorker]
    task2: typ.Optional[gt.SeedGenerationTask]

    def __init__(self, index: int):
        self.title = "SBK - Key Derivation ..."

        super().__init__(index)

        self._layout = qtw.QVBoxLayout()

        label1 = qtw.QLabel("KDF Calibration")
        label2 = qtw.QLabel("Key Derivation")

        self.progressbar1 = qtw.QProgressBar()
        self.progressbar1.setRange(0, 5000)
        self.progressbar1.setValue(0)

        self.progressbar2 = qtw.QProgressBar()
        self.progressbar2.setRange(0, 90000)
        self.progressbar2.setValue(0)

        # Instantiated in switch(), because we want fresh parameters
        # from previous panel every time.
        self.task1 = None
        self.task2 = None

        self._layout.addWidget(label1)
        self._layout.addWidget(self.progressbar1)
        self._layout.addWidget(label2)
        self._layout.addWidget(self.progressbar2)

        self._layout.addStretch(1)
        self.setLayout(self._layout)

    def switch(self) -> None:
        self.progressbar1.setValue(0)
        self.progressbar2.setValue(0)

        state = gpb.get_state()

        self.task1 = gt.ParametersWorker(
            state['target_memory'],
            state['target_duration'],
            state['params'].sss_t,
            state['params'].sss_n,
        )
        self.task1.progress.connect(progressbar_updater(self.progressbar1))
        self.task1.finished.connect(self.on_param_config_done)

        super().switch()

        self.task1.start()

    def on_param_config_done(self, params: parameters.Parameters) -> None:
        self.trace("on_param_config_done")

        state = gpb.get_state()
        state['params'] = params

        self.task2 = gt.SeedGenerationTask(params)
        self.task2.progress.connect(progressbar_updater(self.progressbar2))
        self.task2.finished.connect(self.on_seed_generation_done)

        self.task2.start()

    def on_seed_generation_done(self, status: str) -> None:
        if status == 'ok':
            self.trace("on_seed_generation_done")
            self.parent().get_or_init_panel(SecurityWarningPanel).switch()
        else:
            qtw.QMessageBox.critical(self, 'Error', status)
            self.parent().close()


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


class SecurityWarningPanel(gpb.NavigablePanel):
    def __init__(self, index: int):
        self.title            = "SBK - Create New Wallet"
        self.back_panel_clazz = SelectCommandPanel
        self.next_panel_clazz = CreateKeysShowPanel

        super().__init__(index)

        label      = qtw.QLabel(WARNING_TEXT.strip())
        label_wrap = qtw.QHBoxLayout()
        label_wrap.addStretch(1)
        label_wrap.addWidget(label)
        label_wrap.addStretch(1)

        self._layout = qtw.QVBoxLayout()
        self._layout.addLayout(label_wrap)
        self._layout.addStretch(2)

        self._layout.addLayout(self.nav_layout)
        self.setLayout(self._layout)


class ShowKeysPanel(gpb.NavigablePanel):
    def __init__(self, index: int):
        self.title = "SBK - View Keys"

        super().__init__(index)

        self.header = gpb.header_widget()
        self.text   = qtw.QLabel()

        self.grid_widgets: typ.List[qtw.QWidget] = []
        self.grid_layout = qtw.QGridLayout()

        self._layout = qtw.QVBoxLayout()
        self._layout.addWidget(self.header)
        self._layout.addLayout(gpb.column_headers(self))
        self._layout.addLayout(self.grid_layout)

        self._layout.addStretch(1)
        self._layout.addLayout(self.nav_layout)
        self.setLayout(self._layout)

    def switch(self) -> None:
        self.trace(f"switch {type(self).__name__} {gpb.shared_panel_state['panel_index']}")

        self.header.setText(gpb.get_label_text())

        secret = gpb.get_current_secret()

        intcodes  = ui_common.bytes2intcodes(secret.secret_data)
        mnemonics = ui_common.intcodes2mnemonics(intcodes)

        num_rows = len(intcodes) // 2
        assert num_rows * 2 == len(intcodes)

        lr_intcodes = list(sum(zip(intcodes[:num_rows], intcodes[num_rows:]), ()))

        _lr_intcodes = iter(lr_intcodes)
        _mnemonics   = iter(mnemonics)

        all_row_widgets: gpb.RowWidgets = []
        while True:
            try:
                row_widgets = (
                    gpb._label_widget(self, next(_lr_intcodes), bold=True),
                    gpb._label_widget(self, next(_mnemonics  ), bold=True),
                    gpb._label_widget(self, next(_mnemonics  ), bold=True),
                    gpb._label_widget(self, next(_lr_intcodes), bold=True),
                )
                all_row_widgets.append(row_widgets)
            except StopIteration:
                break

        new_widgets = gpb.init_grid(self, self.grid_layout, all_row_widgets)
        self.grid_widgets.extend(new_widgets)

        super().switch()

    @property
    def back_panel_clazz(self) -> typ.Type[gpb.Panel]:
        state = gpb.shared_panel_state
        self.trace(f"back show {state['panel_index']}")
        if state['panel_index'] == 0:
            return SelectCommandPanel
        else:
            state['panel_index'] -= 1
            return ShowKeysPanel

    @property
    def next_panel_clazz(self) -> typ.Type[gpb.Panel]:
        state = gpb.shared_panel_state
        self.trace(f"next show {state['panel_index']}")
        if state['panel_index'] + 1 < len(state['shares']) + 2:
            state['panel_index'] += 1
            return ShowKeysPanel
        else:
            return SelectCommandPanel

    def destroy_panel(self) -> None:
        for widget in self.grid_widgets:
            self.grid_layout.removeWidget(widget)
            widget.deleteLater()

        del self.grid_widgets[:]

        super().destroy_panel()


class CreateKeysShowPanel(ShowKeysPanel):
    def __init__(self, index: int):
        self.title = "SBK - Create New Wallet"
        super().__init__(index)

    @property
    def back_panel_clazz(self) -> typ.Type[gpb.Panel]:
        self.trace(f"back show {gpb.shared_panel_state['panel_index']}")
        if gpb.shared_panel_state['panel_index'] == 0:
            return SecurityWarningPanel
        else:
            gpb.shared_panel_state['panel_index'] = max(gpb.shared_panel_state['panel_index'] - 1, 0)
            return CreateKeysVerifyPanel

    @property
    def next_panel_clazz(self) -> typ.Type[gpb.Panel]:
        self.trace(f"next show {gpb.shared_panel_state['panel_index']}")
        return CreateKeysVerifyPanel


MaybeBytes = typ.Union[bytes, None]


class CreateKeysVerifyPanel(gpb.EnterSecretPanel):
    def __init__(self, index: int):
        self.title = "SBK - Create New Wallet"
        super().__init__(index)

    def label_text(self) -> str:
        return gpb.get_label_text()

    def secret_len(self) -> int:
        current_secret = gpb.get_current_secret()
        return len(current_secret.secret_data)

    @property
    def back_panel_clazz(self) -> typ.Type[gpb.Panel]:
        return CreateKeysShowPanel

    @property
    def next_panel_clazz(self) -> typ.Type[gpb.Panel]:
        state       = gpb.shared_panel_state
        num_shares  = len(state['shares'])
        num_secrets = num_shares + 2
        if state['panel_index'] + 1 < num_secrets:
            state['panel_index'] = max(state['panel_index'] + 1, 0)
            return CreateKeysShowPanel
        else:
            return SelectCommandPanel

    def is_final_panel(self) -> bool:
        state       = gpb.shared_panel_state
        num_shares  = len(state['shares'])
        num_secrets = num_shares + 2
        return state['panel_index'] + 1 >= num_secrets


class LoadKeysPanel(gpb.EnterSecretPanel):
    def __init__(self, index: int):
        self.title = "SBK - Load Wallet"
        super().__init__(index)

    def label_text(self) -> str:
        if gpb.shared_panel_state['panel_index'] == 0:
            return "Enter Salt"
        else:
            return "Enter Brainkey"

    def secret_len(self) -> int:
        params = gpb.get_params()
        lens   = parameters.raw_secret_lens()
        if gpb.shared_panel_state['panel_index'] == 0:
            return lens.salt
        else:
            return lens.brainkey

    @property
    def back_panel_clazz(self) -> typ.Type[gpb.Panel]:
        state = gpb.shared_panel_state
        if state['panel_index'] == 0:
            return SelectCommandPanel
        else:
            state['panel_index'] = max(state['panel_index'] - 1, 0)
            return LoadKeysPanel

    @property
    def next_panel_clazz(self) -> typ.Type[gpb.Panel]:
        state = gpb.shared_panel_state
        if state['panel_index'] == 0:
            state['panel_index'] = max(state['panel_index'] + 1, 0)
            return LoadKeysPanel
        else:
            return SelectCommandPanel

    def destroy_panel(self) -> None:
        state           = gpb.shared_panel_state
        recovered_datas = self.recover_datas()
        if all(recovered_datas):
            recovered_data = b"".join(recovered_datas)  # type: ignore

            params = gpb.get_params()
            lens   = parameters.raw_secret_lens()
            if state['panel_index'] == 0:
                assert len(recovered_data) == lens.salt
                header = recovered_data[: parameters.SALT_HEADER_LEN]
                state['params'] = parameters.bytes2params(header)
                state['salt'  ] = ct.Salt(recovered_data)
            else:
                assert len(recovered_data) == lens.brainkey
                state['brainkey'] = ct.BrainKey(recovered_data)

            params   = state['params']
            salt     = state['salt']
            brainkey = state['brainkey']

            if params and salt and brainkey:
                raw_salt = ct.RawSalt(bytes(salt)[parameters.SALT_HEADER_LEN :])
                shares   = shamir.split(params, raw_salt, brainkey)
                state['shares'] = shares

        super().destroy_panel()


def progressbar_updater(progressbar: qtw.QProgressBar) -> typ.Callable[[gt.ProgressStatus], None]:
    def update_progressbar(status: gt.ProgressStatus) -> None:
        try:
            progressbar.setRange(0, status.length)
            progressbar.setValue(round(status.current))
        except RuntimeError:
            pass

    return update_progressbar


def load_wallet() -> None:
    def launch():
        seed_data = gpb.shared_panel_state['seed_data']
        offline   = gpb.shared_panel_state['offline']
        assert seed_data is not None
        ui_common.load_wallet(seed_data, offline)

    launcher_thread = threading.Thread(target=launch, daemon=False)
    launcher_thread.start()

    # Delay closing the panel while the wallet loads
    # this is a bit less jarring.
    electrum_daemon_path = pl.Path("~").expanduser() / ".electrum" / "daemon"

    wait_start = time.time()
    while True:
        if os.path.exists(electrum_daemon_path):
            time.sleep(0.5)
            return

        if time.time() - wait_start > 5:
            return

        time.sleep(0.1)


class OpenWalletPanel(gpb.Panel):

    task: typ.Optional[gt.SeedDerivationTask]

    def __init__(self, index: int):
        self.title = "SBK - Key Derivation ..."

        super().__init__(index)

        self._layout = qtw.QVBoxLayout()

        label = qtw.QLabel("KDF Derivation")

        self.progressbar = qtw.QProgressBar()
        self.progressbar.setRange(0, 5000)
        self.progressbar.setValue(0)

        # Instantiated in switch(), because we want fresh parameters
        # from previous panel every time.
        self.task = None

        self._layout.addWidget(label)
        self._layout.addWidget(self.progressbar)

        self._layout.addStretch(1)
        self.setLayout(self._layout)

    def switch(self) -> None:
        self.trace("switch")

        state     = gpb.get_state()
        seed_data = state['seed_data']
        params    = state['params']

        assert params is not None

        if seed_data is None:
            salt     = state['salt']
            brainkey = state['brainkey']
            assert salt     is not None
            assert brainkey is not None

            self.task = gt.SeedDerivationTask(params, salt, brainkey)
            self.task.progress.connect(progressbar_updater(self.progressbar))
            self.task.finished.connect(self.on_key_dervation_done)

            super().switch()

            self.trace("start derivation")
            self.task.start()
        else:
            # seed_data freshly generated
            load_wallet()
            self.parent().close()
            return

    def on_key_dervation_done(self, status: str) -> None:
        if status == 'ok':
            self.trace("OpenWalletPanel.on_key_dervation_done")
            load_wallet()
            self.parent().close()
        else:
            qtw.QMessageBox.critical(self, 'Error', status)
            self.parent().close()

    def is_final_panel(self) -> bool:
        # pylint: disable=no-self-use   # override for ABC
        return True


class RecoverKeysPanel(gpb.EnterSecretPanel):
    def __init__(self, index: int):
        self.title = "SBK - Recover Wallet"
        super().__init__(index)

    def label_text(self) -> str:
        params = gpb.get_params()
        if params is None:
            num_shares = -1
        else:
            num_shares = params.sss_n

        panel_index = gpb.shared_panel_state['panel_index']
        share_no    = panel_index + 1
        if num_shares == -1:
            return f"Enter Share {share_no}/N"
        else:
            return f"Enter Share {share_no}/{num_shares}"

    def secret_len(self) -> int:
        params = gpb.get_params()
        lens   = parameters.raw_secret_lens()
        return lens.share

    def destroy_panel(self) -> None:
        recovered_datas = self.recover_datas()
        if all(recovered_datas):
            share_data = ct.Share(b"".join(recovered_datas))  # type: ignore
            shares     = gpb.shared_panel_state['shares']
            gpb.shared_panel_state['shares'] = list(shares) + [share_data]

        super().destroy_panel()

    @property
    def back_panel_clazz(self) -> typ.Type[gpb.Panel]:
        panel_index = gpb.shared_panel_state['panel_index']
        if panel_index == 0:
            return SelectCommandPanel
        else:
            gpb.shared_panel_state['panel_index'] = max(panel_index - 1, 0)
            return RecoverKeysPanel

    @property
    def next_panel_clazz(self) -> typ.Type[gpb.Panel]:
        state       = gpb.shared_panel_state
        panel_index = state['panel_index']
        if panel_index == 0:
            state['panel_index'] = panel_index + 1
            return RecoverKeysPanel
        else:
            params = gpb.get_params()
            # we should only reach here if a valid share was entered previously
            assert params is not None
            if len(state['shares']) < params.sss_n:
                state['panel_index'] = panel_index + 1
                return RecoverKeysPanel
            else:
                raw_salt, brainkey = shamir.join(params, state['shares'])
                # recompute shares, because user only enters as many as needed
                shares = shamir.split(params, raw_salt, brainkey)

                params_data = parameters.params2bytes(params)
                salt        = ct.Salt(params_data + raw_salt)
                state['salt'    ] = salt
                state['brainkey'] = brainkey
                state['shares'  ] = shares
                return SelectCommandPanel

    def is_final_panel(self) -> bool:
        params = gpb.get_params()
        assert params is not None
        return len(gpb.shared_panel_state['shares']) >= params.sss_n
