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
import re
import time
import typing as typ
import logging
import pathlib as pl
import threading

import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc
import PyQt5.QtWidgets as qtw

from . import cli_io
from . import params
from . import shamir
from . import gui_tasks as gt
from . import ui_common
from . import common_types as ct
from . import gui_panels_base as gpb

logger = logging.getLogger("sbk.gui_panels")


ICON_PATH = pl.Path("logo_256.png")


class SelectCommandPanel(gpb.Panel):

    buttons: typ.Dict[str, qtw.QPushButton]

    def __init__(self, index: int):
        self.title = "SBK"

        super().__init__(index)

        self._layout = qtw.QVBoxLayout()

        pixmap     = qtg.QPixmap(str(ICON_PATH))
        pixmap     = pixmap.scaledToWidth(128)
        icon_label = qtw.QLabel(self)
        icon_label.setPixmap(pixmap)
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

        add_button("Open &Electrum", 'open', enabled=False)
        add_button("&Show Keys"    , 'show', enabled=False)
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

        self.trace("switch " + str((state['salt'], state['brainkey'], state['param_cfg'])))

        state['panel_index'] = 0
        if state['salt'] and state['brainkey'] and state['param_cfg']:
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
                gpb.shared_panel_state['salt'     ] = None
                gpb.shared_panel_state['brainkey' ] = None
                gpb.shared_panel_state['param_cfg'] = None
                gpb.shared_panel_state['shares'   ] = []

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
                param_cfg = params.bytes2param_cfg(b"\x11\x00\x00")
                gpb.shared_panel_state['param_cfg'] = param_cfg
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

        self.next_button.setVisible(False)

        form = qtw.QFormLayout()

        state = gpb.get_state()

        self.offline = qtw.QCheckBox()
        self.offline.setTristate(False)
        self.offline.setCheckState(qtc.Qt.Checked if state['offline'] else qtc.Qt.Unchecked)
        form.addRow("&Offline", self.offline)

        self.wallet_name = qtw.QLineEdit()
        if state['wallet_name'] == 'empty':
            self.wallet_name.setPlaceholderText("empty")
        else:
            self.wallet_name.setText(state['wallet_name'])
        form.addRow("&Wallet Name", self.wallet_name)

        self.threshold = qtw.QSpinBox()
        self.threshold.setRange(2, 5)
        self.threshold.setValue(state['threshold'])
        form.addRow("&Threshold", self.threshold)

        self.num_shares = qtw.QSpinBox()
        self.num_shares.setRange(3, 63)
        self.num_shares.setValue(state['num_shares'])
        form.addRow("&Shares", self.num_shares)

        def constrain_threshold():
            threshold = min(self.num_shares.value(), params.MAX_THRESHOLD)
            self.threshold.setMaximum(threshold)

        def constrain_num_shares():
            self.num_shares.setMinimum(self.threshold.value())

        self.num_shares.valueChanged.connect(constrain_threshold)
        self.threshold.valueChanged.connect(constrain_num_shares)

        self.parallelism = qtw.QSpinBox()
        self.parallelism.setRange(1, state['max_parallelism'])
        self.parallelism.setValue(state['parallelism'])
        form.addRow("&Parallelism [Threads]", self.parallelism)

        self.target_memory = qtw.QSpinBox()
        self.target_memory.setRange(10, state['max_memory'])
        self.target_memory.setValue(state['target_memory'])
        self.target_memory.setSingleStep(10)
        form.addRow("&Memory Usage [MB]", self.target_memory)

        self.target_duration = qtw.QSpinBox()
        self.target_duration.setRange(1, 600)
        self.target_duration.setValue(state['target_duration'])
        form.addRow("&Duration [Seconds]", self.target_duration)

        self._layout = qtw.QVBoxLayout()
        self._layout.addLayout(form)
        self._layout.addStretch(1)

        self._layout.addLayout(self.nav_layout)
        self.setLayout(self._layout)

    def destroy_panel(self) -> None:
        state = gpb.shared_panel_state

        target_memory = self.target_memory.value()
        parallelism   = self.parallelism.value()

        state['threshold'        ] = self.threshold.value()
        state['num_shares'       ] = self.num_shares.value()
        state['parallelism'      ] = parallelism
        state['target_memory'    ] = target_memory
        state['target_duration'  ] = self.target_duration.value()
        state['memory_per_thread'] = round(target_memory / parallelism)


class SeedGenerationPanel(gpb.Panel):

    task1: typ.Optional[gt.ParamConfigWorker]
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

        threshold         = state['threshold']
        num_shares        = state['num_shares']
        parallelism       = state['parallelism']
        memory_per_thread = state['memory_per_thread']
        target_duration   = state['target_duration']

        self.task1 = gt.ParamConfigWorker(
            threshold, num_shares, parallelism, memory_per_thread, target_duration
        )
        self.task1.progress.connect(progressbar_updater(self.progressbar1))
        self.task1.finished.connect(self.on_param_config_done)

        super().switch()

        self.task1.start()

    def on_param_config_done(self, param_cfg: params.ParamConfig) -> None:
        self.trace("on_param_config_done")

        gpb.shared_panel_state['param_cfg'] = param_cfg

        self.task2 = gt.SeedGenerationTask(param_cfg)
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

        # TODO (mb 2021-07-10): kinda hacky to go through the format secret logic
        #    and parse it back out
        output_lines = cli_io.format_secret_lines(secret.secret_type, secret.secret_data)
        content      = "\n".join(line[3:] for line in output_lines)
        all_row_widgets: gpb.RowWidgets = []
        intcodes  = iter(re.findall(r"\b([0-9]{3}-[0-9]{3})\b", content))
        mnemonics = iter(re.findall(r"\b([a-z]{5,8})\b"       , content))

        while True:
            try:
                row_widgets = (
                    gpb._label_widget(self, next(intcodes ), bold=True),
                    gpb._label_widget(self, next(mnemonics), bold=True),
                    gpb._label_widget(self, next(mnemonics), bold=True),
                    gpb._label_widget(self, next(intcodes ), bold=True),
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
        if gpb.shared_panel_state['panel_index'] == 0:
            return params.SALT_LEN
        else:
            return params.BRAINKEY_LEN

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

            if state['panel_index'] == 0:
                assert len(recovered_data) == params.SALT_LEN
                state['param_cfg'] = params.bytes2param_cfg(recovered_data)
                state['salt'     ] = ct.Salt(recovered_data)
            else:
                assert len(recovered_data) == params.BRAINKEY_LEN
                state['brainkey'] = ct.BrainKey(recovered_data)

            param_cfg = state['param_cfg']
            salt      = state['salt']
            brainkey  = state['brainkey']

            if param_cfg and salt and brainkey:
                param_cfg = param_cfg._replace(num_shares=state['num_shares'])
                raw_salt  = ct.RawSalt(bytes(salt)[params.PARAM_CFG_LEN :])
                shares    = shamir.split(param_cfg, raw_salt, brainkey)
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
    wait_start           = time.time()
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
        param_cfg = state['param_cfg']

        assert param_cfg is not None

        if seed_data is None:
            salt     = state['salt']
            brainkey = state['brainkey']
            assert salt     is not None
            assert brainkey is not None

            self.task = gt.SeedDerivationTask(param_cfg, salt, brainkey)
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
        param_cfg = gpb.get_param_cfg()
        if param_cfg is None:
            num_shares = -1
        else:
            num_shares = param_cfg.num_shares

        panel_index = gpb.shared_panel_state['panel_index']
        share_no    = panel_index + 1
        if num_shares == -1:
            return f"Enter Share {share_no}/N"
        else:
            return f"Enter Share {share_no}/{num_shares}"

    def secret_len(self) -> int:
        return params.SHARE_LEN

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
            param_cfg = gpb.get_param_cfg()
            # we should only reach here if a valid share was entered previously
            assert param_cfg is not None
            num_shares = param_cfg.num_shares
            if len(state['shares']) < num_shares:
                state['panel_index'] = panel_index + 1
                return RecoverKeysPanel
            else:
                raw_salt, brainkey = shamir.join(param_cfg, state['shares'])
                # recompute shares, because user only enters as many as needed
                shares = shamir.split(param_cfg, raw_salt, brainkey)

                param_cfg_data = params.param_cfg2bytes(param_cfg)
                salt           = ct.Salt(param_cfg_data + raw_salt)
                state['salt'    ] = salt
                state['brainkey'] = brainkey
                state['shares'  ] = shares
                return SelectCommandPanel

    def is_final_panel(self) -> bool:
        param_cfg = gpb.get_param_cfg()
        assert param_cfg is not None
        num_shares = param_cfg.num_shares
        return len(gpb.shared_panel_state['shares']) >= num_shares
