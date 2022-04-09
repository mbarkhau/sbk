#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""GUI Tasks (on threads) for SBK."""
import time
import logging
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

import PyQt5.QtCore as qtc

from . import ui_common
from . import parameters
from . import sbk_random
from . import common_types as ct
from . import gui_panels_base as gpb

logger = logging.getLogger("sbk.gui_tasks")


class ProgressStatus(NamedTuple):

    current: int
    length : int


def init_progres_status_emitter_clazz(signal) -> Callable:
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


class SeedGenerationTask(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(str)

    def __init__(self, params: parameters.Parameters) -> None:
        super().__init__()
        self.params = params

    def run(self) -> None:
        try:
            ui_common.validated_param_data(self.params)
        except ValueError as err:
            if err.args and isinstance(err.args[0], list):
                bad_checks = err.args[0]
                errmsg     = "\n".join(bad_checks)
            else:
                errmsg = str(err)

            self.finished.emit(errmsg)
            return

        n = 0
        while True:
            entropy = sbk_random.get_entropy_pool_size()
            if entropy < parameters.MIN_ENTROPY and n < parameters.MAX_ENTROPY_WAIT:
                logger.warning(f"low on entropy ({entropy}), waiting a bit for it to accumulate")
                time.sleep(1)
                n += 1
            else:
                break

        if entropy < parameters.MIN_ENTROPY:
            errmsg = f"Not enough entropy: {entropy} < {parameters.MIN_ENTROPY}"
            logger.error(errmsg)
            self.finished.emit(errmsg)
            return

        salt, brainkey, shares = ui_common.create_secrets(self.params)

        # NOTE (mb 2021-07-09): We could do this later in theory, but
        #   if the derivation of seed_data fails, the user would have
        #   written down their shares that are useless. Better to
        #   provoke any such error early on.
        seed_data = ui_common.derive_seed(
            self.params,
            salt,
            brainkey,
            label="KDF Validation ",
            init_progressbar=init_progres_status_emitter_clazz(self.progress),
        )

        gpb.shared_panel_state['salt'     ] = salt
        gpb.shared_panel_state['brainkey' ] = brainkey
        gpb.shared_panel_state['shares'   ] = shares
        gpb.shared_panel_state['seed_data'] = seed_data

        self.finished.emit("ok")


class SeedDerivationTask(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(str)

    def __init__(
        self,
        params  : parameters.Parameters,
        salt    : ct.Salt,
        brainkey: ct.BrainKey,
    ) -> None:
        super().__init__()
        self.params   = params
        self.salt     = salt
        self.brainkey = brainkey

    def run(self) -> None:
        try:
            # provoke error for invalid data
            ui_common.validated_param_data(self.params)
        except ValueError as err:
            if err.args and isinstance(err.args[0], list):
                bad_checks = err.args[0]
                errmsg     = "\n".join(bad_checks)
            else:
                errmsg = str(err)

            self.finished.emit(errmsg)
            return

        seed_data = ui_common.derive_seed(
            self.params,
            self.salt,
            self.brainkey,
            label="KDF Validation ",
            init_progressbar=init_progres_status_emitter_clazz(self.progress),
        )

        state = gpb.shared_panel_state
        state['salt'     ] = self.salt
        state['brainkey' ] = self.brainkey
        state['seed_data'] = seed_data

        self.finished.emit("ok")


class ParametersWorker(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(parameters.Parameters)

    def __init__(
        self,
        target_memory  : ct.MebiBytes,
        target_duration: ct.Seconds,
        threshold      : int,
        num_shares     : int,
    ) -> None:
        super().__init__()
        self.target_memory   = target_memory
        self.target_duration = target_duration

        self.threshold  = threshold
        self.num_shares = num_shares

    def run(self) -> None:
        params = ui_common.init_params(
            target_duration=self.target_duration,
            memory_cost=self.target_memory,
            time_cost=None,  # auto from target_duration
            threshold=self.threshold,
            num_shares=self.num_shares,
            init_progressbar=init_progres_status_emitter_clazz(self.progress),
        )
        self.finished.emit(params)
