#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""GUI Tasks (on threads) for SBK."""
import time
import typing as typ
import logging

import PyQt5.QtCore as qtc

from . import kdf
from . import params
from . import ui_common
from . import common_types as ct
from . import gui_panels_base as gpb

logger = logging.getLogger("sbk.gui_tasks")


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


class SeedGenerationTask(qtc.QThread):

    progress = qtc.pyqtSignal(ProgressStatus)
    finished = qtc.pyqtSignal(str)

    def __init__(self, param_cfg: params.ParamConfig) -> None:
        super().__init__()
        self.param_cfg = param_cfg

    def run(self) -> None:
        try:
            ui_common.validated_param_data(self.param_cfg)
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
            self.finished.emit(errmsg)
            return

        salt, brainkey, shares = ui_common.create_secrets(self.param_cfg)

        # NOTE (mb 2021-07-09): We could do this later in theory, but
        #   if the derivation of seed_data fails, the user would have
        #   written down their shares that are useless. Better to
        #   provoke any such error early on.
        seed_data = ui_common.derive_seed(
            self.param_cfg.kdf_params,
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
        param_cfg: params.ParamConfig,
        salt     : ct.Salt,
        brainkey : ct.BrainKey,
    ) -> None:
        super().__init__()
        self.param_cfg = param_cfg
        self.salt      = salt
        self.brainkey  = brainkey

    def run(self) -> None:
        try:
            # provoke error for invalid data
            ui_common.validated_param_data(self.param_cfg)
        except ValueError as err:
            if err.args and isinstance(err.args[0], list):
                bad_checks = err.args[0]
                errmsg     = "\n".join(bad_checks)
            else:
                errmsg = str(err)

            self.finished.emit(errmsg)
            return

        brainkey = self.brainkey
        salt     = self.salt

        seed_data = ui_common.derive_seed(
            self.param_cfg.kdf_params,
            salt,
            brainkey,
            label="KDF Validation ",
            init_progressbar=init_progres_status_emitter_clazz(self.progress),
        )

        state = gpb.shared_panel_state
        state['salt'     ] = salt
        state['brainkey' ] = brainkey
        state['seed_data'] = seed_data

        self.finished.emit("ok")


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
