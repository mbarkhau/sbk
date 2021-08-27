#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

# type: ignore

"""GUI for SBK.

PyQT docs:
- https://realpython.com/python-pyqt-gui-calculator/
- https://zetcode.com/gui/pyqt5/
"""
import os
import sys
import typing as typ
import logging
import platform

import PyQt5.Qt as qt
import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc
import PyQt5.QtWidgets as qtw

from . import gui_panels
from . import package_data
from . import gui_panels_base as gpb

logger = logging.getLogger("sbk.gui")


class MainGUI(qtw.QStackedWidget):
    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("SBK")
        pixmap = qtg.QPixmap()
        pixmap.loadFromData(package_data.read_binary("logo_256.png"))
        self.setWindowIcon(qtg.QIcon(pixmap))

        select_command_panel = gui_panels.SelectCommandPanel(0)
        self.addWidget(select_command_panel)
        select_command_panel.switch()

    def get_or_init_panel(self, clazz: typ.Type[gpb.Panel]) -> gpb.Panel:
        _panel      = self.findChild(clazz)
        maybe_panel = typ.cast(typ.Optional[gpb.Panel], _panel)
        if maybe_panel is None:
            logger.info(f"get_or_init_panel init: {clazz.__name__}")
            index = self.count()
            panel = clazz(index)
            self.addWidget(panel)
            return panel
        else:
            logger.info(f"get_or_init_panel get : {clazz.__name__}")
            return maybe_panel

    def keyPressEvent(self, e):
        val     = e.key()
        mod     = e.modifiers()
        is_ctrl = mod & qt.Qt.ControlModifier
        is_alt  = mod & qt.Qt.AltModifier
        if val == qt.Qt.Key_Q and (is_ctrl or is_alt):
            self.close()


def _screen_size(app: qtw.QApplication) -> typ.Tuple[int, int]:
    screen = app.primaryScreen()
    size   = screen.size()
    return (size.width(), size.height())


def gui() -> None:
    # cargo cult qt initialization
    qtw.QApplication.setAttribute(qtc.Qt.AA_EnableHighDpiScaling, True)
    if platform.system() == 'Linux':
        qtc.QCoreApplication.setAttribute(qtc.Qt.AA_X11InitThreads)
    if hasattr(qtg.QGuiApplication, 'setDesktopFileName'):
        qtg.QGuiApplication.setDesktopFileName("sbk.desktop")
    if hasattr(qtg.QGuiApplication, 'applicationDisplayName'):
        qtg.QGuiApplication.setApplicationDisplayName('SBK')

    app = qtw.QApplication(sys.argv)

    # w, h = _screen_size(app)

    sbk_dialog = MainGUI()
    x, y = map(int, os.getenv('SBK_WIN_OFFSET', "200x200").split("x"))
    sbk_dialog.setGeometry(x, y, 550, 540)
    sbk_dialog.show()
    app.exec()
    sys.exit()


def main() -> None:
    import sbk.cli

    sbk.cli._configure_logging(verbosity=2)
    gui()


if __name__ == '__main__':
    main()
