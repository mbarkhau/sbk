import os

import sbk.gui_panels as gp
import sbk.gui_panels_base as gpb
from sbk import params
from sbk import ui_common


def test_panel(qtbot):
    os.environ['SBK_PROGRESS_BAR'] = "0"

    param_cfg = params.bytes2param_cfg(b"\x11\x00\x00")
    state     = gpb.shared_panel_state
    state['param_cfg'        ] = param_cfg
    state['threshold'        ] = 2
    state['num_shares'       ] = 3
    state['parallelism'      ] = 1
    state['target_memory'    ] = 10
    state['target_duration'  ] = 1
    state['memory_per_thread'] = 10

    salt, brainkey, shares = ui_common.create_secrets(param_cfg)

    # NOTE (mb 2021-07-09): We could do this later in theory, but
    #   if the derivation of seed_data fails, the user would have
    #   written down their shares that are useless. Better to
    #   provoke any such error early on.
    seed_data = ui_common.derive_seed(
        param_cfg.kdf_params,
        salt,
        brainkey,
        label="KDF Validation ",
    )

    gpb.shared_panel_state['salt'     ] = salt
    gpb.shared_panel_state['brainkey' ] = brainkey
    gpb.shared_panel_state['shares'   ] = shares
    gpb.shared_panel_state['seed_data'] = seed_data

    panel = gp.SelectCommandPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    panel = gp.OptionsPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    panel = gp.SecurityWarningPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    panel = gp.SeedGenerationPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    panel = gp.ShowKeysPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    panel = gp.CreateKeysShowPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    panel = gp.CreateKeysVerifyPanel(0)
    qtbot.addWidget(panel)
    panel.switch()

    # print("RecoverKeysPanel")
    # panel = gp.RecoverKeysPanel(0)
    # qtbot.addWidget(panel)
    # panel.switch()

    # print("LoadKeysPanel")
    # panel = gp.LoadKeysPanel(0)
    # qtbot.addWidget(panel)
    # panel.switch()

    # print("OpenWalletPanel")
    # panel = gp.OpenWalletPanel(0)
    # qtbot.addWidget(panel)
    # panel.switch()

    # # click in the Greet button and make sure it updates the appropriate label
    # qtbot.mouseClick(widget.button_greet, qt_api.QtCore.Qt.MouseButton.LeftButton)

    # assert widget.greet_label.text() == "Hello!"
