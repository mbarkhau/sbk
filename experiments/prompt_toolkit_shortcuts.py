# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Prompt Toolkit Shortcuts."""

import importlib

shortcuts = [
    "prompt_toolkit.Application",
    "prompt_toolkit.buffer.Buffer",
    "prompt_toolkit.completion.CompleteEvent",
    "prompt_toolkit.completion.Completer",
    "prompt_toolkit.completion.Completion",
    "prompt_toolkit.completion.FuzzyCompleter",
    "prompt_toolkit.completion.Completer",
    "prompt_toolkit.completion.FuzzyWordCompleter",
    "prompt_toolkit.completion.WordCompleter",
    "prompt_toolkit.document.Document",
    "prompt_toolkit.formatted_text.FormattedText",
    "prompt_toolkit.formatted_text.to_formatted_text",
    "prompt_toolkit.key_binding.KeyBindings",
    "prompt_toolkit.layout.containers.VSplit",
    "prompt_toolkit.layout.containers.HSplit",
    "prompt_toolkit.layout.containers.Window",
    "prompt_toolkit.layout.containers.VerticalAlign",
    "prompt_toolkit.layout.containers.HorizontalAlign",
    "prompt_toolkit.layout.containers.WindowAlign",
    "prompt_toolkit.layout.controls.BufferControl",
    "prompt_toolkit.layout.controls.FormattedTextControl",
    "prompt_toolkit.layout.layout.Layout",
    "prompt_toolkit.layout.screen.Point",
    "prompt_toolkit.prompt",
    "prompt_toolkit.PromptSession",
    "prompt_toolkit.widgets.Frame",
    "prompt_toolkit.widgets.Label",
    "prompt_toolkit.widgets.TextArea",
    "prompt_toolkit.widgets.ProgressBar",
    "prompt_toolkit.widgets.MenuContainer",
    "prompt_toolkit.widgets.MenuItem",
    "prompt_toolkit.shortcuts.prompt.CompleteStyle",
    "prompt_toolkit.layout.processors.Processor",
    "prompt_toolkit.layout.processors.Transformation",
    "prompt_toolkit.layout.processors.TransformationInput",
    "prompt_toolkit.styles.Style",
]

attr_names = []

for shortcut in shortcuts:
    module_name, attr_name = shortcut.rsplit(".", 1)
    module = importlib.import_module(module_name)
    globals()[attr_name] = getattr(module, attr_name)
    attr_names.append(attr_name)

__all__ = attr_names
