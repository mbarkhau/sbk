import typing as typ

import click
from sbk import enc_util

from . import prompt_toolkit_shortcuts as pts

_phrase0_words = [w.upper() for w in enc_util.ADJECTIVES]
_phrase1_words = [w.upper() for w in enc_util.TITLES]
_phrase2_words = [w.upper() for w in enc_util.CITIES]
_phrase3_words = [w.upper() for w in enc_util.PLACES]

_phrase0_completer = pts.FuzzyWordCompleter(_phrase0_words)
_phrase1_completer = pts.FuzzyWordCompleter(_phrase1_words)
_phrase2_completer = pts.FuzzyWordCompleter(_phrase2_words)
_phrase3_completer = pts.FuzzyWordCompleter(_phrase3_words)


DEFAULT_PHRASE = "__ __  The ______ ______ at the ______ ______ ."


@click.group()
def cli() -> None:
    """Cli for SBK."""


def fmt(html_text: str) -> pts.FormattedText:
    return pts.to_formatted_text(pts.HTML(html_text))


def out(*msg: typ.Any) -> None:
    with open("/tmp/out", mode="a") as fobj:
        print(*msg, file=fobj)


class PhraseCompleter(pts.FuzzyWordCompleter):
    def get_completions(
        self, document: pts.Document, complete_event: pts.CompleteEvent
    ):
        out("-->", document)
        out("-->", complete_event)
        for c in super().get_completions(document, complete_event):
            yield c


class NoopProcessor(pts.Processor):
    def apply_transformation(
        self, ti: pts.TransformationInput
    ) -> pts.Transformation:

        # out(">>>", ti.lineno)
        # out("...", ti)

        new_fragments: typ.List[typ.Tuple[str, str]] = []
        for styles, text in ti.fragments:
            # out(repr(text))
            new_fragments.append((styles, text))

        def display_to_source(from_position: int) -> int:
            if self._first_transform:
                out("--->", from_position)
                self._first_transform = False
                return 1
            return from_position

        return pts.Transformation(
            fragments=new_fragments, display_to_source=display_to_source
        )


def _reformat_phrases(value: str) -> str:
    out(":::", repr(value))
    return value


def prompt_continuation(width, line_number, is_soft_wrap) -> str:
    return f"{line_number + 1:>2}. "


@cli.command()
def pttest() -> None:
    phrase_template = "\n".join([DEFAULT_PHRASE for i in range(6)])

    noop_processor = NoopProcessor()

    bindings = pts.KeyBindings()

    res = pts.prompt(
        " 1. ",
        default=phrase_template,
        # completer=PhraseCompleter(_phrase0_words),
        # complete_while_typing=True,
        multiline=True,
        mouse_support=True,
        input_processors=[noop_processor],
        prompt_continuation=prompt_continuation,
        key_bindings=bindings,
    )
    print(res)


@cli.command()
def pt_matrix_test() -> None:

    # s = pt.PromptSession()
    #
    # s.prompt(
    #     completer=PhraseCompleter(_phrase0_words),
    #     default=phrase_template,
    #     complete_while_typing=True,
    #     multiline=True,
    #     mouse_support=True,
    # )
    bindings = pts.KeyBindings()

    @bindings.add('c-q')
    @bindings.add('c-c')
    def exit_app(event):
        """
        Pressing Ctrl-Q or Ctrl-C will exit the user interface.

        Setting a return value means: quit the event loop that drives the user
        interface and return this value from the `Application.run()` call.
        """
        event.app.exit()

    def _cursor_pos(*args, **kwargs):
        out(args)
        out(kwargs)
        return pts.Point(2, 0)

    inputs = []

    num_phrases      = 6
    num_phrase_words = 4

    container_matrix = [[] for _ in range(num_phrases)]

    completers = [
        _phrase0_completer,
        _phrase1_completer,
        _phrase2_completer,
        _phrase3_completer,
    ]

    for row_idx in range(num_phrases):
        for col_idx in range(num_phrase_words):
            if col_idx == 0:
                container_matrix[row_idx].append(
                    pts.Window(pts.FormattedTextControl("The "))
                )
            elif col_idx == 2:
                container_matrix[row_idx].append(
                    pts.Window(pts.FormattedTextControl(" at the "))
                )
            else:
                container_matrix[row_idx].append(
                    pts.Window(pts.FormattedTextControl(" "))
                )
            # input_index = row_idx * num_phrase_words + col_idx
            textarea = pts.TextArea(
                text="",
                multiline=False,
                completer=completers[col_idx],
                complete_while_typing=True,
                width=8,
                height=1,
                focus_on_click=True,
                style="bg:#888888",
            )

            inputs.append(textarea)
            container_matrix[row_idx].append(textarea)
        container_matrix[row_idx].append(
            pts.Window(pts.FormattedTextControl("."))
        )

    state = {'focus': 0}

    @bindings.add("right")
    def _next_control(event):
        out("next", event)
        state['focus'] = min(len(inputs), state['focus'] + 1)
        app.layout.focus(inputs[state['focus']])

    @bindings.add("left")
    def _prev_control(event):
        out("prev", event)
        state['focus'] = max(0, state['focus'] - 1)
        app.layout.focus(inputs[state['focus']])

    phrase_layouts = []

    for row_containers in container_matrix:
        phrase_layouts.append(
            pts.VSplit(
                row_containers,
                align=pts.HorizontalAlign.LEFT,
                width=num_phrase_words * 8 + 20,
            )
        )

    layout = pts.Layout(
        pts.VSplit(
            [
                pts.HSplit(
                    phrase_layouts,
                    height=num_phrases,
                    width=num_phrase_words * 8 + 20,
                )
            ],
            align=pts.HorizontalAlign.LEFT,
        )
    )

    pts.CompleteStyle.COLUMN

    app = pts.Application(
        layout=layout,
        key_bindings=bindings,
        full_screen=True,
        mouse_support=True,
    )
    app.run()


if __name__ == '__main__':
    cli()
