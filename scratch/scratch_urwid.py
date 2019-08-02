import string
import typing as typ

import click
import urwid


def out(*msg: typ.Any) -> None:
    with open("/tmp/out", mode="a") as fobj:
        print(*msg, file=fobj)


class CustomEdit(urwid.Edit):

    def __init__(self, *args, **kwargs):
        self._max_chars = kwargs.pop('max_chars')
        self._valid_chars = kwargs.pop('valid_chars')
        super().__init__(*args, **kwargs)

    def valid_char(self, ch: str) -> bool:
        return len(ch) == 1 and ch in self._valid_chars

    def keypress(self, size, key):
        out("!;!;!;!", size, key)
        (maxcol,) = size
        unhandled = super().keypress(self, (maxcol, ), key)
        return unhandled


@click.group()
def cli() -> None:
    """Cli for SBK."""


@cli.command()
def urwidtest() -> None:

    def make_attr_wrapper(*attrs):
        def attr_wrapper(elem):
            return urwid.AttrWrap(elem, *attrs)
        return attr_wrapper

    def pad(elem, w):
        return urwid.Padding(elem, width=w)

    edit_boxes = []

    def editbx(elem):
        edit_boxes.append(elem)
        return urwid.AttrWrap(elem, 'editbx')

    def phrase_boxes(constructor, n):
        return urwid.Pile([constructor(i + 1) for i in range(n)])

    def hex_edit() -> CustomEdit:
        return CustomEdit(max_chars=2, valid_chars="0123456789ABCDEFabcdef")

    def word_edit() -> CustomEdit:
        return CustomEdit(max_chars=6, valid_chars=string.ascii_letters)

    phrases = urwid.Columns(
        [
            phrase_boxes((lambda i: urwid.Text(f"{i:>2}: ")), 6),
            phrase_boxes((lambda i: pad(editbx(hex_edit()), w=2)), 6),
            phrase_boxes((lambda i: pad(editbx(hex_edit()), w=2)), 6),
            phrase_boxes(
                (lambda i: pad(editbx(urwid.Edit("", "", align="left")), w=6)), 6
            ),
            phrase_boxes(
                (lambda i: pad(editbx(urwid.Edit("", "", align="left")), w=6)), 6
            ),
            phrase_boxes((lambda i: urwid.Text(" at the ")), 6),
            phrase_boxes(
                (lambda i: pad(editbx(urwid.Edit("", "", align="left")), w=6)), 6
            ),
            phrase_boxes(
                (lambda i: pad(editbx(urwid.Edit("", "", align="left")), w=6)), 6
            ),
            phrase_boxes((lambda i: urwid.Text(".")), 6),
        ],
        dividechars=1,
    )

    header = urwid.Text("Hello World Urwid!")

    body = [header, phrases, urwid.Divider()]

    frame = urwid.ListBox(body)

    def unhandled(key) -> None:
        if key == 'f8':
            raise urwid.ExitMainLoop()

        out("??", key)

    palette = [
        ('body'  , "light gray", 'black', 'standout'),
        ('editbx', "white"     , "dark gray"),
    ]

    state = {'focus': 0}

    def input_filter(keys, raw):
        if 'q' in keys or 'Q' in keys:
            raise urwid.ExitMainLoop()

        if keys == ['shift tab']:
            # focus prev
            state['focus'] -= 1

        if keys == ['tab']:
            # focus next
            state['focus'] += 1

        focus_col = state['focus'] % 6
        focus_row = state['focus'] // 6

        out("---", frame.get_focus_widgets())
        out("!!!", frame.get_focus_path())

        out("<<<", keys, raw)
        frame.set_focus(state['focus'])
        return keys

    out("---", frame.get_focus_widgets())
    out("000", frame.get_focus_path())

    loop = urwid.MainLoop(
        frame,
        palette,
        unhandled_input=unhandled,
        input_filter=input_filter,
    )
    loop.run()
