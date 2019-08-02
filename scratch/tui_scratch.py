#!/usr/bin/python
# -*- coding: utf-8 -*-

import typing as typ

import curses
import curses.textpad


def out(*msg: typ.Any) -> None:
    with open("/tmp/out", mode="a") as fobj:
        print(*msg, file=fobj)


out()


def main(stdscr):
    # stdscr.nodelay(True)
    stdscr.clear()
    curses.use_default_colors()
    out(curses.COLORS)

    # if len(curses.COLORS) == 16:
    for i in range(0, curses.COLORS):
        curses.init_pair(i, i, -1)

    try:
        for i in range(0, 255):
            stdscr.addstr(str(i), curses.color_pair(i))
    except curses.ERR:
        # End of screen reached
        pass
    stdscr.getch()

    return
    # index, foreground, background
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLUE)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    stdscr.bkgd(curses.color_pair(1))
    stdscr.refresh()

    # Edit-Fenster
    win1 = curses.newwin(20, 40, 10, 5)
    win1.bkgd(curses.color_pair(2))

    # Darstellungsfenster
    win2 = curses.newwin(20, 40, 10, 50)
    win2.bkgd(curses.color_pair(2))
    win2.refresh()

    # Textbox
    textbox = curses.textpad.Textbox(win1)
    text = textbox.edit()

    # Text übernehmen
    win2.addstr(0, 0, text)
    win2.refresh()

    # Ende
    c = stdscr.getch()
    print(c)


if __name__ == '__main__':
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
