"""Context manager for coarse grained performance measurement.

Usage:
    with trace("section title"):
        your_code_here()

Output:
    ts:    0.104 ┌ section title
    ts:  123.410 └ d:  123.000 ms

ts: time since start of the process (actually import time).
d : execution duration for the code wrapped by the context manager
"""
import time
import contextlib
import typing as typ

proc_ts_start = time.time() * 1000

context: typ.List[str] = []


@contextlib.contextmanager
def trace(name: typ.Optional[str] = None) -> typ.Iterator:
    ts_start     = time.time() * 1000
    rel_ts_start = ts_start - proc_ts_start
    if name is None:
        name = f"<unnamed {len(context)}>"

    indent = "│ " * len(context) + "┌"

    context.append(name)
    print(f"ts:{rel_ts_start:9.3f} {indent} {name} ")
    yield
    ts_end     = time.time() * 1000
    rel_ts_end = ts_end - proc_ts_start
    duration   = round(ts_end - ts_start)
    context.pop()

    if duration > 0.001:
        indent = "│ " * len(context) + "└"
        print(f"ts:{rel_ts_end:9.3f} {indent} d: {duration:9.3f} ms ")


def main() -> None:
    with trace("section title"):
        time.sleep(0.5)


if __name__ == '__main__':
    main()
