import time
import contextlib

proc_ts_start = time.time() * 1000

context = []


@contextlib.contextmanager
def trace(name=None):
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
        print(f"ts:{rel_ts_end:9.3f} {indent} {duration:9.3f} ms ")


def main():
    with trace():
        time.sleep(0.5)


if __name__ == '__main__':
    main()
