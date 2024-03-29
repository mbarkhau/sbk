import io
import sys

import qrcode


def main(args=sys.argv[1:]):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    if args:
        data = " ".join(args)
    else:
        data = "https://sbk.dev/airgap"

    qr.add_data(data)

    bw_buf = io.StringIO()
    wb_buf = io.StringIO()

    qr.print_ascii(out=bw_buf, invert=False)
    qr.print_ascii(out=wb_buf, invert=True)

    bw_text = bw_buf.getvalue().replace("\x0a", "\n").replace("\xa0", " ")
    wb_text = wb_buf.getvalue().replace("\x0a", "\n").replace("\xa0", " ")

    print(bw_text)

    bw_lines = bw_text.splitlines()
    wb_lines = wb_text.splitlines()

    print()
    for bw_line, wb_line in zip(bw_lines, wb_lines):
        print(bw_line, wb_line)


if __name__ == '__main__':
    main()
