import io
import qrcode


qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data('Hello World!')

bw_buf = io.StringIO()
wb_buf = io.StringIO()

qr.print_ascii(out=bw_buf, invert=False)
qr.print_ascii(out=wb_buf, invert=True)

bw_lines = bw_buf.getvalue().splitlines()
wb_lines = wb_buf.getvalue().splitlines()

for bw_line, wb_line in zip(bw_lines, wb_lines):
    print(bw_line, wb_line)
