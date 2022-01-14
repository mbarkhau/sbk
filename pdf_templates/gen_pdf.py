import io
import sys
import base64
import pathlib as pl

import jinja2
import qrcode
import weasyprint
import qrcode.image.svg


TEMPLATES_DIR = pl.Path(__file__).parent.absolute()


def qr_img_b64(text: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=8, border=0)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    data = buf.getvalue()
    return base64.b64encode(data).decode("ascii")


def read_html(tmpl, **kwargs) -> str:
    fpath = TEMPLATES_DIR / f"{tmpl}_template.html"
    with fpath.open(mode="r", encoding="utf-8") as fobj:
        html_tmpl = fobj.read()

    tmpl_obj = jinja2.Template(html_tmpl)
    return tmpl_obj.render(**kwargs)


SHARE_QR_SRC = "data:image/svg+xml;base64," + qr_img_b64("https://sbk.dev/share")
AUTH_QR_SRC  = "data:image/svg+xml;base64," + qr_img_b64("https://sbk.dev/auth")
# SHARE_QR_SRC = "data:image/svg+xml;base64," + qr_img_b64("SBK: Split Bitcoin Keys")
# AUTH_QR_SRC  = "data:image/svg+xml;base64," + qr_img_b64("SBK: Split Bitcoin Keys")

CONTEXTS = [
    {'tmpl': "share", 'w': 210, 'h': 297, 'wc': 24, 'fmt': "a4", 'qr_src': SHARE_QR_SRC},
    {'tmpl': "share", 'w': 8.5, 'h': 11 , 'wc': 24, 'fmt': "letter", 'qr_src': SHARE_QR_SRC},
    {'tmpl': "auth", 'w': 210, 'h': 297, 'fmt': "a4", 'qr_src': AUTH_QR_SRC},
    {'tmpl': "auth", 'w': 8.5, 'h': 11, 'fmt': "letter", 'qr_src': AUTH_QR_SRC},
    {'tmpl': "grid", 'w': 210, 'h': 297, 'fmt': "a4"},
    {'tmpl': "grid", 'w': 8.5, 'h': 11, 'fmt': "letter"},
]


def main() -> int:
    out_paths = {pl.Path(path).absolute() for path in sys.argv[1:]}
    for ctx in CONTEXTS:
        if ctx['fmt'] == 'letter':
            ctx['w'] *= 25.4
            ctx['h'] *= 25.4

        out_path_html = TEMPLATES_DIR / "{tmpl}_{fmt}.html".format(**ctx)
        out_path_pdf = TEMPLATES_DIR / "{tmpl}_{fmt}.pdf".format(**ctx)

        if out_paths and out_path_pdf not in out_paths:
            continue

        html_text = read_html(**ctx)
        wp_ctx    = weasyprint.HTML(string=html_text, base_url=str(TEMPLATES_DIR))

        with out_path_html.open(mode="w", encoding="utf-8") as fobj:
            fobj.write(html_text)
        print("wrote", str(out_path_html.absolute()))

        with out_path_pdf.open(mode="wb") as fobj:
            wp_ctx.write_pdf(fobj)
        print("wrote", str(out_path_pdf.absolute()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
