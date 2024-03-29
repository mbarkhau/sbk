import io
import sys
import base64
import pathlib as pl

import jinja2
import qrcode
import weasyprint
import qrcode.image.svg

STATIC_DIR = pl.Path(__file__).parent


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
    fpath = STATIC_DIR / f"{tmpl}_template.html"
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
    {'tmpl': "share", 'w': 8.5, 'h': 11 , 'wc': 24, 'fmt': "usletter", 'qr_src': SHARE_QR_SRC},
    {'tmpl': "auth", 'w': 210, 'h': 297, 'fmt': "a4", 'qr_src': AUTH_QR_SRC},
    {'tmpl': "auth", 'w': 8.5, 'h': 11, 'fmt': "usletter", 'qr_src': AUTH_QR_SRC},
    {'tmpl': "grid", 'w': 210, 'h': 297, 'fmt': "a4"},
    {'tmpl': "grid", 'w': 8.5, 'h': 11, 'fmt': "usletter"},
]


def main() -> int:
    for ctx in CONTEXTS:
        if ctx['fmt'] == 'usletter':
            ctx['w'] *= 25.4
            ctx['h'] *= 25.4

        html_text = read_html(**ctx)
        wp_ctx    = weasyprint.HTML(string=html_text, base_url=str(STATIC_DIR))

        out_path_html = STATIC_DIR / "{tmpl}_{fmt}.html".format(**ctx)
        with out_path_html.open(mode="w", encoding="utf-8") as fobj:
            fobj.write(html_text)
        print("wrote", str(out_path_html.absolute()))

        out_path_pdf = STATIC_DIR / "{tmpl}_{fmt}.pdf".format(**ctx)
        with out_path_pdf.open(mode="wb") as fobj:
            wp_ctx.write_pdf(fobj)
        print("wrote", str(out_path_pdf.absolute()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
