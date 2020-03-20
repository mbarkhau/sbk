import io
import sys
import base64
import pathlib as pl

import jinja2
import qrcode
import weasyprint
import qrcode.image.svg

STATIC_DIR = pl.Path(__file__).parent


def qr_img_b64(url) -> str:
    qr = qrcode.QRCode(
        version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=8, border=0,
    )
    qr.add_data(url)
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


SHARE_QR_SRC = "data:image/svg+xml;base64," + qr_img_b64("http://youtu.be/aaaaaaaaa")
AUTH_QR_SRC  = "data:image/svg+xml;base64," + qr_img_b64("http://youtu.be/bbbbbbbbb")
SHARE_QR_SRC = "data:image/svg+xml;base64," + qr_img_b64("SBK: Split Bitcoin Keys")
AUTH_QR_SRC  = "data:image/svg+xml;base64," + qr_img_b64("SBK: Split Bitcoin Keys")


CONTEXTS = [
    # {'tmpl': "share", 'fmt': "a4", 'qr_src': SHARE_QR_SRC, 'w': 210, 'h': 297, 'wc': 24},
    # {
    #     'tmpl'  : "share",
    #     'fmt'   : "usletter",
    #     'qr_src': SHARE_QR_SRC,
    #     'w'     : 8.5 * 25.4,
    #     'h'     : 11  * 25.4,
    #     'wc'    : 24,
    # },
    # {'tmpl': "auth", 'qr_src': AUTH_QR_SRC, 'w': 210, 'h': 297, 'fmt': "a4"},
    # {'tmpl': "auth", 'qr_src': AUTH_QR_SRC, 'w': 8.5 * 25.4, 'h': 11 * 25.4, 'fmt': "usletter"},
    {'tmpl': "grid", 'w': 210, 'h': 297, 'fmt': "a4"},
    {'tmpl': "grid", 'w': 8.5 * 25.4, 'h': 11 * 25.4, 'fmt': "usletter"},
]


def main() -> int:
    for ctx in CONTEXTS:
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
