import io
import sys
import base64
import random
import pathlib as pl

import qrcode
import qrcode.image.svg
import jinja2
import weasyprint


STATIC_DIR = pl.Path(__file__).parent

QR_TEXT = "http://youtu.be/aaaaaaaaa"


def qr_img_b64() -> str:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=0,
    )
    qr.add_data(QR_TEXT)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    data = buf.getvalue()
    return base64.b64encode(data).decode("ascii")


def read_html(**kwargs) -> str:
    fpath = STATIC_DIR / "template.html"
    with fpath.open(mode="r", encoding="utf-8") as fobj:
        html_tmpl = fobj.read()

    tmpl_obj = jinja2.Template(html_tmpl)
    return tmpl_obj.render(**kwargs)


def main() -> int:
    qr_src    = "data:image/svg+xml;base64," + qr_img_b64()
    wordcount = random.randint(4, 8) * 4
    wordcount = 24
    print("...", wordcount)
    contexts = [
        {'wordcount': wordcount, 'qr_src': qr_src, 'w': 210, 'h': 297, 'fmt': "a4"},
        {
            'wordcount': wordcount,
            'qr_src'   : qr_src,
            'w'        : 8.5 * 25.4,
            'h'        : 11  * 25.4,
            'fmt'      : "usletter",
        },
    ]
    for ctx in contexts:
        html_text = read_html(**ctx)
        wp_ctx    = weasyprint.HTML(string=html_text, base_url=str(STATIC_DIR))

        out_path_html = STATIC_DIR / "{fmt}_{wordcount}.html".format(**ctx)
        out_path_pdf  = STATIC_DIR / "{fmt}_{wordcount}.pdf".format(**ctx)

        with out_path_html.open(mode="w", encoding="utf-8") as fobj:
            fobj.write(html_text)
        print("wrote", str(out_path_html.absolute()))

        with out_path_pdf.open(mode="wb") as fobj:
            wp_ctx.write_pdf(fobj)
        print("wrote", str(out_path_pdf.absolute()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
