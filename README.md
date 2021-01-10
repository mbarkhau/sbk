# [SBK: Split Bitcoin Keys][repo_ref]

<p align="center">
<b>SBK is still ALPHA quality software, please only use if you want to contribute.</b>
</p>

<p align="center">
<img src="https://mbarkhau.keybase.pub/sbk/logo_128.png" height=128 style="background: white;">
</p>

SBK is a program to generate and recover Bitcoin wallets. The goal of SBK is to enable most people to live up to the security mantra of Bitcoin: [Your keys, your coins; not your keys, not your coins][href_yt_aantonop].


Project/Repo:

[![LitProg Documentation][docs_img]][docs_ref]
[![MIT License][license_img]][license_ref]
[![Supported Python Versions][pyversions_img]][pyversions_ref]
[![CalVer 2021.1001-beta][version_img]][version_ref]
[![PyPI Version][pypi_img]][pypi_ref]
[![PyPI Downloads][downloads_img]][downloads_ref]

Code Quality/CI:

[![Build Status][build_img]][build_ref]
[![Type Checked with mypy][mypy_img]][mypy_ref]
[![Code Coverage][codecov_img]][codecov_ref]
[![Code Style: sjfmt][style_img]][style_ref]

| Name                                | role              | since   | until |
| ----------------------------------- | ----------------- | ------- | ----- |
| Manuel Barkhau (mbarkhau@gmail.com) | author/maintainer | 2019-01 | -     |

## Development/Testing

```bash
$ git clone https://gitlab.com/mbarkhau/sbk
$ cd sbk
$ make install
$ make lint mypy test
```

[href_yt_aantonop]: https://www.youtube.com/watch?v=AcrEEnDLm58

[docs_img]: https://mbarkhau.keybase.pub/sbk/litprog_badge.svg
[docs_ref]: https://mbarkhau.gitlab.io/sbk/docs

[repo_ref]: https://gitlab.com/mbarkhau/sbk

[build_img]: https://gitlab.com/mbarkhau/sbk/badges/master/pipeline.svg
[build_ref]: https://gitlab.com/mbarkhau/sbk/pipelines

[codecov_img]: https://gitlab.com/mbarkhau/sbk/badges/master/coverage.svg
[codecov_ref]: https://mbarkhau.gitlab.io/sbk/cov

[license_img]: https://img.shields.io/badge/License-MIT-blue.svg
[license_ref]: https://gitlab.com/mbarkhau/sbk/blob/master/LICENSE

[mypy_img]: https://img.shields.io/badge/mypy-checked-green.svg
[mypy_ref]: https://mbarkhau.gitlab.io/sbk/mypycov

[style_img]: https://img.shields.io/badge/code%20style-%20sjfmt-f71.svg
[style_ref]: https://gitlab.com/mbarkhau/straitjacket/

[pypi_img]: https://img.shields.io/badge/PyPI-wheels-green.svg
[pypi_ref]: https://pypi.org/project/sbk/#files

[downloads_img]: https://pepy.tech/badge/sbk/month
[downloads_ref]: https://pepy.tech/project/sbk

[version_img]: https://img.shields.io/badge/CalVer-2021.1001--beta-blue.svg
[version_ref]: https://pypi.org/project/pycalver/

[pyversions_img]: https://img.shields.io/pypi/pyversions/sbk.svg
[pyversions_ref]: https://pypi.python.org/pypi/sbk
