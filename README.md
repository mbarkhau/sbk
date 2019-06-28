# [Split Bitcoin Keys][repo_ref]

With SBK you can split a determanistically generated key into multiple pieces. You can later join these pieces back together again to recover the original secret key. This protects your keys from:

 1. Loss: Any individual piece can be lost as more pieces are generated than are required to recover the original secret. Individual pieces can be lost or destroyed and you can still recover your secret as long as you can still access enough other pieces to recover your original secret keys.
 2. Theft: Any individual piece can be stolen as it is useless by itself. Your secret is secure even if individual pieces fall into the wrong hands, be it through theft, hacking, extortion or bad security practices.

If a piece is either lost or stolen, you should create a new key as soon as possible (and move your coins to a new wallet).


Project/Repo:

[![MIT License][license_img]][license_ref]
[![Supported Python Versions][pyversions_img]][pyversions_ref]
[![PyCalVer v201906.0001-alpha][version_img]][version_ref]
[![PyPI Version][pypi_img]][pypi_ref]
[![PyPI Downloads][downloads_img]][downloads_ref]

Code Quality/CI:

[![Build Status][build_img]][build_ref]
[![Type Checked with mypy][mypy_img]][mypy_ref]
[![Code Coverage][codecov_img]][codecov_ref]
[![Code Style: sjfmt][style_img]][style_ref]


|                 Name                |        role       |  since  | until |
|-------------------------------------|-------------------|---------|-------|
| Manuel Barkhau (mbarkhau@gmail.com) | author/maintainer | 2019-06 | -     |


<!--
  To update the TOC:
  $ pip install md-toc
  $ md_toc -i gitlab README.md
-->


[](TOC)

[](TOC)


## Error Correction

Errors are corrected through redundancy, which is done at multiple
levels.

 1. Overall Redundancy: The choice of the minimum number of
    shares in relation to the total number of shares, gives a
    configurable level of redundancy to the owner. The number of shares
    that can be lost, while still being able to recover the original
    secret is up to them.

 2. Single Share Redundancy: At the level of the share, there are
    4 bytes dedicated to a checksum. This checksum is however not used
    simply to validate the input, but rather it is used to determine
    which guesses at the full share are valid. If the individual share
    is partially corrupted, the share decode step will go through
    quite a few possible combinations of words, in order to recover
    the full share. The lost words can be marked, so that the recovery
    of these will be attempted first. The recovery of up to three
    missing or incorrect words is possible, given enough time.

 3. Codeword Redundancy: At the level of each byte of data,
    the list words is chosen so that each word distinctive,
    from others in the wordlist. This allows typos or spelling
    errors can be caught and corrected.

Quite frankly, I'm not smart enough to implement error correction
using Reed Solomon or LDPC. Fortunately there is a computationally
expensive brute force method to correct errors: Use a large
cryptographic checksum and simply guess at the answer. Incidentally
this may actually be optimal as far as the shannon limit is
concerned.




[href_pai_ssss]: http://point-at-infinity.org/ssss/)
[href_ssss_js]: https://github.com/gburca/ssss-js

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

[version_img]: https://img.shields.io/static/v1.svg?label=PyCalVer&message=v201906.0001-alpha&color=blue
[version_ref]: https://pypi.org/project/pycalver/

[pyversions_img]: https://img.shields.io/pypi/pyversions/sbk.svg
[pyversions_ref]: https://pypi.python.org/pypi/sbk

