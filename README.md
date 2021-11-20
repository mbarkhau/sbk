<div align="center">
<p align="center">
  <a href="https://github.com/mbarkhau/sbk">
    <img src="https://sbk.dev/logo_1024.png" height=128 style="background: white;">
  </a>
</p>
</div>

# [SBK: Split Bitcoin Keys][repo_ref]

<p align="center">
<b>SBK is ALPHA quality software, please only use if you want to contribute.</b>
</p>

SBK is a program to generate and recover Bitcoin wallets. The goal of SBK is to enable most people to live up to the security mantra of Bitcoin: [Your keys, your coins; not your keys, not your coins][href_yt_held_storing_btc].

[href_yt_held_storing_btc]: https://www.youtube.com/watch?v=5WWfQM0SFXQ

Project/Repo:

[![LitProg Documentation][docs_img]][docs_ref]
[![MIT License][license_img]][license_ref]
[![Libera.Chat][liberachat_img]][liberachat_ref]

[![Supported Python Versions][pyversions_img]][pyversions_ref]
[![CalVer 2021.1004-beta][version_img]][version_ref]

Code Quality/CI:

[![GitHub CI Status][github_build_img]][github_build_ref]
[![GitLab CI Status][gitlab_build_img]][gitlab_build_ref]
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
$ make conda
$ make lint mypy devtest
```


[docs_img]: https://img.shields.io/badge/LitProg-Docs-white
[docs_ref]: https://sbk.dev/docs

[repo_ref]: https://gitlab.com/mbarkhau/sbk

[liberachat_img]: https://img.shields.io/static/v1.svg?label=Libera.Chat&labelColor=55d&message=%23SBK&color=f3b
[liberachat_ref]: https://web.libera.chat/#sbk

[github_build_img]: https://github.com/mbarkhau/sbk/workflows/CI/badge.svg
[github_build_ref]: https://github.com/mbarkhau/sbk/actions?query=workflow%3ACI

[gitlab_build_img]: https://gitlab.com/mbarkhau/sbk/badges/master/pipeline.svg
[gitlab_build_ref]: https://gitlab.com/mbarkhau/sbk/pipelines

[codecov_img]: https://gitlab.com/mbarkhau/sbk/badges/master/coverage.svg
[codecov_ref]: https://mbarkhau.gitlab.io/sbk/cov

[license_img]: https://img.shields.io/badge/License-MIT-blue.svg
[license_ref]: https://gitlab.com/mbarkhau/sbk/blob/master/LICENSE

[mypy_img]: https://img.shields.io/badge/mypy-checked-green.svg
[mypy_ref]: https://mbarkhau.gitlab.io/sbk/mypycov

[style_img]: https://img.shields.io/badge/code%20style-%20sjfmt-f71.svg
[style_ref]: https://gitlab.com/mbarkhau/straitjacket/

[version_img]: https://img.shields.io/badge/CalVer-2021.1004--beta-blue.svg
[version_ref]: https://pypi.org/project/pycalver/

[pyversions_img]: https://img.shields.io/pypi/pyversions/sbk.svg
[pyversions_ref]: https://pypi.python.org/pypi/sbk
