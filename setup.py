# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

import os
import sys
import setuptools


def project_path(*sub_paths):
    project_dirpath = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(project_dirpath, *sub_paths)


def read(*sub_paths):
    with open(project_path(*sub_paths), mode="rb") as fobj:
        return fobj.read().decode("utf-8")

install_requires = [
    line.strip()
    for line in read("requirements", "pypi.txt").splitlines()
    if line.strip() and not line.startswith("#")
]


long_description = "\n\n".join((read("README.md"), read("CHANGELOG.md")))

# try:
#     import lib3to6
#     distclass = lib3to6.Distribution
# except ImportError:
#     distclass = setuptools.dist.Distribution


setuptools.setup(
    name="sbk",
    license="MIT",
    author="Manuel Barkhau",
    author_email="mbarkhau@gmail.com",
    url="https://github.com/mbarkhau/sbk",
    version="2022.1009b0",
    keywords="ssss shamir split share secret bitcoin electrum seed brainkey crypto",
    description="Wallet seed generation from a brainkey with Shamir Secret Shares as Backup.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["sbk", "sbk.assets", "sbk.wordlist"],
    package_dir={"": "src"},
    zip_safe=False,
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=install_requires,
    # setup_requires=['lib3to6>=202110.1050b0'],
    # distclass=distclass,
    entry_points="""
        [console_scripts]
        sbk=sbk.cli:cli
        sbk-gui=sbk.gui:main
    """,

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        # "Operating System :: MacOS :: MacOS X",
        # "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
