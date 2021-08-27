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

package_dir={"": "src"}

if any(arg.startswith("bdist") for arg in sys.argv):
    try:
        import lib3to6
        package_dir = lib3to6.fix(
            package_dir,
            target_version="3.7",
            install_requires=install_requires,
            default_mode='enabled',
        )
    except ImportError:
        if sys.version_info < (3, 9):
            raise
        else:
            sys.stderr.write((
                "WARNING: Creating non-universal bdist, "
                "this should only be used for development.\n"
            ))


setuptools.setup(
    name="sbk",
    license="MIT",
    author="Manuel Barkhau",
    author_email="mbarkhau@gmail.com",
    url="https://github.com/mbarkhau/sbk",
    version="2021.1002b0",
    keywords="ssss shamir split share secret bitcoin electrum seed brainkey crypto",
    description="Wallet seed generation from a brainkey with Shamir Secret Shares as Backup.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["sbk", "sbk.assets", "sbk.wordlist"],
    package_dir={"": "src"},
    zip_safe=False,
    include_package_data=True,
    setup_requires=['lib3to6'],
    install_requires=install_requires,
    entry_points="""
        [console_scripts]
        sbk=sbk.cli:cli
        sbk-gui=sbk.gui:main
    """,
    python_requires=">=3.7",

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
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
