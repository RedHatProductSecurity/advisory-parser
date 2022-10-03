# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

from setuptools import setup


with open("README.rst", "r") as f:
    description = f.read()

requires = ["beautifulsoup4>=4.0.0"]

setup(
    name="advisory-parser",
    version="1.12",
    description="Security flaw parser for upstream security advisories",
    long_description=description,
    url="https://github.com/RedHatProductSecurity/advisory-parser",
    author="Martin Prpič, Red Hat Product Security",
    author_email="secalert@redhat.com",
    license="LGPLv3+",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="security advisory parser scraper",
    packages=["advisory_parser", "advisory_parser.parsers"],
    install_requires=requires,
)
