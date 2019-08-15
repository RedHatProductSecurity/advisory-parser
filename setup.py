# -*- coding: UTF-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+

from setuptools import setup


with open('README.rst', 'r') as f:
    description = f.read()

requires = ['beautifulsoup4>=4.0.0']

setup(
    name='advisory-parser',
    version='1.8',
    description='Security flaw parser for upstream security advisories',
    long_description=description,
    url='https://github.com/mprpic/advisory-parser',
    author='Martin Prpič, Red Hat Product Security',
    author_email='mprpic@redhat.com',
    license='LGPLv3+',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='security advisory parser scraper',
    packages=['advisory_parser', 'advisory_parser.parsers'],
    install_requires=requires,
)
