Advisory Parser
===============

.. image:: https://img.shields.io/travis/mprpic/advisory-parser/master.svg
   :target: https://travis-ci.org/mprpic/advisory-parser
   :alt: Travis CI test status

This library allows you to parse data from security advisories of certain
projects to extract information about security issues. The parsed
information includes metadata such as impact, CVSS score, summary,
description, and others; for a full list, see the
``advisory_parser/flaw.py`` file.

**DISCLAIMER**: Much of the advisory parsing is fairly fragile. Because web
pages change all the time, it is not uncommon for parsers to break when a
page is changed in some way. Also, the advisory parsers only work with the
latest version of the advisory pages.

The need for parsing raw security advisories in this way could be avoided
if vendors provided their security pages in a machine readable (and
preferably standardized) format. An example of this would be Red Hat's
security advisories that can be pulled in from a separate Security Data API
(`RHSA-2016:1883.json <https://access.redhat.com/labs/securitydataapi/cvrf/RHSA-2016:1883.json>`_)
or downloaded as an XML file
(`cvrf-rhsa-2016-1883.xml <https://www.redhat.com/security/data/cvrf/2016/cvrf-rhsa-2016-1883.xml>`_),
or OpenSSL's list of issues available in XML
(`vulnerabilities.xml <https://www.openssl.org/news/vulnerabilities.xml>`_).

If you are a vendor or an upstream project owner interested in providing
your security advisories in a machine readable format and don't know where
to start, feel free to reach out to mprpic@redhat.com.

Currently available parsers include:

.. csv-table::
    :header: "Project", "Example URL"
    :widths: 20, 80

    "Google Chrome", `<https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html>`_
    "Adobe Flash", `<https://helpx.adobe.com/security/products/flash-player/apsb17-17.html>`_
    "Jenkins", ""
    "MySQL", `<http://www.oracle.com/technetwork/security-advisory/cpujul2017verbose-3236625.html>`_
    "phpMyAdmin", ""
    "Wireshark", ""

Installation
------------

::

    pip install advisory-parser

Usage
-----

.. code-block:: python

    from pprint import pprint
    from advisory_parser import Parser


    url = 'https://helpx.adobe.com/security/products/flash-player/apsb17-17.html'
    flaws, warnings = Parser.parse_from_url(url)

    for flaw in flaws:
        print()
        pprint(vars(flaw))
