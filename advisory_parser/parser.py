# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

from .parsers import *
from .exceptions import AdvisoryParserUrlException


class Parser:
    """Parser for various project-specific advisory pages"""

    @classmethod
    def parse_from_url(cls, url):
        """
        Parses content from provided URL and returns a list of flaws containing all parsed data.

        :param url: URL to parse
        :return: List of Flaw objects
        """
        if not url:
            raise AdvisoryParserUrlException('No URL specified')

        if 'chromereleases' in url:
            return parse_chrome_advisory(url)

        elif 'wireshark.org' in url:
            pass

        elif 'flash-player' in url:
            return parse_flash_advisory(url)

        elif 'oracle.com' in url:
            return parse_mysql_advisory(url)

        elif 'jenkins-ci' in url:
            pass

        elif 'phpmyadmin' in url:
            pass

        else:
            raise AdvisoryParserUrlException('Could not find parser for: {}'.format(url))
