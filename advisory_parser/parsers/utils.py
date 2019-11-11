# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+

import re
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from bs4 import BeautifulSoup

from advisory_parser.exceptions import AdvisoryParserGetContentException

CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,}')


def get_request(url):
    try:
        res = urlopen(url)
    except HTTPError as e:
        error_msg = 'Failed to GET with status code: {}'.format(e.code)
        raise AdvisoryParserGetContentException(error_msg)
    except URLError as e:
        error_msg = 'Failed to establish connection: {}'.format(e.reason)
        raise AdvisoryParserGetContentException(error_msg)
    except ValueError:
        raise AdvisoryParserGetContentException('Invalid URL specified.')
    else:
        return res.read()


def get_text_from_url(url):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")

    # Remove script and style tags and their contents
    for script in soup(['script', 'style']):
        script.decompose()

    text = soup.get_text()

    # Filter out blank lines and leading/trailing spaces
    text = '\n'.join(line.strip() for line in text.splitlines() if line)

    return text
