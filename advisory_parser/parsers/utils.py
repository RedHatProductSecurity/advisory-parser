# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+

import re
import gzip
import logging
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request

from bs4 import BeautifulSoup

from advisory_parser.exceptions import AdvisoryParserGetContentException

logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,}")


def get_request(url):
    headers = {
        "User-Agent": "Advisory-Parser/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    }
    request = Request(url, None, headers)
    try:
        res = urlopen(request, timeout=30)
        data = res.read()

        # Handle gzip-compressed responses
        if res.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
    except HTTPError as e:
        error_msg = "Failed to GET {} with status code: {}".format(url, e.code)
        raise AdvisoryParserGetContentException(error_msg)
    except URLError as e:
        error_msg = "Failed to establish connection to {}: {}".format(url, e.reason)
        raise AdvisoryParserGetContentException(error_msg)
    except ValueError:
        raise AdvisoryParserGetContentException("Invalid URL specified: {}".format(url))
    else:
        return data


def get_text_from_url(url):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")

    # Remove script and style tags and their contents
    for script in soup(["script", "style"]):
        script.decompose()

    text = soup.get_text()

    # Filter out blank lines and leading/trailing spaces
    text = "\n".join(line.strip() for line in text.splitlines() if line)

    return text


def find_tag_by_text(url, tag, text):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")
    return soup.find(tag, text=text)


def find_tag_by_id(url, tag, tag_id):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")
    return soup.findAll(tag, id=tag_id)
