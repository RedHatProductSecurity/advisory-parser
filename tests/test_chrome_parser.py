import pytest
import datetime
from os import path
from io import open
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.parsers.chrome import parse_chrome_advisory


@patch('advisory_parser.parsers.chrome.get_text_from_url')
@pytest.mark.parametrize('input_file, url', [
    ('chrome_2017-06-15.txt', 'https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html')
])
def test_parser(get_text_from_url, input_file, url):

    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, 'test_data', input_file), 'r', encoding='utf-8') as f:
        testing_text = f.read()

    get_text_from_url.return_value = testing_text
    flaws, warnings = parse_chrome_advisory(url)

    assert not warnings
    assert len(flaws) == 3
    assert vars(flaws[0]) == {'summary': 'chromium-browser: Sandbox Escape in IndexedDB',
                              'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                              'description': 'A sandbox escape flaw was found in the IndexedDB component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=725032', 'from_url': 'https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html',
                              'fixed_in': {'chromium-browser': ['59.0.3071.104']}, 'cvss2': None, 'advisory_id': None,
                              'impact': 'important', 'cves': ['CVE-2017-5087'], 'public_date': datetime.datetime(2017, 6, 15, 0, 0)}
    assert vars(flaws[1]) == {'summary': 'chromium-browser: Out of bounds read in V8',
                              'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                              'description': 'An out of bounds read flaw was found in the V8 component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=729991', 'from_url': 'https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html',
                              'fixed_in': {'chromium-browser': ['59.0.3071.104']}, 'cvss2': None, 'advisory_id': None,
                              'impact': 'important', 'cves': ['CVE-2017-5088'], 'public_date': datetime.datetime(2017, 6, 15, 0, 0)}
    assert vars(flaws[2]) == {'summary': 'chromium-browser: Domain spoofing in Omnibox',
                              'cvss3': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
                              'description': 'A domain spoofing flaw was found in the Omnibox component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=714196', 'from_url': 'https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html',
                              'fixed_in': {'chromium-browser': ['59.0.3071.104']}, 'cvss2': None, 'advisory_id': None,
                              'impact': 'moderate', 'cves': ['CVE-2017-5089'], 'public_date': datetime.datetime(2017, 6, 15, 0, 0)}
