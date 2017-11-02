import pytest
import datetime
from os import path
from io import open
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.parsers.flash import parse_flash_advisory


@patch('advisory_parser.parsers.flash.get_request')
@pytest.mark.parametrize('input_file, url', [
    ('flash_apsb17-17.html', 'https://helpx.adobe.com/security/products/flash-player/apsb17-17.html')
])
def test_parser(get_request, input_file, url):

    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, 'test_data', input_file), 'r', encoding='utf-8') as f:
        testing_html = f.read()

    get_request.return_value = testing_html
    flaws, warnings = parse_flash_advisory(url)

    assert not warnings
    assert len(flaws) == 2
    assert vars(flaws[0]) == {'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-17.html',
                              'cves': ['CVE-2017-3075,', 'CVE-2017-3081,', 'CVE-2017-3083,', 'CVE-2017-3084'],
                              'impact': 'critical', 'summary': 'flash-plugin: remote code execution vulnerability (APSB17-17)',
                              'public_date': datetime.datetime(2017, 6, 13, 0, 0),
                              'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                              'description': 'Adobe Security Bulletin APSB17-17 for Adobe Flash Player '
                                             'describes multiple use after free\n flaws that can possibly '
                                             'lead to remote code execution when Flash Player is used to '
                                             'play a specially crafted SWF file.',
                              'cvss2': None, 'fixed_in': {'flash-plugin': ['26.0.0.126']}, 'advisory_id': 'APSB17-17'}
    assert vars(flaws[1]) == {'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-17.html',
                              'cves': ['CVE-2017-3076,', 'CVE-2017-3077,', 'CVE-2017-3078,', 'CVE-2017-3079,', 'CVE-2017-3082'],
                              'impact': 'critical', 'summary': 'flash-plugin: remote code execution vulnerability (APSB17-17)',
                              'public_date': datetime.datetime(2017, 6, 13, 0, 0),
                              'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                              'description': 'Adobe Security Bulletin APSB17-17 for Adobe Flash Player '
                                             'describes multiple memory corruption flaws that can possibly '
                                             'lead to remote code execution when Flash Player is used to '
                                             'play a specially crafted SWF file.',
                              'cvss2': None, 'fixed_in': {'flash-plugin': ['26.0.0.126']}, 'advisory_id': 'APSB17-17'}
