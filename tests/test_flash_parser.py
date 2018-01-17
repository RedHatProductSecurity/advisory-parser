import pytest
import datetime
from os import path
from io import open
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.parsers.flash import parse_flash_advisory

apsb17_21 = [
    {
        'advisory_id': 'APSB17-21',
        'cves': ['CVE-2017-3080'],
        'cvss2': None,
        'cvss3': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'description': 'Adobe Security Bulletin APSB17-21 for Adobe Flash Player describes a flaw that can possibly lead to information disclosure when Flash Player is used to play a specially crafted SWF file:\n\nSecurity Bypass -- CVE-2017-3080',
        'fixed_in': {'flash-plugin': ['26.0.0.137']},
        'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-21.html',
        'impact': 'important',
        'public_date': datetime.datetime(2017, 7, 11, 0, 0),
        'summary': 'flash-plugin: Information Disclosure vulnerability (APSB17-21)'
    }, {
        'advisory_id': 'APSB17-21',
        'cves': ['CVE-2017-3100'],
        'cvss2': None,
        'cvss3': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'description': 'Adobe Security Bulletin APSB17-21 for Adobe Flash Player describes a flaw that can possibly lead to memory address disclosure when Flash Player is used to play a specially crafted SWF file:\n\nMemory Corruption -- CVE-2017-3100',
        'fixed_in': {'flash-plugin': ['26.0.0.137']},
        'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-21.html',
        'impact': 'important',
        'public_date': datetime.datetime(2017, 7, 11, 0, 0),
        'summary': 'flash-plugin: Memory address disclosure vulnerability (APSB17-21)'
    }, {
        'advisory_id': 'APSB17-21',
        'cves': ['CVE-2017-3099'],
        'cvss2': None,
        'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        'description': 'Adobe Security Bulletin APSB17-21 for Adobe Flash Player describes a flaw that can possibly lead to remote code execution when Flash Player is used to play a specially crafted SWF file:\n\nMemory Corruption -- CVE-2017-3099',
        'fixed_in': {'flash-plugin': ['26.0.0.137']},
        'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-21.html',
        'impact': 'critical',
        'public_date': datetime.datetime(2017, 7, 11, 0, 0),
        'summary': 'flash-plugin: Remote Code Execution vulnerability (APSB17-21)'
    }
]

apsb17_23 = [
    {
        'advisory_id': 'APSB17-23',
        'cves': ['CVE-2017-3085'],
        'cvss2': None,
        'cvss3': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'description': 'Adobe Security Bulletin APSB17-23 for Adobe Flash Player describes a flaw that can possibly lead to information disclosure when Flash Player is used to play a specially crafted SWF file:\n\nSecurity Bypass -- CVE-2017-3085',
        'fixed_in': {'flash-plugin': ['26.0.0.151']},
        'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-23.html',
        'impact': 'important',
        'public_date': datetime.datetime(2017, 8, 8, 0, 0),
        'summary': 'flash-plugin: Information Disclosure vulnerability (APSB17-23)'
    }, {
        'advisory_id': 'APSB17-23',
        'cves': ['CVE-2017-3106'],
        'cvss2': None,
        'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        'description': 'Adobe Security Bulletin APSB17-23 for Adobe Flash Player describes a flaw that can possibly lead to remote code execution when Flash Player is used to play a specially crafted SWF file:\n\nType Confusion -- CVE-2017-3106',
        'fixed_in': {'flash-plugin': ['26.0.0.151']},
        'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-23.html',
        'impact': 'critical',
        'public_date': datetime.datetime(2017, 8, 8, 0, 0),
        'summary': 'flash-plugin: Remote Code Execution vulnerability (APSB17-23)'
    }
]

apsb17_33 = [
    {
        'advisory_id': 'APSB17-33',
        'cves': ['CVE-2017-11213', 'CVE-2017-3112', 'CVE-2017-3114', 'CVE-2017-11215', 'CVE-2017-11225'],
        'cvss2': None,
        'cvss3': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        'description': 'Adobe Security Bulletin APSB17-33 for Adobe Flash Player describes multiple flaws that can possibly lead to remote code execution when Flash Player is used to play a specially crafted SWF file:\n\nOut-of-bounds Read -- CVE-2017-11213, CVE-2017-3112, CVE-2017-3114\nUse after free -- CVE-2017-11215, CVE-2017-11225',
        'fixed_in': {'flash-plugin': ['27.0.0.187']},
        'from_url': 'https://helpx.adobe.com/security/products/flash-player/apsb17-33.html',
        'impact': 'critical',
        'public_date': datetime.datetime(2017, 11, 14, 0, 0),
        'summary': 'flash-plugin: Remote Code Execution vulnerabilities (APSB17-33)'
    }
]


@patch('advisory_parser.parsers.flash.get_request')
@pytest.mark.parametrize('input_file, url, expected_data', [
    ('flash_apsb17-21.html', 'https://helpx.adobe.com/security/products/flash-player/apsb17-21.html',
     apsb17_21),
    ('flash_apsb17-23.html', 'https://helpx.adobe.com/security/products/flash-player/apsb17-23.html',
     apsb17_23),
    ('flash_apsb17-33.html', 'https://helpx.adobe.com/security/products/flash-player/apsb17-33.html',
     apsb17_33),
])
def test_parser(get_request, input_file, url, expected_data):

    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, 'test_data', input_file), 'r', encoding='utf-8') as f:
        testing_html = f.read()

    get_request.return_value = testing_html
    flaws, warnings = parse_flash_advisory(url)

    assert not warnings
    assert len(flaws) == len(expected_data)

    for index, flaw in enumerate(flaws):
        assert vars(flaw) == expected_data[index]
