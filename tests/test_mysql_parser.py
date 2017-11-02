import pytest
from datetime import datetime
from os import path
from io import open
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.parsers.mysql import parse_mysql_advisory, _nearest_tuesday


@pytest.mark.parametrize('year, month, day, expected_date', [
    (2017, 'jul', 3, datetime(2017, 7, 4)),
    (2017, 'jul', 4, datetime(2017, 7, 4)),  # Tuesday
    (2017, 'jul', 5, datetime(2017, 7, 4)),
    (2017, 'jul', 6, datetime(2017, 7, 4)),
    (2017, 'jul', 7, datetime(2017, 7, 4)),
    (2017, 'jul', 8, datetime(2017, 7, 11)),
    (2017, 'jul', 9, datetime(2017, 7, 11)),
    (2017, 'jul', 10, datetime(2017, 7, 11)),
    (2017, 'jul', 11, datetime(2017, 7, 11)),  # Tuesday
    (2017, 'jul', 12, datetime(2017, 7, 11)),
])
def test_nearest_tuesday(year, month, day, expected_date):
    assert expected_date == _nearest_tuesday(year, month, day)


@patch('advisory_parser.parsers.mysql.get_request')
@pytest.mark.parametrize('input_file, url', [
    ('mysql_cpu-jul-2017.html', 'http://www.oracle.com/technetwork/security-advisory/cpujul2017verbose-3236625.html')
])
def test_parser(get_request, input_file, url):

    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, 'test_data', input_file), 'r', encoding='utf-8') as f:
        testing_html = f.read()

    get_request.return_value = testing_html
    flaws, warnings = parse_mysql_advisory(url)

    assert len(warnings) == 6
    assert 'Skipping CVE-2014-1912' in warnings[0]
    assert 'Skipping CVE-2016-4436' in warnings[1]
    assert 'Skipping CVE-2017-3635' in warnings[2]
    assert 'Skipping CVE-2017-3732' in warnings[3]
    assert 'Skipping CVE-2017-5647' in warnings[4]
    assert 'Skipping CVE-2017-5651' in warnings[5]

    assert vars(flaws[0]) == {'cves': ['CVE-2017-3529'],
                              'cvss2': None, 'cvss3': '5.3/CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H',
                              'description': 'Vulnerability in the MySQL Server component of Oracle MySQL '
                                             '(subcomponent: Server: UDF). Supported versions that are '
                                             'affected are 5.7.18 and earlier. Difficult to exploit '
                                             'vulnerability allows low privileged attacker with network '
                                             'access via multiple protocols to compromise MySQL Server. '
                                             'Successful attacks of this vulnerability can result in '
                                             'unauthorized ability to cause a hang or frequently '
                                             'repeatable crash (complete DOS) of MySQL Server.',
                              'fixed_in': {'mysql': ['5.7.19']},
                              'from_url': 'http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html',
                              'impact': 'moderate', 'public_date': datetime(2017, 7, 18),
                              'summary': 'mysql: Server: UDF unspecified vulnerability (CPU Jul 2017)',
                              'advisory_id': 'CPU Jul 2017'}
