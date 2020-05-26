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
@patch('advisory_parser.parsers.mysql.create_mariadb_cve_map')
@pytest.mark.parametrize('input_file, url', [
    ('mysql_cpu-apr-2019.html', 'https://www.oracle.com/security-alerts/cpuapr2019.html')
])
def test_parser(create_mariadb_cve_map, get_request, input_file, url):

    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, 'test_data', input_file), 'r', encoding='utf-8') as f:
        testing_html = f.read()

    get_request.return_value = testing_html
    create_mariadb_cve_map.return_value = {}
    flaws, warnings = parse_mysql_advisory(url)

    assert len(warnings) == 4
    assert 'Skipping CVE-2018-0734' in warnings[0]
    assert 'Skipping CVE-2019-1559' in warnings[1]
    assert 'Skipping CVE-2019-1559' in warnings[2]
    assert 'Skipping CVE-2019-2692' in warnings[3]

    assert vars(flaws[0]) == {'cves': ['CVE-2018-3123'],
                              'summary': 'mysql: Server: libmysqld unspecified vulnerability (CPU Apr 2019)',
                              'public_date': datetime(2019, 4, 16),
                              'cvss3': '5.9/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
                              'cvss2': None,
                              'impact': 'moderate',
                              'description': 'Vulnerability in the MySQL Server component of '
                                             'Oracle MySQL (subcomponent: Server: libmysqld). '
                                             'Supported versions that are affected are 5.6.42 and prior, '
                                             '5.7.24 and prior and 8.0.13 and prior. Difficult to exploit '
                                             'vulnerability allows unauthenticated attacker with network '
                                             'access via multiple protocols to compromise MySQL Server. '
                                             'Successful attacks of this vulnerability can result in '
                                             'unauthorized access to critical data or complete access to '
                                             'all MySQL Server accessible data.',
                              'fixed_in': {'mysql': ['5.6.43', '5.7.25', '8.0.14']},
                              'from_url': 'https://www.oracle.com/security-alerts/cpuapr2019.html#AppendixMSQL',
                              'advisory_id': 'CPU Apr 2019'}
