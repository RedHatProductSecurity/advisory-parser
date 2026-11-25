import pytest
import time
from datetime import datetime
from os import path
from io import open

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.exceptions import AdvisoryParserTextException
from advisory_parser.parsers.mysql import (
    CVSS_SCORE_REGEX,
    CVSS_SPLIT_REGEX,
    MAX_PAGE_TEXT_CHARS,
    _nearest_tuesday,
    _third_tuesday,
    create_mariadb_cve_map,
    parse_mysql_advisory,
)


@pytest.mark.parametrize(
    "year, month, day, expected_date",
    [
        (2017, 7, 3, datetime(2017, 7, 4)),
        (2017, 7, 4, datetime(2017, 7, 4)),  # Tuesday
        (2017, 7, 5, datetime(2017, 7, 4)),
        (2017, 7, 6, datetime(2017, 7, 4)),
        (2017, 7, 7, datetime(2017, 7, 4)),
        (2017, 7, 8, datetime(2017, 7, 11)),
        (2017, 7, 9, datetime(2017, 7, 11)),
        (2017, 7, 10, datetime(2017, 7, 11)),
        (2017, 7, 11, datetime(2017, 7, 11)),  # Tuesday
        (2017, 7, 12, datetime(2017, 7, 11)),
    ],
)
def test_nearest_tuesday(year, month, day, expected_date):
    assert expected_date == _nearest_tuesday(year, month, day)


@pytest.mark.parametrize(
    "year, month, expected_date",
    [
        (2017, 7, datetime(2017, 7, 18).date()),
        (2024, 7, datetime(2024, 7, 16).date()),
        (2024, 10, datetime(2024, 10, 15).date()),
        (2025, 1, datetime(2025, 1, 21).date()),
        (2025, 4, datetime(2025, 4, 15).date()),
    ],
)
def test_third_tuesday(year, month, expected_date):
    assert expected_date == _third_tuesday(year, month)


@patch("advisory_parser.parsers.mysql.get_request")
@patch("advisory_parser.parsers.mysql.create_mariadb_cve_map")
@pytest.mark.parametrize(
    "input_file, url",
    [("mysql_cpu-apr-2019.html", "https://www.oracle.com/security-alerts/cpuapr2019.html")],
)
def test_parser(create_mariadb_cve_map, get_request, input_file, url):
    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, "test_data", input_file), "r", encoding="utf-8") as f:
        testing_html = f.read()

    get_request.return_value = testing_html
    create_mariadb_cve_map.return_value = {}
    flaws, warnings = parse_mysql_advisory(url)

    assert len(warnings) == 4
    assert "Skipping CVE-2018-0734" in warnings[0]
    assert "Skipping CVE-2019-1559" in warnings[1]
    assert "Skipping CVE-2019-1559" in warnings[2]
    assert "Skipping CVE-2019-2692" in warnings[3]

    assert vars(flaws[0]) == {
        "cves": ["CVE-2018-3123"],
        "summary": "mysql: Server: libmysqld unspecified vulnerability (CPU Apr 2019)",
        "public_date": datetime(2019, 4, 16),
        "cvss3": "5.9/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss2": None,
        "impact": "moderate",
        "description": "Vulnerability in the MySQL Server component of "
        "Oracle MySQL (subcomponent: Server: libmysqld). "
        "Supported versions that are affected are 5.6.42 and prior, "
        "5.7.24 and prior and 8.0.13 and prior. Difficult to exploit "
        "vulnerability allows unauthenticated attacker with network "
        "access via multiple protocols to compromise MySQL Server. "
        "Successful attacks of this vulnerability can result in "
        "unauthorized access to critical data or complete access to "
        "all MySQL Server accessible data.",
        "fixed_in": {"mysql": ["5.6.43", "5.7.25", "8.0.14"]},
        "from_url": "https://www.oracle.com/security-alerts/cpuapr2019.html#AppendixMSQL",
        "advisory_id": "CPU Apr 2019",
    }


MARIADB_PAGE = (
    "Security Vulnerabilities Fixed in MariaDB\n"
    "Contents\n"
    "About CVEs\n"
    "Full List of CVEs fixed in MariaDB\n"
    "CVEs without specific version numbers:\n"
    "About CVEs\n"
    "Full List of CVEs fixed in MariaDB\n"
    "CVE-2022-32091: MariaDB 10.9.2, MariaDB 10.8.4\n"
    "CVE-2022-32089: MariaDB 10.9.2, MariaDB 10.4.26\n"
    "CVE-2005-0004: MariaDB 5.5.66\n"
    "CVEs without specific version numbers:\n"
    "CVE-2012-0113: MariaDB 5.1, MariaDB 5.5\n"
    "CVE-1999-1234: MariaDB 5.5.10\n"
    "Footer\n"
)


@patch("advisory_parser.parsers.mysql.get_text_from_url")
def test_create_mariadb_cve_map(get_text_from_url):
    get_text_from_url.return_value = MARIADB_PAGE

    # Only CVEs between the last "Full List of CVEs fixed in MariaDB" header
    # and the last "CVEs without specific version numbers" header count; both
    # markers also appear in the table of contents at the top of the page.
    assert create_mariadb_cve_map() == {
        "CVE-2022-32091": ["10.9.2", "10.8.4"],
        "CVE-2022-32089": ["10.9.2", "10.4.26"],
        "CVE-2005-0004": ["5.5.66"],
    }


@patch("advisory_parser.parsers.mysql.get_text_from_url")
def test_create_mariadb_cve_map_hostile_page(get_text_from_url):
    # A page with the start marker but no end marker must fail fast instead
    # of scanning quadratically like the old greedy re.DOTALL match.
    get_text_from_url.return_value = (
        "Security Vulnerabilities Fixed in MariaDB\n"
        "Full List of CVEs fixed in MariaDB\n" + "\n" * 200000
    )

    start = time.perf_counter()
    with pytest.raises(AdvisoryParserTextException):
        create_mariadb_cve_map()

    assert time.perf_counter() - start < 2.0


@patch("advisory_parser.parsers.mysql.get_text_from_url")
def test_create_mariadb_cve_map_caps_page(get_text_from_url):
    # The page is capped before it is scanned, so markers beyond the cap
    # are not seen and parsing fails rather than scanning unbounded text.
    get_text_from_url.return_value = "x" * MAX_PAGE_TEXT_CHARS + MARIADB_PAGE

    with pytest.raises(AdvisoryParserTextException):
        create_mariadb_cve_map()


def test_cvss_split_regex():
    description = (
        "Vulnerability in the MySQL Server component of Oracle MySQL "
        "(subcomponent: Server: libmysqld). Supported versions that are "
        "affected are 5.6.42 and prior.\n \n"
        "CVSS v3.0 Base Score 5.9 (Confidentiality impacts). CVSS Vector: "
        "(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). (legend)"
    )

    parts = CVSS_SPLIT_REGEX.split(description)

    assert len(parts) == 2
    assert parts[0].strip().endswith("affected are 5.6.42 and prior.")
    # The split consumes the "\nCVSS v3.0 " prefix, so the CVSS text starts
    # at "Base Score"; "Base Score" itself is only a lookahead.
    assert parts[1].startswith("Base Score 5.9 (Confidentiality impacts)")


def test_cvss_split_regex_hostile_input():
    # A cell with newlines but no CVSS text must not split and must be
    # scanned linearly; the old "\n\s*CVSS" pattern was quadratic here.
    description = "A description without a CVSS score.\n" + "\n" * 400000

    start = time.perf_counter()
    parts = CVSS_SPLIT_REGEX.split(description)

    assert parts == [description]
    assert time.perf_counter() - start < 2.0


def test_cvss_score_regex():
    # CVSS text as it comes out of CVSS_SPLIT_REGEX (see above).
    cvss_text = (
        "Base Score 5.9 (Confidentiality impacts). CVSS Vector: "
        "(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). (legend) [Advisory]"
    )

    match = CVSS_SCORE_REGEX.search(cvss_text)

    assert match.group(1) == "5.9"
    assert match.group(2) == "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_cvss_score_regex_hostile_input():
    # Repeated scores without a vector must be scanned linearly; the old
    # unbounded ".*Vector:" pattern was quadratic here.
    cvss_text = "CVSS 3.1 Base Score 5.9 (A) " * 40000

    start = time.perf_counter()
    match = CVSS_SCORE_REGEX.search(cvss_text)

    assert match is None
    assert time.perf_counter() - start < 2.0
