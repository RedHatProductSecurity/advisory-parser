# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

import calendar
import re
from datetime import datetime, timedelta

import bs4

from advisory_parser.exceptions import AdvisoryParserTextException
from advisory_parser.flaw import Flaw
from .utils import get_request, get_text_from_url, CVE_REGEX

MARIADB_VULN_PAGE = "https://mariadb.com/kb/en/security/"
VERSION_REGEX = re.compile(r"(\d\d?\.\d\.\d\d?)")

month_to_num = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


def _nearest_tuesday(year, month, day=17):
    """For a given year and month, return nearest Tuesday to the 17th of that month

    "Critical Patch Updates are collections of security fixes for Oracle
    products. They are available to customers with valid support contracts.
    They are released on the Tuesday closest to the 17th day of January, April,
    July and October."
    [https://www.oracle.com/security-alerts/]
    """

    base_date = datetime(year, month, day)

    previous_tuesday = base_date - timedelta(days=((base_date.weekday() + 6) % 7))
    next_tuesday = base_date + timedelta(days=((1 - base_date.weekday()) % 7))

    return (
        next_tuesday
        if next_tuesday - base_date < base_date - previous_tuesday
        else previous_tuesday
    )


def _third_tuesday(year, month):
    """For a given year and month, return the 3rd Tuesday of that month

    "Critical Patch Updates provide security patches for supported Oracle on-premises products.
    They are available to customers with valid support contracts. Starting in April 2022,
    Critical Patch Updates are released on the third Tuesday of January, April, July, and October
    (They were previously published on the Tuesday closest to the 17th day of January, April, July,
     and October). The next four dates are:

    16 July 2024
    15 October 2024
    21 January 2025
    15 April 2025
    "
    [https://www.oracle.com/security-alerts/]
    """

    c = calendar.Calendar()
    monthcal = c.monthdatescalendar(year, month)
    third_tuesday = [
        day
        for week in monthcal
        for day in week
        if day.weekday() == calendar.TUESDAY and day.month == month
    ][2]
    return third_tuesday


def create_mariadb_cve_map():
    # Pull plain text of the MariaDB page since the HTML is invalid: it
    # doesn't define </li> ending tags for list elements. The HTML would
    # have to be parsed with a more lenient parser (html5lib), which is an
    # extra dependency.
    page_text = get_text_from_url(MARIADB_VULN_PAGE)

    match = re.match(
        r".+Full List of CVEs fixed in MariaDB\n(.+)\s*CVEs without specific version numbers.*",
        page_text,
        re.DOTALL,
    )

    if not match:
        raise AdvisoryParserTextException("Could not parse date from CPU URL.")

    cve_map = {}
    for cve_line in match.group(1).split("\n"):
        cve = CVE_REGEX.search(cve_line)
        versions = VERSION_REGEX.findall(cve_line)

        if cve and versions:
            cve_map[cve.group(0)] = versions

    return cve_map


def parse_mysql_advisory(url):
    # The url passed in can be either the main CPU page, or the "Text Form of
    # Risk Matrices" (aka verbose) page

    # Parse url first to get base url and cpu date
    url_match = re.search(r"/cpu([a-z]{3})(\d{4})(?:verbose)?\.html(?:#.*)?$", url)
    if not url_match:
        raise AdvisoryParserTextException("Unexpected CPU URL format.")

    # Get base url and determine advisory_url and verbose_url
    url = url[0 : url_match.start() + len("/cpuMMMYYYY")]
    advisory_url = url + ".html#AppendixMSQL"
    verbose_url = url + "verbose.html"

    # Extract the CPU's month and year from the URL since the verbose page has
    # no dates on it
    month, year = url_match.groups()
    if month.lower() not in month_to_num:
        raise AdvisoryParserTextException("Invalid month parsed from advisory URL:", str(month))
    month_num = month_to_num[month.lower()]
    year_int = int(year)
    # Starting in April 2022, Critical Patch Updates are released on the third Tuesday of January,
    # April, July, and October (They were previously published on the Tuesday closest to the 17th
    # day of January, April, July, and October).
    # [https://www.oracle.com/security-alerts/]
    if year_int < 2022:
        cpu_date = _nearest_tuesday(year_int, month_num)
    elif year_int == 2022 and month_num < 4:
        cpu_date = _nearest_tuesday(year_int, month_num)
    else:
        cpu_date = _third_tuesday(year_int, month_num)
    advisory_id = "CPU {} {}".format(month.capitalize(), year)

    # Fetch the CPU verbose page
    advisory_html = get_request(verbose_url)
    soup = bs4.BeautifulSoup(advisory_html, "html.parser")

    mysql_table = soup.find(id="MSQL").find_next("table")

    # The first row is the table header so throw that one away
    table_rows = mysql_table.find_all("tr")[1:]

    mariadb_cve_map = create_mariadb_cve_map()

    flaws, warnings = [], []
    for row in table_rows:
        # First anchor id contains the CVE
        cve = row.find("a").get("id")

        # Second td contains a description
        description_cell = row.find_all("td")[1].contents

        # Join all contents of the cell into one string
        description = []
        for element in description_cell:
            if isinstance(element, bs4.element.NavigableString) and element.string:
                description.append(element.string)
            elif isinstance(element, bs4.element.Tag) and element.text:
                description.append(element.text)

        description = "\n".join(description)

        # Take the text part only, i.e. anything before the CVSS string
        desc_cvss = re.split(r"\n\s*CVSS v?3\.[0-9] (?=Base Score)", description)
        if len(desc_cvss) != 2:
            warnings.append(
                "ERROR: Could not identify CVSS score in {}; skipping:\n\n{}\n---".format(
                    cve, description
                )
            )
            continue
        description, cvss_text = desc_cvss

        # Filter out some whitespace
        description = description.replace("\n", " ").replace("  ", " ").strip()

        product = re.search(r"^Vulnerability in the (.+) (component|product) of ", description)
        if not product:
            warnings.append(
                "ERROR: Could not identify product in {}; skipping:\n\n{}\n---".format(
                    cve, description
                )
            )
            continue
        if "MySQL Server" not in product.group(1) and "MySQL Client" not in product.group(1):
            warnings.append(
                "ERROR: Skipping {}; does not affect MySQL Server or Client component".format(cve)
            )
            continue

        # Filter out the lines that start with CVSS and find the score + vector
        match = re.search(r"Base Score\s*(\d?\d\.\d).*Vector:\s*\(([^)]+)\)", cvss_text)
        if not match:
            cvss3 = None
            warnings.append("Could not parse CVSSv3 score from {} description".format(cve))
        else:
            cvss3_score = match.group(1)
            cvss3 = cvss3_score + "/" + match.group(2)

        x = float(cvss3_score)
        if 0.0 < x < 4.0:
            impact = "low"
        elif 4.0 <= x < 7.0:
            impact = "moderate"
        elif 7.0 <= x < 9.0:
            impact = "important"
        else:
            impact = "critical"

        component = re.search(r"\((sub)?component: ([^)]+\)?)\)", description).group(2)

        summary = "mysql: {} unspecified vulnerability ({})".format(component, advisory_id)

        # Flaw descriptions contain vulnerable versions. Fixed versions are usually
        # one version higher.
        vulnerable_versions = VERSION_REGEX.findall(description)
        mysql_fixed_in = []
        for version in vulnerable_versions:
            fixed_version = "{}.{}".format(
                version.rsplit(".", 1)[0], int(version.split(".")[-1]) + 1
            )
            mysql_fixed_in.append(fixed_version)

        fixed_in = {"mysql": mysql_fixed_in}

        mariadb_fixed_in = mariadb_cve_map.get(cve)
        if mariadb_fixed_in:
            fixed_in["mariadb"] = mariadb_fixed_in

        flaws.append(
            Flaw(
                cves=[cve],
                summary=summary,
                public_date=cpu_date,
                cvss3=cvss3,
                impact=impact,
                description=description,
                fixed_in=fixed_in,
                from_url=advisory_url,
                advisory_id=advisory_id,
            )
        )

    return flaws, warnings
