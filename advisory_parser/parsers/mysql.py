# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+

import re
from datetime import date, timedelta
import bs4

from .utils import get_request
from advisory_parser.flaw import Flaw
from advisory_parser.exceptions import AdvisoryParserTextException


def _nearest_tuesday(year, month, day=17):
    """For a given year and month, return nearest Tuesday to the 17th of that month

    "Critical Patch Updates are collections of security fixes for Oracle
    products. They are available to customers with valid support contracts.
    They are released on the Tuesday closest to the 17th day of January, April,
    July and October."
    [https://www.oracle.com/technetwork/topics/security/alerts-086861.html]
    """
    month_to_num = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }

    if month.lower() not in month_to_num:
        raise AdvisoryParserTextException('Invalid month parsed from advisory URL:', str(month))

    base_date = date(year, month_to_num[month.lower()], day)

    previous_tuesday = base_date - timedelta(days=((base_date.weekday() + 6) % 7))
    next_tuesday = base_date + timedelta(days=((1 - base_date.weekday()) % 7))

    return next_tuesday if next_tuesday - base_date < base_date - previous_tuesday else previous_tuesday


def parse_mysql_advisory(url):

    if 'verbose' not in url:
        raise AdvisoryParserTextException(
            'Please provide a verbose URL, e.g.: '
            'http://www.oracle.com/technetwork/security-advisory/cpuoct2016verbose-2881725.html'
        )

    advisory_html = get_request(url)
    soup = bs4.BeautifulSoup(advisory_html, 'html.parser')

    mysql_table = soup.find(id='MSQL').find_next('table')

    # The first row is the table header so throw that one away
    table_rows = mysql_table.find_all('tr')[1:]
    advisory_url = table_rows[0].find('a', text='Advisory')['href']

    # Extract the CPU's month and year from the URL since the page has no dates on it.
    date_match = re.search(r'/cpu([a-z]{3})(\d{4})verbose', url)
    if not date_match:
        raise AdvisoryParserTextException('Could not parse date from CPU URL.')

    month, year = date_match.groups()
    cpu_date = _nearest_tuesday(int(year), month)

    flaws, warnings = [], []
    for row in table_rows:
        # First anchor hyperlink contains the CVE
        cve = row.find('a').string

        # Second td contains a description
        description_cell = row.find_all('td')[1].contents

        # Join all contents of the cell into one string
        description = []
        for element in description_cell:
            if isinstance(element, bs4.element.NavigableString) and element.string:
                description.append(element.string)
            elif isinstance(element, bs4.element.Tag) and element.text:
                description.append(element.text)

        description = '\n'.join(description)

        # Take the text part only, i.e. anything before the CVSS string
        description, cvss_text = description.split('CVSS v3.0')

        # Filter out some whitespace
        description = description.replace('\n', ' ').replace('  ', ' ').strip()

        product = re.search('Vulnerability in the (.+) component', description)
        if not product:
            warnings.append('ERROR: Could not identify product in {}; skipping:\n\n{}\n---'
                            .format(cve, description))
            continue
        if 'MySQL Server' not in product.group(1):
            warnings.append('ERROR: Skipping {}; does not affect MySQL Server component'
                            .format(cve))
            continue

        # Filter out the lines that start with CVSS and find the score + vector
        match = re.search(r'Score\s*(\d?\d\.\d).*Vector:\s*\(([^\)]+)\)', cvss_text)
        if not match:
            cvss3 = None
            warnings.append('Could not parse CVSSv3 score from {} description'.format(cve))
        else:
            cvss3_score = match.group(1)
            cvss3 = cvss3_score + '/' + match.group(2)

        x = float(cvss3_score)
        if 0.0 < x < 4.0:
            impact = 'low'
        elif 4.0 <= x < 7.0:
            impact = 'moderate'
        elif 7.0 <= x < 9.0:
            impact = 'important'
        else:
            impact = 'critical'

        component = re.search(r'subcomponent: ([^\)]*)\)', description).group(1)

        summary = ('mysql: {} unspecified vulnerability (CPU {} {})'
                   .format(component, month.capitalize(), year))

        # Flaw descriptions contain vulnerable versions. Fixed versions are usually
        # one version higher.
        vulnerable_versions = re.findall('(\d\.\d\.\d\d?)', description)
        fixed_in = []
        for version in vulnerable_versions:
            fixed_version = '{}.{}'.format(version.rsplit('.', 1)[0], int(version.split('.')[-1]) + 1)
            fixed_in.append(fixed_version)

        flaws.append(Flaw(
            cves=[cve],
            summary=summary,
            public_date=cpu_date,
            cvss3=cvss3,
            impact=impact,
            description=description,
            fixed_in=fixed_in,
            from_url=advisory_url,
        ))

    return flaws, warnings
