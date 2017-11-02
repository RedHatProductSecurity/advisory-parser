# -*- coding: UTF-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+

from datetime import datetime
from bs4 import BeautifulSoup

from .utils import get_request
from advisory_parser.flaw import Flaw
from advisory_parser.exceptions import AdvisoryParserTextException

DESCRIPTION_TEMPLATE = (u'Adobe Security Bulletin {advisory_id} for Adobe Flash '
                        'Player describes {flaws} that can possibly lead to {vuln_impact} '
                        'when Flash Player is used to play a specially crafted SWF file.')
CVSS_MAP = {
    'remote code execution': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    'information disclosure': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    'memory address disclosure': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
}


def parse_flash_advisory(url):
    advisory_html = get_request(url)
    soup = BeautifulSoup(advisory_html, 'html.parser')

    # Get the advisory ID and public date from the first table
    details_table = soup.find('div', {'class': 'page-description'}).find_next('table')
    table_rows = details_table.find_all('tr')

    # The first row is the header, the second contains the data we need
    advisory_id, public_date, _ = [elem.get_text() for elem in table_rows[1].find_all('td')]

    try:
        public_date = datetime.strptime(public_date, '%B %d, %Y')
    except ValueError:
        raise AdvisoryParserTextException(
            'Could not parse public date ({}) from {}'.format(public_date, url)
        )

    # Get the fixed_in version from the Solution table
    solution_table = soup.find(id='solution').find_next('table')
    table_rows = solution_table.find_all('tr')

    fixed_in = []
    for row in table_rows:
        _, version, platform, _, _ = [elem.get_text() for elem in row.find_all('td')]
        if platform == 'Linux':
            fixed_in.append(version)
            break

    # Get CVE information from the Vulnerability details table
    vulns_table = soup.find(id='Vulnerabilitydetails').find_next('table')
    table_rows = vulns_table.find_all('tr')

    # Loop over every row (excluding the header) and create a new Flaw
    flaws, warnings = [], []
    for row in table_rows[1:]:
        vuln_category, vuln_impact, impact_rating, cves = [elem.get_text() for elem in row.find_all('td')]
        vuln_category = vuln_category.lower()
        vuln_impact = vuln_impact.lower()
        impact_rating = impact_rating.lower()
        cves = cves.split()

        description = DESCRIPTION_TEMPLATE.format(
            advisory_id=advisory_id, vuln_impact=vuln_impact,
            flaws='multiple {} flaws'.format(vuln_category) if len(cves) > 1 else 'a {} flaw'.format(vuln_category)
        )

        flaws.append(Flaw(
            from_url=url, public_date=public_date, cves=cves, fixed_in={'flash-plugin': fixed_in},
            summary='flash-plugin: {} vulnerability ({})'.format(vuln_impact, advisory_id),
            impact=impact_rating, description=description,
            cvss3=CVSS_MAP.get(vuln_impact, '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'),
            advisory_id=advisory_id
        ))

    return flaws, warnings
