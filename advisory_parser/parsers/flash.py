# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

from datetime import datetime
from itertools import groupby

from bs4 import BeautifulSoup

from advisory_parser.exceptions import AdvisoryParserTextException
from advisory_parser.flaw import Flaw
from .utils import get_request

DESCRIPTION_TEMPLATE = (u'Adobe Security Bulletin {advisory_id} for Adobe Flash '
                        'Player describes {number_of_flaws} that can possibly lead to {vuln_impact} '
                        'when Flash Player is used to play a specially crafted SWF file:\n\n'
                        '{flaw_summaries}')
CVSS_MAP = {
    'remote code execution': '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    'information disclosure': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    'memory address disclosure': '6.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
}

# Ordered severities used by Adobe: https://helpx.adobe.com/security/severity-ratings.html
SEVERITY_ORDER = ['critical', 'important', 'moderate']


def parse_flash_advisory(url):
    advisory_html = get_request(url)
    soup = BeautifulSoup(advisory_html, 'html.parser')

    # Get the advisory ID and public date from the first table
    details_table = soup.find('div', {'class': 'page-description'}).find_next('table')
    table_rows = details_table.find_all('tr')

    # The first row is the header, the second contains the data we need
    advisory_id, public_date, _ = [elem.get_text().strip() for elem in table_rows[1].find_all('td')]

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

    # Loop over every row (excluding the header) and extract flaw data; group by vuln impact
    vuln_data = []
    for row in table_rows[1:]:
        vuln_category, vuln_impact, severity, cve = [elem.get_text().strip().replace(u'\xa0', u' ')
                                                     for elem in row.find_all('td')]
        vuln_data.append((vuln_impact, vuln_category, severity, cve))

    flaws, warnings = [], []
    for vuln_impact, group_1 in groupby(sorted(vuln_data), lambda x: x[0]):
        data = list(group_1)  # Need a copy of the generator to loop over multiple times
        highest_severity = sorted([entry[2].lower() for entry in data],
                                  key=SEVERITY_ORDER.index)[0]
        all_cves = [entry[3] for entry in data]

        flaw_summaries = []
        for vuln_category, group_2 in groupby(sorted(data), lambda x: x[1]):
            cves = [entry[3] for entry in group_2]
            flaw_summaries.append('{} -- {}'.format(vuln_category, ', '.join(cves)))

        description = DESCRIPTION_TEMPLATE.format(
            advisory_id=advisory_id, vuln_impact=vuln_impact.lower(),
            number_of_flaws='multiple flaws' if len(flaw_summaries) > 1 else 'a flaw',
            flaw_summaries='\n'.join(flaw_summaries),
        )

        summary = ('flash-plugin: {} {} ({})'
                   .format(vuln_impact,
                           'vulnerability' if len(all_cves) == 1 else 'vulnerabilities',
                           advisory_id))

        flaws.append(Flaw(
            from_url=url, public_date=public_date, cves=list(all_cves),
            fixed_in={'flash-plugin': fixed_in},
            summary=summary,
            impact=highest_severity, description=description,
            cvss3=CVSS_MAP.get(vuln_impact.lower(), '8.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'),
            advisory_id=advisory_id,
        ))

    return flaws, warnings
