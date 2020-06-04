# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

import re
from datetime import datetime

from advisory_parser.exceptions import AdvisoryParserTextException
from advisory_parser.flaw import Flaw
from .utils import get_text_from_url, CVE_REGEX

# Chromium does not publish CVSS scores with their CVEs so these values are
# best-effort guesses based on impact.
CVSS3_MAP = {'critical': '9.6/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H',
             'important': '8.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
             'moderate': '6.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
             'low': '4.3/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L'}


def parse_chrome_advisory(url):
    advisory_text = get_text_from_url(url)

    # Workaround for advisories that do not use <div>s for each CVE entry. E.g.:
    # https://chromereleases.googleblog.com/2018/04/stable-channel-update-for-desktop.html
    advisory_text = re.sub(r'(.)\[\$', r'\1\n[$', advisory_text)

    if 'Security Fixes' not in advisory_text:
        raise AdvisoryParserTextException('No security fixes found in {}'.format(url))

    # Throw away parts of the text after the blog post
    flaws_text = advisory_text.split('Labels:\nStable updates')[0].strip()

    # Parse out public date
    match = re.search('^Stable Channel Update for Desktop\n(.+)', flaws_text, re.MULTILINE)
    if not match:
        raise AdvisoryParserTextException('Could not find public date in {}'.format(url))

    try:
        public_date = datetime.strptime(match.group(1), "%A, %B %d, %Y")
    except ValueError:
        raise AdvisoryParserTextException(
            'Could not parse public date ({}) from {}'.format(match.group(1), url)
        )

    # Find Chrome version, e.g. 46.0.2490.71
    try:
        fixed_in = re.search(r'\d{2}\.\d\.\d{4}\.\d{2,3}', flaws_text).group(0)
    except ValueError:
        raise AdvisoryParserTextException('Could not find fixed-in version in {}'.format(url))

    # Filter out lines that contain CVEs
    cve_lines = [line.strip() for line in flaws_text.split('\n')
                 if CVE_REGEX.search(line)]
    if not cve_lines:
        raise AdvisoryParserTextException('Could not find any CVEs in {}'.format(url))

    flaws, warnings = [], []
    for line in cve_lines:
        # Parse each line containing information about a CVE, e.g.:
        # [$7500][590275] High CVE-2016-1652: XSS in X. Credit to anonymous.
        # First, split into two groups by first encountered colon.
        metadata, text = line.split(':')
        if not metadata or not text:
            warnings.append('Could not parse line: {}'.format(line))
            continue

        # If a line contains Various, it describes internal fixes, e.g.:
        # [563930] CVE-2015-6787: Various fixes from internal audits...
        if 'Various' in text:
            impact = 'important'
        else:
            match = re.search(r'(High|Medium|Low)', metadata)
            if not match:
                print('Could not find impact; skipping: {}'.format(line))
                continue
            else:
                impact = match.group(1)

            impact = impact.lower()
            impact = impact.replace('high', 'important')
            impact = impact.replace('medium', 'moderate')

        bug_ids = re.findall(r'\d{6,}', metadata)
        cves = CVE_REGEX.findall(metadata)
        if not bug_ids and not cves:
            warnings.append('Could not find CVEs or bugs; skipping: {}'.format(line))
            continue

        summary = text.split('.')[0].strip()
        if ' in ' in summary:
            issue, component = summary.split(' in ', 1)
            article = 'An' if issue.lower()[0] in 'aeiou' else 'A'
            description = ('{} {} flaw was found in the {} component of the Chromium browser.'
                           .format(article, issue.lower(), component))

        elif 'various fixes' in summary.lower():
            description = summary + '.'
            summary = 'various fixes from internal audits'

        else:
            description = ('The following flaw was identified in the Chromium browser: {}.'
                           .format(summary))

        summary = 'chromium-browser: ' + summary

        description += '\n\nUpstream bug(s):\n'
        for bug in bug_ids:
            description += '\nhttps://code.google.com/p/chromium/issues/detail?id=' + bug

        com_url = url if 'blogspot.com' in url else re.sub(r'blogspot\.[^/]*/', 'blogspot.com/', url)
        cvss3 = CVSS3_MAP[impact]

        flaws.append(Flaw(from_url=com_url, cves=cves, summary=summary, public_date=public_date,
                          cvss3=cvss3, impact=impact, fixed_in={'chromium-browser': [fixed_in]},
                          description=description))

    return flaws, warnings
