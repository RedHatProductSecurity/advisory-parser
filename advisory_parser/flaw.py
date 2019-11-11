# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

IMPACT_WEIGHT = {
    'critical': 0,
    'important': 1,
    'moderate': 2,
    'low': 3,
    'unspecified': 4,
}


class Flaw:
    """Object that represents a scraped security flaw with all its metadata"""

    def __init__(self, from_url=None, cves=None, summary=None, public_date=None, cvss3=None,
                 cvss2=None, impact='unspecified', description=None, fixed_in=None, advisory_id=None):

        # List of CVEs relating to a single security flaw.
        self.cves = cves or []

        # A summary that shortly describes the security flaw.
        self.summary = summary

        # A datetime.datetime object of when the security flaw was made public.
        self.public_date = public_date

        # CVSS scores
        self.cvss3 = cvss3
        self.cvss2 = cvss2

        # An impact rating using the LMIC scale (Low/Moderate/Important/Critical).
        self.impact = impact

        # A longer description of the security flaw that may include links to other resources.
        self.description = description

        # Dictionary of components and their versions in which the security flaw was fixed.
        self.fixed_in = fixed_in or {}

        # The URL from which the security flaw was parsed.
        self.from_url = from_url

        # The ID of the scraped advisory, if one exists (e.g. APSB17-28 for Flash)
        self.advisory_id = advisory_id

    # Sort highest impact to lowest impact
    def __lt__(self, other):
        return (IMPACT_WEIGHT.get(self.impact, IMPACT_WEIGHT['unspecified']) <
                IMPACT_WEIGHT.get(other.impact, IMPACT_WEIGHT['unspecified']))

    def __gt__(self, other):
        return (IMPACT_WEIGHT.get(self.impact, IMPACT_WEIGHT['unspecified']) >
                IMPACT_WEIGHT.get(other.impact, IMPACT_WEIGHT['unspecified']))
