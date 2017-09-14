# -*- coding: UTF-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
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

    def __init__(self, from_url=None, cves=[], summary=None, public_date=None, cvss3=None,
                 cvss2=None, impact='unspecified', description=None, fixed_in=[]):
        # List of CVEs relating to a single security flaw.
        self.cves = cves

        # A summary that shortly describes the security flaw.
        self.summary = summary

        # A datetime.date object of when the security flaw was made public.
        self.public_date = public_date

        # CVSS scores
        self.cvss3 = cvss3
        self.cvss2 = cvss2

        # An impact rating using the LMIC scale (Low/Moderate/Important/Critical).
        self.impact = impact

        # A longer description of the security flaw that may include links to other resources.
        self.description = description

        # List of versions of the affected component in which the security flaw was fixed.
        self.fixed_in = fixed_in

        # The URL from which the security flaw was parsed.
        self.from_url = from_url

    # Sort highest impact to lowest impact
    def __lt__(self, other):
        return (IMPACT_WEIGHT.get(self.impact, IMPACT_WEIGHT['unspecified']) <
                IMPACT_WEIGHT.get(other.impact, IMPACT_WEIGHT['unspecified']))

    def __gt__(self, other):
        return (IMPACT_WEIGHT.get(self.impact, IMPACT_WEIGHT['unspecified']) >
                IMPACT_WEIGHT.get(other.impact, IMPACT_WEIGHT['unspecified']))
