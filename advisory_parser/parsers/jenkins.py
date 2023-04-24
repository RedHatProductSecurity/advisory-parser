# Copyright (c) 2019 Red Hat, Inc.
# Author: Shubh Bapna
# License: LGPLv3+

import re
from datetime import datetime

from advisory_parser.exceptions import AdvisoryParserTextException
from advisory_parser.flaw import Flaw
from .utils import get_text_from_url, find_tag_by_text, CVE_REGEX, get_request
from cvss import CVSS3


def parse_jenkins_advisory(url):
    advisory_text = get_text_from_url(url)
    severity_to_cvss3_map = extract_severity_to_cvss3_map(url)
    fixes = extract_fixes(url)

    # extract date from the url
    public_date_match = re.compile(r"\d{4}-\d{2}-\d{2}").search(url).group()
    try:
        public_date = datetime.strptime(public_date_match, "%Y-%m-%d")
    except ValueError:
        raise AdvisoryParserTextException(
            "Could not parse public date ({}) from {}".format(public_date_match, url)
        )

    # split it into chunks of advisories
    advisories = re.split(r"\n(?=.*?\nSECURITY-\d+\n/\n)", advisory_text)[1:]
    if len(advisories) == 0:
        raise AdvisoryParserTextException("No security fixes found in {}".format(url))

    flaws, warnings = [], []
    for index, advisory in enumerate(advisories):
        severity = re.search(r"(SECURITY-\d+)", advisory).group(1)
        if severity not in severity_to_cvss3_map.keys():
            warnings.append("Could not find impact or cvss; skipping: {}".format(severity))
            continue

        cves = list(set(CVE_REGEX.findall(advisory)))
        if len(cves) == 0:
            warnings.append("Could not find CVEs or bugs; skipping: {}".format(severity))
            continue

        from_url = url + "#" + severity
        summary = advisory.strip().split("\n")[0].strip()
        impact = re.search(r"(High|Medium|Low)", advisory).group(1)
        cvss3 = severity_to_cvss3_map[severity]
        description = extract_description(advisory, index == len(advisories) - 1)
        affected_plugins_fix = extract_affected_plugins_fixes(
            advisory, fixes, summary, description, severity, warnings
        )

        flaws.append(
            Flaw(
                from_url=from_url,
                cves=cves,
                summary=summary,
                public_date=public_date,
                cvss3=cvss3,
                impact=impact,
                fixed_in=affected_plugins_fix,
                description=description,
                advisory_id=severity,
            )
        )

    return flaws, warnings


def extract_description(advisory, is_last):
    description = "\n".join(advisory.strip().split("Description:")[-1].strip().split("\n")[:-1])
    # if it is last advisory then we have to remove more stuff from description
    if is_last:
        description = description.split("Severity\n")[0].strip()
    return description


def extract_affected_plugins_fixes(advisory, fixes, summary, description, severity, warnings):
    affected_plugins = [
        a.strip()
        for a in re.search(r"Affected plugins?:\n((.*\n)*?.*?)\nDescription", advisory)
        .group(1)
        .strip()
        .split(",")
    ]
    affected_plugins_fixes = {}
    for fix in fixes:
        if (
            fix.lower() in affected_plugins
            or summary.find(fix) != -1
            or description.find(fix) != -1
        ):
            affected_plugins_fixes[fix.lower()] = fixes[fix]

    for affected_plugin in affected_plugins:
        if affected_plugin not in affected_plugins_fixes:
            warnings.append(
                "{}: Could not find a fixed version for {} plugin".format(severity, affected_plugin)
            )

    return affected_plugins_fixes


def extract_severity_to_cvss3_map(url):
    severity_list = find_tag_by_text(url, "h2", re.compile(r"\s*Severity\s*")).findNext("ul")
    severity_to_cvss3_map = {}

    # jenkins marks each severity with a high, medium or low impact and links that with a url to
    # a cvss calculator. depending on the security advisory, each high, medium or low might be
    # different from the next high, medium or low, so we will try to extract the cvss vector to get
    # the most accurate cvss3 score
    for c in severity_list.findChildren("li"):
        severity, _ = list(c.stripped_strings)

        # the href url contains the cvss vector after the # example:
        # https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
        css3_vector = c.findNext().attrs["href"].split("#")[-1]

        # severity contains a colon at the end so have to remove that
        severity_to_cvss3_map[severity[:-1]] = CVSS3(css3_vector).rh_vector()

    return severity_to_cvss3_map


def extract_fixes(url):
    fixes_list = find_tag_by_text(url, "h2", re.compile(r"\s*Fix\s*")).findNext("ul")
    plugins_to_fix = {}
    # jenkins does include fixes in each advisories' description but that makes it harder to extract
    # it also does have a list of fixes for each plugin for all the advisories at the end of the page
    for fix in fixes_list.findChildren("li"):
        plugin = list(fix.stripped_strings)[0].split("Plugin")[0].strip()
        version = list(fix.stripped_strings)[1].split("version")[1].strip()
        plugins_to_fix.setdefault(plugin, []).append(version)
    return plugins_to_fix
