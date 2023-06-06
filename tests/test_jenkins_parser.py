import datetime
from io import open
from os import path

import pytest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.parsers.jenkins import (
    parse_jenkins_advisory,
    extract_severity_to_cvss3_map,
    extract_fixes,
    extract_advisories,
)


def load_test_data(fname):
    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, "test_data", fname), "r", encoding="utf-8") as f:
        testing_text = f.read()
    return testing_text


@patch("advisory_parser.parsers.jenkins.get_request")
def test_parser(get_request):
    get_request.return_value = load_test_data("jenkins_2023-04-12.html")
    url = "https://www.jenkins.io/security/advisory/2023-04-12/"
    flaws, warnings = parse_jenkins_advisory(url)
    print(warnings)

    # sort multiple cves to make comparison easier
    flaws[0].cves = sorted(flaws[0].cves)

    assert len(flaws) == 14
    assert vars(flaws[0]) == {
        "summary": "jenkins-plugin: kubernetes, azure-keyvault, thycotic-devops-secrets-vault: "
        "Improper masking of credentials in multiple plugins",
        "cvss3": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "description": "Multiple plugins do not properly mask (i.e., replace with "
        "asterisks) credentials printed in the build log from Pipeline "
        "steps like sh and bat, when both of the following conditions "
        "are met:\n"
        "The credentials are printed in build steps executing on an "
        "agent (typically inside a node block).\n"
        "Push mode for durable task logging is enabled.\n"
        "This is a hidden option in Pipeline: Nodes and Processes that "
        "can be enabled through the Java system property "
        "org.jenkinsci.plugins.workflow.steps.durable_task.DurableTaskStep.USE_WATCHING.\n"
        "It is also automatically enabled by some plugins, e.g., "
        "OpenTelemetry and Pipeline Logging over CloudWatch.\n"
        "The following plugins are affected by this vulnerability:\n"
        "Kubernetes 3909.v1f2c633e8590 and earlier (SECURITY-3079 / "
        "CVE-2023-30513)\n"
        "Azure Key Vault 187.va_cd5fecd198a_ and earlier "
        "(SECURITY-3051 / CVE-2023-30514)\n"
        "Thycotic DevOps Secrets Vault 1.0.0 (SECURITY-3078 / "
        "CVE-2023-30515)\n"
        "The following plugins have been updated to properly mask "
        "credentials in the build log when push mode for durable task "
        "logging is enabled:\n"
        "Kubernetes 3910.ve59cec5e33ea_ (SECURITY-3079 / "
        "CVE-2023-30513)\n"
        "Azure Key Vault 188.vf46b_7fa_846a_1 (SECURITY-3051 / "
        "CVE-2023-30514)\n"
        "As of publication of this advisory, there is no fix available "
        "for the following plugin:\n"
        "Thycotic DevOps Secrets Vault 1.0.0 (SECURITY-3078 / "
        "CVE-2023-30515)\n"
        "An improvement in Credentials Binding 523.525.vb_72269281873 "
        "implements a workaround that applies build log masking even "
        "in affected plugins.",
        "from_url": "https://www.jenkins.io/security/advisory/2023-04-12/#SECURITY-3075",
        "fixed_in": {
            "kubernetes": ["3910.ve59cec5e33ea_"],
            "azure key vault": ["188.vf46b_7fa_846a_1"],
        },
        "cvss2": None,
        "advisory_id": "SECURITY-3075",
        "impact": "moderate",
        "cves": sorted(["CVE-2023-30515", "CVE-2023-30513", "CVE-2023-30514"]),
        "public_date": datetime.datetime(2023, 4, 12, 0, 0),
    }

    assert vars(flaws[-1]) == {
        "summary": "jenkins-plugin: spoonscript: Lack of authentication mechanism in TurboScript Plugin webhook",
        "cvss3": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        "description": "TurboScript Plugin provides a webhook endpoint at "
        "/turbo-webhook/ that can be used to trigger builds of jobs "
        "configured to use a specified repository.\n"
        "In TurboScript Plugin 1.3 and earlier, this endpoint can be "
        "accessed by attackers with Item/Read permission to trigger "
        "builds of jobs corresponding to the attacker-specified "
        "repository.\n"
        "As of publication of this advisory, there is no fix.",
        "from_url": "https://www.jenkins.io/security/advisory/2023-04-12/#SECURITY-2851",
        "fixed_in": {},
        "cvss2": None,
        "advisory_id": "SECURITY-2851",
        "impact": "moderate",
        "cves": ["CVE-2023-30532"],
        "public_date": datetime.datetime(2023, 4, 12, 0, 0),
    }

    assert "SECURITY-3075: Could not find a fixed version for azure-keyvault plugin" in warnings
    assert (
        "SECURITY-3075: Could not find a fixed version for thycotic-devops-secrets-vault plugin"
        in warnings
    )
    assert "SECURITY-3075: Could not find a fixed version for kubernetes plugin" not in warnings
    assert "SECURITY-2851: Could not find a fixed version for spoonscript plugin" in warnings


@patch("advisory_parser.parsers.jenkins.get_request")
def test_extract_severity_to_cvss3_map(get_request):
    get_request.return_value = load_test_data("jenkins_2023-04-12.html")
    url = "https://www.jenkins.io/security/advisory/2023-04-12/"
    impact_to_cvss3_map = extract_severity_to_cvss3_map(url)

    assert impact_to_cvss3_map == {
        "SECURITY-2837": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "impact": "moderate",
        },
        "SECURITY-2840": {
            "score": "5.3/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
            "impact": "moderate",
        },
        "SECURITY-2841": {
            "score": "5.9/CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-2849": {
            "score": "5.3/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-2850": {
            "score": "8.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "impact": "important",
        },
        "SECURITY-2851": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-2872": {
            "score": "5.3/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-2873": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-2944": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "impact": "moderate",
        },
        "SECURITY-2945": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "impact": "moderate",
        },
        "SECURITY-2950": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-2992": {
            "score": "3.3/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "impact": "low",
        },
        "SECURITY-3013": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "impact": "moderate",
        },
        "SECURITY-3075": {
            "score": "4.3/CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "impact": "moderate",
        },
    }


@patch("advisory_parser.parsers.jenkins.get_request")
def test_extract_fixes(get_request):
    get_request.return_value = load_test_data("jenkins_2023-04-12.html")
    url = "https://www.jenkins.io/security/advisory/2023-04-12/"
    fixes = extract_fixes(url)
    assert fixes == {
        "Azure Key Vault": ["188.vf46b_7fa_846a_1"],
        "Kubernetes": ["3910.ve59cec5e33ea_"],
    }


@patch("advisory_parser.parsers.jenkins.get_request")
def test_extract_advisories(get_request):
    get_request.return_value = load_test_data("jenkins_2023-04-12.html")
    url = "https://www.jenkins.io/security/advisory/2023-04-12/"
    advisories = extract_advisories(url)
    assert len(advisories) == 14
