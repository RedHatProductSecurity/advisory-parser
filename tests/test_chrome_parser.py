import datetime
from io import open
from os import path

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from advisory_parser.parsers.chrome import parse_chrome_advisory


def load_test_data(fname):
    file_dir = path.abspath(path.dirname(__file__))
    with open(path.join(file_dir, "test_data", fname), "r", encoding="utf-8") as f:
        testing_text = f.read()
    return testing_text


@patch("advisory_parser.parsers.chrome.get_text_from_url")
def test_parser(get_text_from_url):
    get_text_from_url.return_value = load_test_data("chrome_2024-08-28.txt")
    url = "https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html"
    flaws, warnings = parse_chrome_advisory(url)

    assert not warnings
    assert len(flaws) == 4
    assert vars(flaws[0]) == {
        "summary": "chromium-browser: Type Confusion in V8",
        "cvss3": "8.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "A type confusion flaw was found in the V8 component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=351865302",
        "from_url": "https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html",
        "fixed_in": {"chromium-browser": ["128.0.6613.113"]},
        "cvss2": None,
        "advisory_id": None,
        "impact": "important",
        "cves": ["CVE-2024-7969"],
        "public_date": datetime.datetime(2024, 8, 28, 0, 0),
    }
    assert vars(flaws[1]) == {
        "summary": "chromium-browser: Heap buffer overflow in Skia",
        "cvss3": "8.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "A heap buffer overflow flaw was found in the Skia component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=360265320",
        "from_url": "https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html",
        "fixed_in": {"chromium-browser": ["128.0.6613.113"]},
        "cvss2": None,
        "advisory_id": None,
        "impact": "important",
        "cves": ["CVE-2024-8193"],
        "public_date": datetime.datetime(2024, 8, 28, 0, 0),
    }
    assert vars(flaws[2]) == {
        "summary": "chromium-browser: Type Confusion in V8",
        "cvss3": "8.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "A type confusion flaw was found in the V8 component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=360533914",
        "from_url": "https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html",
        "fixed_in": {"chromium-browser": ["128.0.6613.113"]},
        "cvss2": None,
        "advisory_id": None,
        "impact": "important",
        "cves": ["CVE-2024-8194"],
        "public_date": datetime.datetime(2024, 8, 28, 0, 0),
    }
    assert vars(flaws[3]) == {
        "summary": "chromium-browser: Heap buffer overflow in Skia",
        "cvss3": "8.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "A heap buffer overflow flaw was found in the Skia component of the Chromium browser.\n\nUpstream bug(s):\n\nhttps://code.google.com/p/chromium/issues/detail?id=360758697",
        "from_url": "https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html",
        "fixed_in": {"chromium-browser": ["128.0.6613.113"]},
        "cvss2": None,
        "advisory_id": None,
        "impact": "important",
        "cves": ["CVE-2024-8198"],
        "public_date": datetime.datetime(2024, 8, 28, 0, 0),
    }
