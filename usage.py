# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

from pprint import pprint

from advisory_parser import Parser

url = 'https://helpx.adobe.com/security/products/flash-player/apsb17-17.html'
flaws, warnings = Parser.parse_from_url(url)

for flaw in flaws:
    print()
    pprint(vars(flaw))
