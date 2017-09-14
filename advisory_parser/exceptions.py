# -*- coding: UTF-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+


class AdvisoryParserUrlException(Exception):
    """
    Exception for unknown or malformed URL to parse.
    """
    pass


class AdvisoryParserTextException(Exception):
    """
    General exception for malformed text
    """
    pass


class AdvisoryParserGetContentException(Exception):
    """
    Exception for failures when getting advisory content
    """
    pass
