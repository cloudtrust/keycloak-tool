#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018:
#     Sebastien Pasche, sebastien.pasche@elca.ch
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

author = "Sebastien Pasche"
maintainer = "Sebastien Pasche"
version = "0.0.1"

import json

def prepared_request_to_json(req):
    """
    Helper dedicated to translate python request Request to a json format
    """
    json_request = dict()

    json_request['url'] = req.url

    if hasattr(req, 'headers'):
        json_request['headers'] = {}
        for header, value in req.headers.items():
            json_request['headers'][header] = value

    if hasattr(req, 'body'):
        json_request['body'] = req.body

    return json_request


def log_request(logger, req):
    """
    Helper dedicated to log a request
    """
    logger.debug(
        json.dumps(
            prepared_request_to_json(req),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )
