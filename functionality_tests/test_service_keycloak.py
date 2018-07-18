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

from pathlib import Path
import logging
import pytest
import requests
import re
from requests import Request, Session
from urllib3.exceptions import InsecureRequestWarning
import json
from helpers.logging import prepared_request_to_json

author = "Sebastien Pasche"
maintainer = "Sebastien Pasche"
version = "0.0.1"

# Logging
# Default to Debug
##################

logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('keycloak-tool.tests.service_keycloak')
logger.setLevel(logging.DEBUG)

# # Fixture
# #########
#
# @pytest.fixture(scope='module')
# def target_logger():
#     """
#     Allow logger injection within global fixtures
#     """
#     return logger

# Tests
#######

@pytest.mark.usefixtures('disable_http_warning', scope='classe')
@pytest.mark.usefixtures('test_settings', scope='classe')
class TestKeycloakService(object):
    """
    KeyCloak service test.
    This tests target a running and working instance of keycloak
    """

    def test_is_keycloak_online(self, test_settings):
        """
        Test if keycloak service is running
        :param test_settings: pytest config loaded from config file
        :return:
        """

        # Challenge value
        keycloak_welcome_validation = 'Welcome to Keycloak'

        # Settings
        keycloak_hostname = test_settings['keycloak']['hostname']
        keycloak_scheme = test_settings['keycloak']['http_scheme']
        keycloak_ip = test_settings['keycloak']['ip']
        keycloak_port = test_settings['keycloak']['port']

        # Test
        s = Session()

        headers = {
            'Accept': "text/html; charset = UTF-8",
            'Host':   '{host}'.format(host=keycloak_hostname)
        }

        req = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/auth/".format(
                scheme=keycloak_scheme,
                port=keycloak_port,
                ip=keycloak_ip
            ),
            headers=headers
        )

        prepared_request = req.prepare()

        logger.debug(
            json.dumps(
                prepared_request_to_json(req),
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

        response = s.send(prepared_request, verify=False)

        assert re.search(
            keycloak_welcome_validation,
            response.text
        )





