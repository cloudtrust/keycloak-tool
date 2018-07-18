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

import logging
import pytest
import re
from requests import Request, Session
import json
import jsonschema
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
logger = logging.getLogger('keycloak-tool.tests.service_keycloak_bridge')
logger.setLevel(logging.DEBUG)


@pytest.fixture()
def default_route_json_schema():
    schema = {
        "type": "object",
        "$schema": "http://json-schema.org/schema#",
        "properties": {
            "name": {
                "type": "string"
            },
            "version": {
                "$id": "/properties/version",
                "type": "string"
            },
            "environment": {
                "type": "string"
            },
            "commit": {
                "type": "string"
            }
        },
    }
    return schema

@pytest.fixture()
def services_json_schema():
    schema = {
        "type": "object",
        "$schema": "http://json-schema.org/schema#",
        "required": ["influx", "jaeger", "keycloak", "redis", "sentry"],
        "properties": {
            "influx": {
                "type": "string"
            },
            "jaeger": {
                "type": "string"
            },
            "keycloak": {
                "type": "string"
            },
            "redis": {
                "type": "string"
            },
            "sentry":{
                "type": "string"
            }
        },
    }
    return schema



@pytest.mark.usefixtures('disable_http_warning', scope='classe')
@pytest.mark.usefixtures('test_settings', scope='classe')
@pytest.mark.usefixtures('default_route_json_schema', scope='classe')
class TestKeycloakServiceBridge(object):
    """
    KeyCloak bridge service test.
    This test targets a running and working instance of keycloak bridge connect to his keycloak instance
    """

    def test_is_keycloak_bridge_online(self, test_settings, default_route_json_schema):
        """
        Test if keycloak bridge service is running
        :param test_settings: pytest config loaded from config file
        :return:
        """

        #Challange value
        component_name = test_settings['keycloak_bridge']['component_name']

        #Settings
        keycloak_bridge_hostname = test_settings['keycloak_bridge']['hostname']
        keycloak_bridge_scheme = test_settings['keycloak_bridge']['http_scheme']
        keycloak_bridge_ip = test_settings['keycloak_bridge']['ip']
        keycloak_bridge_port = test_settings['keycloak_bridge']['port']

        #Test
        s = Session()

        headers = {
            'Accept': "application/json'",
            'Host':   '{host}'.format(host=keycloak_bridge_hostname)
        }

        req = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/".format(
                scheme=keycloak_bridge_scheme,
                ip=keycloak_bridge_ip,
                port=keycloak_bridge_port
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
        response_json = response.json()

        assert jsonschema.Draft3Validator(default_route_json_schema).is_valid(response_json)

        assert re.search(
            component_name,
            response_json['name']
        )


    def test_are_all_services_running(self, test_settings, services_json_schema):
        """
        Test if all the services are up by doing a health check
        :param test_settings: pytest config loaded from config file
        :return:
        """

        #Challange value
        fail_value = "KO"

        #Settings
        keycloak_bridge_hostname = test_settings['keycloak_bridge']['hostname']
        keycloak_bridge_scheme = test_settings['keycloak_bridge']['http_scheme']
        keycloak_bridge_ip = test_settings['keycloak_bridge']['ip']
        keycloak_bridge_port = test_settings['keycloak_bridge']['port']

        #Test
        s = Session()

        headers = {
            'Accept': "application/json'",
            'Host':   '{host}'.format(host=keycloak_bridge_hostname)
        }

        req = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/health".format(
                scheme=keycloak_bridge_scheme,
                ip=keycloak_bridge_ip,
                port=keycloak_bridge_port
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
        response_json = response.json()

        assert jsonschema.Draft3Validator(services_json_schema).is_valid(response_json)

        assert re.search(
            fail_value,
            response.text
        ) is None
