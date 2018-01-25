#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013:
#     Sebastien Pasche, sebastien.pasche@leshop.ch
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

def pytest_addoption(parser):

    ##Keycloak args
    ###############

    group = parser.getgroup('KeyCloak integration')

    group.addoption(
        "--config-file",
        action="store",
        default="./tests_config/dev.json",
        dest="config_file",
        help="Test configuration files"
    )

# Fixtures
##########

@pytest.fixture
def disable_http_warning(target_logger):
    """
    Disable HTTPS warning at urlib3 level
    :return:
    """
    target_logger.debug("Disabling https warning")
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

@pytest.fixture
def test_settings(pytestconfig,target_logger):
    """
    Load json based configuration file from --config-file fixures args
    :param pytestconfig: pytest config containing --config-file args values
    :return: Dict containing loaded configuration
    """
    config_file = Path(pytestconfig.getoption('config_file')).absolute()
    target_logger.debug(config_file)
    try:

        with open(config_file) as json_data:
            config = json.load(json_data)

    except FileNotFoundError:
        raise FileNotFoundError("Config file {path} not found".format(path=config_file))
    else:

        target_logger.debug(
            json.dumps(
                config,
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

    return config
