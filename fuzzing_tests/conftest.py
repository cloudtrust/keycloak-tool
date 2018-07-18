#!/usr/bin/env python
# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

import pytest
import json
import logging
import re

import helpers.requests as req
from helpers.logging import log_request

from bs4 import BeautifulSoup
from requests import Request, Session
from http import HTTPStatus


logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('conftest')
logger.setLevel(logging.DEBUG)


def pytest_addoption(parser):
    parser.addoption("--config-file", action="store", help="Json configuration file ", dest="config_file")


@pytest.fixture(scope='session')
def settings(pytestconfig):
    try:
        with open(pytestconfig.getoption('config_file')) as json_data:
            config = json.load(json_data)

    except IOError as e:
        raise IOError("Config file {path} not found".format(path=pytestconfig.getoption('config_file')))

    return config

@pytest.fixture(scope='session')
def import_realm(settings):
    """
    Fixture to perform the import of a realm from a JSON file
    :param settings:
    :return:
    """

    # Identity provider settings
    idp_ip = settings["idp"]["ip"]
    idp_port = settings["idp"]["port"]
    idp_scheme = settings["idp"]["http_scheme"]

    idp_username = settings["idp"]["master_realm"]["username"]
    idp_password = settings["idp"]["master_realm"]["password"]
    idp_client_id = settings["idp"]["master_realm"]["client_id"]

    idp_realm_id = settings["idp"]["master_realm"]["name"]

    filename = settings["idp"]["test_realm"]["json_file"]

    s = Session()

    access_token_data={
        "client_id": idp_client_id,
        "username": idp_username,
        "password": idp_password,
        "grant_type": "password"
    }

    access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)

    header = {
        'Accept': "application/json,text/plain, */*",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-US,en;q=0.5",
        'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
        'Connection': "keep-alive",
        'Content-Type': "application/json",
        'Referer': "{scheme}://{ip}:{port}/auth/admin/master/console/".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port
        ),
        'Host': "{ip}:{port}".format(
            ip=idp_ip,
            port=idp_port
        ),
        "DNT": "1",
        "Keep-Alive": "timeout=15, max=3",
        'Authorization': 'Bearer ' + access_token

    }

    with open(filename, "r") as f:
        realm_representation = f.read()

    req_import_realm = Request(
        method='POST',
        url="{scheme}://{ip}:{port}/auth/admin/realms".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
        ),
        headers=header,
        data=realm_representation
    )

    prepared_request = req_import_realm.prepare()

    log_request(logger, req_import_realm)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response

