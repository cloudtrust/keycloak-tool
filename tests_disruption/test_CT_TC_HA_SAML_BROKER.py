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
import logging

import helpers.requests as req
from helpers.logging import log_request

from bs4 import BeautifulSoup
from requests import Request, Session
from http import HTTPStatus

author = "Romain Poiffaut"
maintainer = "Romain Poiffaut"
version = "0.0.1"

# Logging
# Default to Debug
##################

logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('keycloak-tool.tests_disruption.test_CT_TC_HA_SAML_BROKER')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings')
class Test_CT_TC_HA_SAML_BROKER():
    """
    As a user I can create, read a realm while disruption of nodes without noticing it.
    """

    # This test expect the following environment :
    #  - 2 Keycloak : KC1, KC2
    #  - 2 CockroachDB : DB1, DB2


    def test_CT_TC_HA_DB_SAML_BROKER_ACCESS_CONTROL_RBAC_OK(self, settings):
        # After first round trip, kill all DB nodes, scenario still ok
        pass

    def test_CT_TC_HA_DB_SAML_BROKER_ACCESS_CONTROL_RBAC_KO(self, settings):
        # After first round trip, kill all DB nodes, scenario still ok
        pass

