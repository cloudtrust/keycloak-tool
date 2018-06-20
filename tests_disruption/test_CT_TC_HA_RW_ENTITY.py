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
from requests import Request, Session
import time


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
logger = logging.getLogger('keycloak-tool.tests_disruption.test_CT_TC_HA_RW_ENTITY')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings')
class Test_CT_TC_HA_RW_ENTITY():
    """
    As a user I can create, read a realm while disruption of nodes without noticing it.
    """

    # This test expect the following environment :
    #  - 2 Keycloak : KC1, KC2
    #  - 2 CockroachDB : DB1, DB2


    # Check HA for CockroachDB with creation and deletion of realm.
    # Test propagation of persitent data accross DB nodes while disruption
    def test_CT_TC_HA_DB_SIMPLE_RW(self, settings):
        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["master_realm"]["username"]
        idp_password = settings["idp"]["master_realm"]["password"]
        idp_client_id = settings["idp"]["master_realm"]["client_id"]

        idp_realm_id = settings["idp"]["master_realm"]["name"]

        filename = settings["idp"]["test_realm"]["json_file"]
        realm_to_create = "test_disruption"

        # Build token for connection to Keycloak
        s = Session()

        access_token_data = {
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

        # Check realm does not exist
        req_get_realms = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
                scheme=idp_scheme,
                ip=idp_ip,
                port=idp_port,
                realm=realm_to_create,
            ),
            headers=header,
        )

        prepared_request = req_get_realms.prepare()

        log_request(logger, req_get_realms)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 404

        # TODO
        # Kill DB2
        #kubectl exec -it cockroach-1 -- systemctl stop cockroach


        # Create new realm
        # The new realm is persisted in DB1 only

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
        assert response.status_code == 201


        # TODO
        # Restart DB2 and wait a bit to propagate the realm in DB2
        # kubectl exec -it cockroach-1 -- systemctl start cockroach
        # time.sleep(5)

        # Restart DB1
        # kubectl exec -it cockroach-0 -- systemctl stop cockroach

        # Restart all KC
        # kubectl scale keycloak 0
        # kubectl scale keycloak 2


        # Check new realm is visible from KC2

        prepared_request = req_get_realms.prepare()

        log_request(logger, req_get_realms)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 200

        # Delete the newly created realm

        req_delete_realm = Request(
            method='DELETE',
            url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
                scheme=idp_scheme,
                ip=idp_ip,
                port=idp_port,
                realm=realm_to_create
            ),
            headers=header,
        )

        prepared_request = req_delete_realm.prepare()

        log_request(logger, req_delete_realm)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 200

        #TODO
        # Restart DB1
        # Restart all KC
        # Kill DB2


        # List and check realm is deleted

        prepared_request = req_get_realms.prepare()

        log_request(logger, req_get_realms)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 404

    # Test behavior during DB disruption
    def test_CT_TC_HA_NO_DB(self, settings):
        # All components running

        # Ensure Infinityspan cache of KC nodes is empty -> Restart
        # TODO restart all KC

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["master_realm"]["username"]
        idp_password = settings["idp"]["master_realm"]["password"]
        idp_client_id = settings["idp"]["master_realm"]["client_id"]

        idp_realm_id = settings["idp"]["master_realm"]["name"]

        filename = settings["idp"]["test_realm"]["json_file"]
        realm_to_create = "test_disruption"

        # Build token for connection to Keycloak
        s = Session()

        access_token_data = {
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

        # Kill DB1 & DB2



        # Try to create new realm -> error expected

        # Create new realm
        # The new realm is persisted in DB1 only

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
        assert response.status_code == 400

        # Start DB1 & DB2

        # Create realm
        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 201

        # Kill DB1 & DB2


        # List all realms & check behavior -> No error expected cache should be populated
        req_get_realms = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
                scheme=idp_scheme,
                ip=idp_ip,
                port=idp_port,
                realm=realm_to_create,
            ),
            headers=header,
        )

        prepared_request = req_get_realms.prepare()

        log_request(logger, req_get_realms)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 200

        # Start DB1 & DB2

        # Delete
        req_delete_realm = Request(
            method='DELETE',
            url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
                scheme=idp_scheme,
                ip=idp_ip,
                port=idp_port,
                realm=realm_to_create
            ),
            headers=header,
        )

        prepared_request = req_delete_realm.prepare()

        log_request(logger, req_delete_realm)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 200


    # Test Infinityspan propagates cache accross nodes
    def test_CT_TC_HA_IF_SIMPLE_RW(self, settings):
        # All components running

        # Ensure Infinityspan cache of KC nodes is empty -> Restart
        # TODO
        # Kill KC1 & KC2

        # Restart KC1

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["master_realm"]["username"]
        idp_password = settings["idp"]["master_realm"]["password"]
        idp_client_id = settings["idp"]["master_realm"]["client_id"]

        idp_realm_id = settings["idp"]["master_realm"]["name"]

        filename = settings["idp"]["test_realm"]["json_file"]
        realm_to_create = "test_disruption"

        # Build token for connection to Keycloak
        s = Session()

        access_token_data = {
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

        # Create new realm (target will be KC1 )
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
        assert response.status_code == 200

        # Restart KC2

        # Kill DB1, DB2

        # Kill KC1 (wait a bit to ensure cache is propagated to KC2)
        time.sleep(5)


        # Check the new realm is there -> info is coming from cache
        req_get_realms = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
                scheme=idp_scheme,
                ip=idp_ip,
                port=idp_port,
                realm=realm_to_create,
            ),
            headers=header,
        )

        prepared_request = req_get_realms.prepare()

        log_request(logger, req_get_realms)

        response = s.send(prepared_request, verify=False)

        logger.debug(response.status_code)
        assert response.status_code == 200