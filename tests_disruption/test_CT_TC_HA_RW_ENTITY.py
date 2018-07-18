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
import os

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
    # def test_CT_TC_HA_DB_SIMPLE_RW(self, settings):
    #     os.system("kubectl exec -it cockroach-0 -- systemctl stop monit")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl stop monit")
    #     os.system("kubectl exec -it cockroach-2 -- systemctl stop monit")
    #
    #     os.system("kubectl exec -it keycloak-0 -- systemctl stop monit")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl stop monit")
    #
    #     # Ensure start
    #     os.system("kubectl exec -it cockroach-0 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-2 -- systemctl start cockroach")
    #
    #     os.system("kubectl exec -it keycloak-0 -- systemctl start keycloak")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl start keycloak")
    #
    #
    #     # Identity provider settings
    #     idp_ip = settings["idp"]["ip"]
    #     idp_port = settings["idp"]["port"]
    #     idp_scheme = settings["idp"]["http_scheme"]
    #
    #     idp_username = settings["idp"]["master_realm"]["username"]
    #     idp_password = settings["idp"]["master_realm"]["password"]
    #     idp_client_id = settings["idp"]["master_realm"]["client_id"]
    #
    #     idp_realm_id = settings["idp"]["master_realm"]["name"]
    #
    #     filename = settings["idp"]["test_realm_ha"]["json_file"]
    #     realm_to_create = settings["idp"]["test_realm_ha"]["name"]
    #
    #     # Build token for connection to Keycloak
    #     s = Session()
    #
    #     access_token_data = {
    #         "client_id": idp_client_id,
    #         "username": idp_username,
    #         "password": idp_password,
    #         "grant_type": "password"
    #     }
    #
    #     access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)
    #
    #     header = req.create_header(idp_scheme, idp_ip, idp_port, access_token)
    #
    #
    #     # Check realm does not exist
    #     req_get_realms = Request(
    #         method='GET',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #             realm=realm_to_create,
    #         ),
    #         headers=header,
    #     )
    #
    #     prepared_request = req_get_realms.prepare()
    #
    #     log_request(logger, req_get_realms)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 404
    #
    #     # Kill DB2
    #     os.system("kubectl exec -it cockroach-2 -- systemctl stop cockroach")
    #     time.sleep(5)
    #
    #
    #     # Create new realm
    #     # The new realm is persisted in DB0 & DB1
    #
    #     with open(filename, "r") as f:
    #         realm_representation = f.read()
    #
    #     req_import_realm = Request(
    #         method='POST',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #         ),
    #         headers=header,
    #         data=realm_representation
    #     )
    #
    #     prepared_request = req_import_realm.prepare()
    #
    #     log_request(logger, req_import_realm)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 201
    #
    #
    #     # Restart DB2 and kill DB1
    #     os.system("kubectl exec -it cockroach-2 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl stop cockroach")
    #
    #     # Restart all KC
    #     os.system("kubectl exec -it keycloak-0 -- systemctl restart keycloak")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl restart keycloak")
    #     req.wait_online(s, idp_scheme, idp_ip, idp_port, 60)
    #
    #
    #     # Build token for connection to Keycloak
    #     access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)
    #
    #     header = req.create_header(idp_scheme, idp_ip, idp_port, access_token)
    #
    #     # Check new realm is visible from KC2
    #     req_get_realms = Request(
    #         method='GET',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #             realm=realm_to_create,
    #         ),
    #         headers=header,
    #     )
    #
    #     prepared_request = req_get_realms.prepare()
    #
    #     log_request(logger, req_get_realms)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 200
    #
    #     # Delete the newly created realm
    #     req_delete_realm = Request(
    #         method='DELETE',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #             realm=realm_to_create
    #         ),
    #         headers=header,
    #     )
    #
    #     prepared_request = req_delete_realm.prepare()
    #
    #     log_request(logger, req_delete_realm)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 204
    #
    #     # Restart DB1
    #     os.system("kubectl exec -it cockroach-1 -- systemctl start cockroach")
    #
    #     # Restart all KC
    #     os.system("kubectl exec -it keycloak-0 -- systemctl restart keycloak")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl restart keycloak")
    #
    #     req.wait_online(s, idp_scheme, idp_ip, idp_port, 60)
    #
    #     # Kill DB0
    #     os.system("kubectl exec -it cockroach-0 -- systemctl stop cockroach")
    #
    #     # Build token for connection to Keycloak
    #
    #     access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)
    #
    #     header = req.create_header(idp_scheme, idp_ip, idp_port, access_token)
    #
    #     # List and check realm is deleted
    #     req_get_realms = Request(
    #         method='GET',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #             realm=realm_to_create,
    #         ),
    #         headers=header,
    #     )
    #
    #     prepared_request = req_get_realms.prepare()
    #
    #     log_request(logger, req_get_realms)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 404
    #
    #
    #     #Clean state
    #     os.system("kubectl exec -it cockroach-0 -- systemctl start cockroach")
    #
    #     os.system("kubectl exec -it cockroach-0 -- systemctl start monit")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl start monit")
    #     os.system("kubectl exec -it cockroach-2 -- systemctl start monit")
    #
    #     os.system("kubectl exec -it keycloak-0 -- systemctl start monit")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl start monit")


    # Test behavior during DB disruption
    # Cockroach hangs for ever when corrum is not available
    # def test_CT_TC_HA_NO_DB(self, settings):
    #     os.system("kubectl exec -it cockroach-0 -- systemctl stop monit")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl stop monit")
    #     os.system("kubectl exec -it cockroach-2 -- systemctl stop monit")
    #
    #     os.system("kubectl exec -it keycloak-0 -- systemctl stop monit")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl stop monit")
    #
    #     # Ensure start
    #     os.system("kubectl exec -it cockroach-0 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-2 -- systemctl start cockroach")
    #
    #     os.system("kubectl exec -it keycloak-0 -- systemctl start keycloak")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl start keycloak")
    #
    #
    #     # Identity provider settings
    #     idp_ip = settings["idp"]["ip"]
    #     idp_port = settings["idp"]["port"]
    #     idp_scheme = settings["idp"]["http_scheme"]
    #
    #     idp_username = settings["idp"]["master_realm"]["username"]
    #     idp_password = settings["idp"]["master_realm"]["password"]
    #     idp_client_id = settings["idp"]["master_realm"]["client_id"]
    #
    #     idp_realm_id = settings["idp"]["master_realm"]["name"]
    #
    #     filename = settings["idp"]["test_realm"]["json_file"]
    #     realm_to_create = "test_disruption"
    #
    #     s = Session()
    #
    #     # Ensure Infinityspan cache of KC nodes is empty -> Restart
    #     os.system("kubectl exec -it keycloak-0 -- systemctl restart keycloak")
    #     os.system("kubectl exec -it keycloak-1 -- systemctl restart keycloak")
    #
    #     req.wait_online(s, idp_scheme, idp_ip, idp_port, 60)
    #
    #     # Build token for connection to Keycloak
    #     access_token_data = {
    #         "client_id": idp_client_id,
    #         "username": idp_username,
    #         "password": idp_password,
    #         "grant_type": "password"
    #     }
    #
    #     access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)
    #
    #     header = req.create_header(idp_scheme, idp_ip, idp_port, access_token)
    #
    #     # Kill DB1 & DB2
    #     os.system("kubectl exec -it cockroach-0 -- systemctl stop cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl stop cockroach")
    #
    #
    #     # Try to create new realm -> error expected
    #     with open(filename, "r") as f:
    #         realm_representation = f.read()
    #
    #     req_import_realm = Request(
    #         method='POST',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #         ),
    #         headers=header,
    #         data=realm_representation
    #     )
    #
    #     prepared_request = req_import_realm.prepare()
    #
    #     log_request(logger, req_import_realm)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 400
    #
    #
    #     # start DB1 & DB2
    #     os.system("kubectl exec -it cockroach-0 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl start cockroach")
    #     time.sleep(10)
    #
    #     # Create realm -> Ok
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 201
    #
    #     # Kill DB1 & DB2
    #     os.system("kubectl exec -it cockroach-0 -- systemctl stop cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl stop cockroach")
    #
    #
    #     # List all realms & check behavior -> No error expected cache should be populated
    #     req_get_realms = Request(
    #         method='GET',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #             realm=realm_to_create,
    #         ),
    #         headers=header,
    #     )
    #
    #     prepared_request = req_get_realms.prepare()
    #
    #     log_request(logger, req_get_realms)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 200
    #
    #     # Start DB1 & DB2
    #     os.system("kubectl exec -it cockroach-0 -- systemctl start cockroach")
    #     os.system("kubectl exec -it cockroach-1 -- systemctl start cockroach")
    #     time.sleep(10)
    #
    #     # Delete
    #     req_delete_realm = Request(
    #         method='DELETE',
    #         url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
    #             scheme=idp_scheme,
    #             ip=idp_ip,
    #             port=idp_port,
    #             realm=realm_to_create
    #         ),
    #         headers=header,
    #     )
    #
    #     prepared_request = req_delete_realm.prepare()
    #
    #     log_request(logger, req_delete_realm)
    #
    #     response = s.send(prepared_request, verify=False)
    #
    #     logger.debug(response.status_code)
    #     assert response.status_code == 204


    # # Test Infinityspan propagates cache accross nodes
    def test_CT_TC_HA_IF_SIMPLE_RW(self, settings):
        # All components running
        os.system("kubectl exec -it cockroach-0 -- systemctl stop monit")
        os.system("kubectl exec -it cockroach-1 -- systemctl stop monit")
        os.system("kubectl exec -it cockroach-2 -- systemctl stop monit")

        os.system("kubectl exec -it keycloak-0 -- systemctl stop monit")
        os.system("kubectl exec -it keycloak-1 -- systemctl stop monit")

        # Ensure start
        os.system("kubectl exec -it cockroach-0 -- systemctl start cockroach")
        os.system("kubectl exec -it cockroach-1 -- systemctl start cockroach")
        os.system("kubectl exec -it cockroach-2 -- systemctl start cockroach")


        # Kill KC1
        os.system("kubectl exec -it keycloak-0 -- systemctl stop keycloak")
        # Ensure Infinityspan cache of KC0 node is empty
        os.system("kubectl exec -it keycloak-1 -- systemctl restart keycloak")


        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["master_realm"]["username"]
        idp_password = settings["idp"]["master_realm"]["password"]
        idp_client_id = settings["idp"]["master_realm"]["client_id"]

        idp_realm_id = settings["idp"]["master_realm"]["name"]

        filename = settings["idp"]["test_realm_ha"]["json_file"]
        realm_to_create = settings["idp"]["test_realm_ha"]["name"]

        # Build token for connection to Keycloak
        s = Session()

        access_token_data = {
            "client_id": idp_client_id,
            "username": idp_username,
            "password": idp_password,
            "grant_type": "password"
        }

        req.wait_online(s, idp_scheme, idp_ip, idp_port, 60)

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

        # Create new realm (target will be KC0 )
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

        # Restart KC0
        os.system("kubectl exec -it keycloak-0 -- systemctl start keycloak")

        # Kill KC1 (wait a bit to ensure cache is propagated to KC0)
        time.sleep(5)
        os.system("kubectl exec -it keycloak-1 -- systemctl stop keycloak")
        time.sleep(5)

        req.wait_online(s, idp_scheme, idp_ip, idp_port, 60)


        # Check the session token is propagated -> info is coming from cache
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
        assert response.status_code == 204


        #Clean state
        os.system("kubectl exec -it keycloak-1 -- systemctl start keycloak")

        os.system("kubectl exec -it cockroach-0 -- systemctl start monit")
        os.system("kubectl exec -it cockroach-1 -- systemctl start monit")
        os.system("kubectl exec -it cockroach-2 -- systemctl start monit")

        os.system("kubectl exec -it keycloak-0 -- systemctl start monit")
        os.system("kubectl exec -it keycloak-1 -- systemctl start monit")