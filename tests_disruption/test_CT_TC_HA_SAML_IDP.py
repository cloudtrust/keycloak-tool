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

import re
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
logger = logging.getLogger('keycloak-tool.tests_disruption.test_CT_TC_HA_SAML_IDP')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'import_realm')
class Test_CT_TC_HA_SAML_IDP():
    """
      Class to test the test_CT_TC_SAML_IDP_ACCESS_CONTROL_RBAC_[OK|KO] use case with disruption (Infinityspan or CockroachDB):
      As a end user, switching between applications in a timeframe smaller than the allowed single sign on time span,
      I need the solution to grant me access to applications whose access I am entitled to have without re-authenticating.

      The scenario are copy pasted from original automated tests with minor adaption to simulate disruption.
    """

    # This test expect the following environment :
    #  - 2 Keycloak : KC1, KC2
    #  - 2 CockroachDB : DB1, DB2




    # Kill KC2

        # Execute first round trip

        # I.E:         # User is logged in on SP1
                       #
                       # Attempt to perform login on SP2

        # At this stage we have to do the start/ kill step (line 168-170 in test_CT_TC_SAML_IDP_ACCESS_CONTROL_RBAC_OK)

        # Start KC2
        # Kill KC1

        # Execute second part

    # Test HA scenario (Infinityspan) for SAML IDP scenario
    def test_CT_TC_HA_IF_SAML_IDP_ACCESS_CONTROL_RBAC_OK_SP_initiated(self, settings):
        """
        Scenario:
        Only KC1 is avaialable
        User logs in to SP1 where he has the appropriate role.
        Restart KC2 & Kill KC1
        Same user tries to access to SP2, SP that he is authorized to access. He should
        be able to access SP2 without authenticating again.
        :param settings:
        :return:
        """

        # TODO
        # Kill KC2

        s = Session()

        # Service provider settings
        sp = settings["sps_saml"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Service provider 2 settings
        sp2 = settings["sps_saml"][1]
        sp2_ip = sp2["ip"]
        sp2_port = sp2["port"]
        sp2_scheme = sp2["http_scheme"]
        sp2_path = sp2["path"]
        sp2_message = sp2["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["test_realm"]["username"]
        idp_password = settings["idp"]["test_realm"]["password"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # Perform login to SP1

        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                        idp_ip, idp_port)

        assert response.status_code == HTTPStatus.FOUND

        # store the cookie received from keycloak
        keycloak_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, keycloak_cookie)

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.find("form", {"id": keycloak_login_form_id})

        assert form is not None

        url_form = form.get('action')
        method_form = form.get('method')

        inputs = form.find_all('input')

        input_name = []
        for input in inputs:
            input_name.append(input.get('name'))

        assert "username" in input_name
        assert "password" in input_name

        # Simulate the login to the identity provider by providing the credentials
        credentials_data = {}
        credentials_data["username"] = idp_username
        credentials_data["password"] = idp_password

        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               keycloak_cookie, method_form)

        assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND  #or response.status_code == 303 or response.status_code == 307

        keycloak_cookie_2 = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token (SAML response) from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie_2)

        assert response.status_code == HTTPStatus.OK

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None

        # User is logged in on SP1

        #TODO
        # Start KC2
        # Kill KC1


        # Attempt to perform login on SP2

        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path, idp_ip,
                                                        idp_port)

        session_cookie2 = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, {**session_cookie2, **keycloak_cookie_2})

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token (SAML response) from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp2_cookie) = req.access_sp_with_token(logger, s, header, sp2_ip, sp2_port, sp2_scheme, idp_scheme, idp_ip,
                                                          idp_port, method_form, url_form, token, session_cookie,
                                                          session_cookie2)

        assert response.status_code == HTTPStatus.OK

        assert re.search(sp2_message, response.text) is not None


    def test_CT_TC_HA_IF_SAML_IDP_ACCESS_CONTROL_RBAC_KO_SP_initiated(self, settings):
        """
        Scenario:
        Only KC1 is avaialable
        User logs in to SP1 where he has the appropriate role.
        Restart KC2 & Kill KC1
        Same user tries to log in to SP2, SP that he is not authorized to access. He should receive an
        error message saying he has not the authorization.
        :param settings:
        :return:
        """

        # TODO
        # Kill KC2

        s = Session()

        # Service provider settings
        sp = settings["sps_saml"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Service provider 2 settings
        sp2 = settings["sps_saml"][2]
        sp2_ip = sp2["ip"]
        sp2_port = sp2["port"]
        sp2_scheme = sp2["http_scheme"]
        sp2_path = sp2["path"]
        sp2_message = settings["idp"]["not_authorized_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["test_realm"]["username"]
        idp_password = settings["idp"]["test_realm"]["password"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # Perform login to SP1
        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                        idp_ip, idp_port)

        assert response.status_code == HTTPStatus.FOUND

        # store the cookie received from keycloak
        keycloak_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, keycloak_cookie)

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.find("form", {"id": keycloak_login_form_id})

        assert form is not None

        url_form = form.get('action')
        method_form = form.get('method')

        inputs = form.find_all('input')

        input_name = []
        for input in inputs:
            input_name.append(input.get('name'))

        assert "username" in input_name
        assert "password" in input_name

        # Simulate the login to the identity provider by providing the credentials
        credentials_data = {}
        credentials_data["username"] = idp_username
        credentials_data["password"] = idp_password

        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form,
                                               credentials_data,
                                               keycloak_cookie, method_form)

        assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND  # or response.status_code == 303 or response.status_code == 307

        keycloak_cookie_2 = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token (SAML response) from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                         idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie_2)

        assert response.status_code == HTTPStatus.OK

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None

        # User is logged in on SP1

        # TODO
        # Start KC2
        # Kill KC1


        # Attempt to perform login on SP2

        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path,
                                                        idp_ip,
                                                        idp_port)

        session_cookie2 = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp,
                                       {**session_cookie2, **keycloak_cookie_2})

        # Assert that the client is not authorized to access SP2
        assert response.status_code == HTTPStatus.FORBIDDEN

        assert re.search(sp2_message, response.text) is not None

    def test_CT_TC_HA_DB_SAML_IDP_ACCESS_CONTROL_RBAC_OK_SP_initiated(self, settings):
        """
        Scenario: User logs in to SP1 where he has the appropriate role.
        Kill all DB
        Same user tries to access to SP2, SP that he is authorized to access. He should
        be able to access SP2 without authenticating again.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp = settings["sps_saml"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Service provider 2 settings
        sp2 = settings["sps_saml"][1]
        sp2_ip = sp2["ip"]
        sp2_port = sp2["port"]
        sp2_scheme = sp2["http_scheme"]
        sp2_path = sp2["path"]
        sp2_message = sp2["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["test_realm"]["username"]
        idp_password = settings["idp"]["test_realm"]["password"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # Perform login to SP1

        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                        idp_ip, idp_port)

        assert response.status_code == HTTPStatus.FOUND

        # store the cookie received from keycloak
        keycloak_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, keycloak_cookie)

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.find("form", {"id": keycloak_login_form_id})

        assert form is not None

        url_form = form.get('action')
        method_form = form.get('method')

        inputs = form.find_all('input')

        input_name = []
        for input in inputs:
            input_name.append(input.get('name'))

        assert "username" in input_name
        assert "password" in input_name

        # Simulate the login to the identity provider by providing the credentials
        credentials_data = {}
        credentials_data["username"] = idp_username
        credentials_data["password"] = idp_password

        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form,
                                               credentials_data,
                                               keycloak_cookie, method_form)

        assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND  # or response.status_code == 303 or response.status_code == 307

        keycloak_cookie_2 = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token (SAML response) from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                         idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie_2)

        assert response.status_code == HTTPStatus.OK

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None

        # User is logged in on SP1

        # Attempt to perform login on SP2

        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path,
                                                        idp_ip,
                                                        idp_port)

        session_cookie2 = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp,
                                       {**session_cookie2, **keycloak_cookie_2})

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token (SAML response) from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp2_cookie) = req.access_sp_with_token(logger, s, header, sp2_ip, sp2_port, sp2_scheme, idp_scheme,
                                                          idp_ip,
                                                          idp_port, method_form, url_form, token, session_cookie,
                                                          session_cookie2)

        assert response.status_code == HTTPStatus.OK

        assert re.search(sp2_message, response.text) is not None


    def test_CT_TC_HA_DB_SAML_IDP_ACCESS_CONTROL_RBAC_KO_SP_initiated(self, settings):
        """
        Scenario: User logs in to SP1 where he has the appropriate role.
        Kill all DB
        Same user tries to log in to SP2, SP that he is not authorized to access. He should receive an
        error message saying he has not the authorization.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp = settings["sps_saml"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Service provider 2 settings
        sp2 = settings["sps_saml"][2]
        sp2_ip = sp2["ip"]
        sp2_port = sp2["port"]
        sp2_scheme = sp2["http_scheme"]
        sp2_path = sp2["path"]
        sp2_message = settings["idp"]["not_authorized_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["test_realm"]["username"]
        idp_password = settings["idp"]["test_realm"]["password"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # Perform login to SP1
        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                        idp_ip, idp_port)

        assert response.status_code == HTTPStatus.FOUND

        # store the cookie received from keycloak
        keycloak_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, keycloak_cookie)

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.find("form", {"id": keycloak_login_form_id})

        assert form is not None

        url_form = form.get('action')
        method_form = form.get('method')

        inputs = form.find_all('input')

        input_name = []
        for input in inputs:
            input_name.append(input.get('name'))

        assert "username" in input_name
        assert "password" in input_name

        # Simulate the login to the identity provider by providing the credentials
        credentials_data = {}
        credentials_data["username"] = idp_username
        credentials_data["password"] = idp_password

        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               keycloak_cookie, method_form)

        assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND  #or response.status_code == 303 or response.status_code == 307

        keycloak_cookie_2 = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token (SAML response) from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie_2)

        assert response.status_code == HTTPStatus.OK

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None

        # User is logged in on SP1

        # Attempt to perform login on SP2

        (session_cookie, response) = req.access_sp_saml(logger, s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path, idp_ip,
                                                        idp_port)

        session_cookie2 = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, {**session_cookie2, **keycloak_cookie_2})

        # Assert that the client is not authorized to access SP2
        assert response.status_code == HTTPStatus.FORBIDDEN

        assert re.search(sp2_message, response.text) is not None


