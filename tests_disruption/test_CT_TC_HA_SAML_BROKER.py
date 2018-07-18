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



    # After first round trip, kill all DB nodes, scenario still ok
    def test_CT_TC_HA_DB_SAML_BROKER_ACCESS_CONTROL_RBAC_OK_SP_initiated(self, settings):
        """
        Scenario: User logs in to SP1 where he has the appropriate role.
        Same user tries to log in to SP2, SP that he is authorized to access. He should
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
        sp2_message = sp["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp_external"]["test_realm"]["username"]
        idp_password = settings["idp_external"]["test_realm"]["password"]

        idp2_ip = settings["idp_external"]["ip"]
        idp2_port = settings["idp_external"]["port"]
        idp2_scheme = settings["idp_external"]["http_scheme"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # We check that test works for both types of identity provider
        idp_brokers = [settings["idp"]["saml_broker"], settings["idp"]["wsfed_broker"]]

        for idp_broker in idp_brokers:

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

            # In the login page we can choose to login with the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')

            div = soup.find("div", {"id": "kc-social-providers"})

            assert div is not None

            # we can have several idp external; choose the one needed for the test
            all_li = div.find_all('li')
            for li in all_li:
                if li.span.text == idp_broker:
                    external_idp_url = "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) + \
                                       li.a[
                                           'href']

            assert external_idp_url is not None

            # Select to login with the external IDP
            req_choose_external_idp = Request(
                method='GET',
                url="{url}".format(url=external_idp_url),
                headers=header,
                cookies=keycloak_cookie
            )

            prepared_request = req_choose_external_idp.prepare()

            log_request(logger, req_choose_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            # get the HTTP binding response with the url to the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            params = {}
            for input in inputs:
                params[input.get('name')] = input.get('value')

            header_redirect_external_idp = {
                **header,
                'Host': "{ip}:{port}".format(ip=idp2_ip, port=idp2_port),
                'Referer': "{ip}:{port}".format(ip=idp_ip, port=idp_port)
            }

            # Redirect to external IDP
            if idp_broker == "cloudtrust_saml":
                req_redirect_external_idp = Request(
                    method=method_form,
                    url="{url}".format(url=url_form),
                    data=params,
                    headers=header_redirect_external_idp
                )
            else:
                req_redirect_external_idp = Request(
                    method=method_form,
                    url="{url}".format(url=url_form),
                    params=params,
                    headers=header_redirect_external_idp
                )

            # url_parts = list(urlparse.urlparse(url_form))
            # query = dict(urlparse.parse_qsl(url_parts[4]))
            # query.update(params)
            # url_parts[4] = urlencode(query)
            # referer_url = urlparse.urlunparse(url_parts)
            referer_url = url_form

            prepared_request = req_redirect_external_idp.prepare()

            log_request(logger, req_redirect_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            # if we have an identity provider saml, we do an extra redirect
            if idp_broker == "cloudtrust_saml":
                redirect_url = response.headers['Location']
                keycloak_cookie_ext = response.cookies
                response = req.redirect_to_idp(logger, s, redirect_url, header, keycloak_cookie_ext)
            else:
                keycloak_cookie_ext = response.cookies

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

            credentials_data = {}
            credentials_data["username"] = idp_username
            credentials_data["password"] = idp_password

            # Authenticate to the external IDP
            response = req.send_credentials_to_idp(logger, s, header, idp2_ip, idp2_port, referer_url, url_form,
                                                   credentials_data, {**session_cookie, **keycloak_cookie_ext},
                                                   method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            keycloak_cookie2 = response.cookies

            # get the HTTP binding response with the url to the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            req_token_from_external_idp = Request(
                method=method_form,
                url="{url}".format(url=url_form),
                data=token,
                cookies=keycloak_cookie,
                headers=header
            )

            prepared_request = req_token_from_external_idp.prepare()

            log_request(logger, req_token_from_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            keycloak_cookie3 = response.cookies

            logger.debug(response.status_code)

            # Get the token (SAML response) from the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            # Access SP with the token
            (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                             idp_ip, idp_port, method_form, url_form, token,
                                                             session_cookie,
                                                             keycloak_cookie2)

            assert response.status_code == HTTPStatus.OK

            # assert that we are logged in
            assert re.search(sp_message, response.text) is not None

            # User is logged in on SP1

            # TODO
            # Kill all DBs

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
                                           {**session_cookie2, **keycloak_cookie3})

            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            # Get the token (SAML response) from the identity provider
            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            (response, sp2_cookie) = req.access_sp_with_token(logger, s, header, sp2_ip, sp2_port, sp2_scheme,
                                                              idp_scheme,
                                                              idp_ip,
                                                              idp_port, method_form, url_form, token, session_cookie,
                                                              session_cookie2)

            assert response.status_code == HTTPStatus.OK

        assert re.search(sp2_message, response.text) is not None

    def test_CT_TC_HA_IF_SAML_BROKER_ACCESS_CONTROL_RBAC_OK_SP_initiated(self, settings):
        """
        Scenario: User logs in to SP1 where he has the appropriate role.
        Same user tries to log in to SP2, SP that he is authorized to access. He should
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
        sp2_message = sp["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp_external"]["test_realm"]["username"]
        idp_password = settings["idp_external"]["test_realm"]["password"]

        idp2_ip = settings["idp_external"]["ip"]
        idp2_port = settings["idp_external"]["port"]
        idp2_scheme = settings["idp_external"]["http_scheme"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # We check that test works for both types of identity provider
        idp_brokers = [settings["idp"]["saml_broker"], settings["idp"]["wsfed_broker"]]

        for idp_broker in idp_brokers:

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

            # In the login page we can choose to login with the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')

            div = soup.find("div", {"id": "kc-social-providers"})

            assert div is not None

            # we can have several idp external; choose the one needed for the test
            all_li = div.find_all('li')
            for li in all_li:
                if li.span.text == idp_broker:
                    external_idp_url = "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) + \
                                       li.a[
                                           'href']

            assert external_idp_url is not None

            # Select to login with the external IDP
            req_choose_external_idp = Request(
                method='GET',
                url="{url}".format(url=external_idp_url),
                headers=header,
                cookies=keycloak_cookie
            )

            prepared_request = req_choose_external_idp.prepare()

            log_request(logger, req_choose_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            # get the HTTP binding response with the url to the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            params = {}
            for input in inputs:
                params[input.get('name')] = input.get('value')

            header_redirect_external_idp = {
                **header,
                'Host': "{ip}:{port}".format(ip=idp2_ip, port=idp2_port),
                'Referer': "{ip}:{port}".format(ip=idp_ip, port=idp_port)
            }

            # Redirect to external IDP
            if idp_broker == "cloudtrust_saml":
                req_redirect_external_idp = Request(
                    method=method_form,
                    url="{url}".format(url=url_form),
                    data=params,
                    headers=header_redirect_external_idp
                )
            else:
                req_redirect_external_idp = Request(
                    method=method_form,
                    url="{url}".format(url=url_form),
                    params=params,
                    headers=header_redirect_external_idp
                )

            # url_parts = list(urlparse.urlparse(url_form))
            # query = dict(urlparse.parse_qsl(url_parts[4]))
            # query.update(params)
            # url_parts[4] = urlencode(query)
            # referer_url = urlparse.urlunparse(url_parts)
            referer_url = url_form

            prepared_request = req_redirect_external_idp.prepare()

            log_request(logger, req_redirect_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            # if we have an identity provider saml, we do an extra redirect
            if idp_broker == "cloudtrust_saml":
                redirect_url = response.headers['Location']
                keycloak_cookie_ext = response.cookies
                response = req.redirect_to_idp(logger, s, redirect_url, header, keycloak_cookie_ext)
            else:
                keycloak_cookie_ext = response.cookies

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

            credentials_data = {}
            credentials_data["username"] = idp_username
            credentials_data["password"] = idp_password

            # Authenticate to the external IDP
            response = req.send_credentials_to_idp(logger, s, header, idp2_ip, idp2_port, referer_url, url_form,
                                                   credentials_data, {**session_cookie, **keycloak_cookie_ext},
                                                   method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            keycloak_cookie2 = response.cookies

            # get the HTTP binding response with the url to the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            req_token_from_external_idp = Request(
                method=method_form,
                url="{url}".format(url=url_form),
                data=token,
                cookies=keycloak_cookie,
                headers=header
            )

            prepared_request = req_token_from_external_idp.prepare()

            log_request(logger, req_token_from_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            keycloak_cookie3 = response.cookies

            logger.debug(response.status_code)

            # Get the token (SAML response) from the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            # Access SP with the token
            (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                             idp_ip, idp_port, method_form, url_form, token,
                                                             session_cookie,
                                                             keycloak_cookie2)

            assert response.status_code == HTTPStatus.OK

            # assert that we are logged in
            assert re.search(sp_message, response.text) is not None

            # User is logged in on SP1

            # TODO

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
                                           {**session_cookie2, **keycloak_cookie3})

            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            # Get the token (SAML response) from the identity provider
            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            (response, sp2_cookie) = req.access_sp_with_token(logger, s, header, sp2_ip, sp2_port, sp2_scheme,
                                                              idp_scheme,
                                                              idp_ip,
                                                              idp_port, method_form, url_form, token, session_cookie,
                                                              session_cookie2)

            assert response.status_code == HTTPStatus.OK

        assert re.search(sp2_message, response.text) is not None


