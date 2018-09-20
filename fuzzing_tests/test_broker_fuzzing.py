#!/usr/bin/env python3

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
import re
import random
import time
import calendar
import os
import sys
import fcntl
import json

import helpers.fuzzing as fuzz
import helpers.requests as req
from helpers.logging import log_request

import urllib.parse as url
from bs4 import BeautifulSoup
from requests import Request, Session
from http import HTTPStatus
from logging.handlers import TimedRotatingFileHandler

# Turn off O_NONBLOCK (to avoid BlockingIOError)
# import os,sys,fcntl
# flags = fcntl.fcntl(sys.stdout, fcntl.F_GETFL)
# fcntl.fcntl(sys.stdout, fcntl.F_SETFL, flags&~os.O_NONBLOCK)


flags = fcntl.fcntl(sys.stdout, fcntl.F_GETFL)
# print("Checking the flag of stdout")
# print(flags&os.O_NONBLOCK)

author = "Sonia Bogos"
maintainer = "Sonia Bogos"
version = "0.0.1"

# Logging
# Default to Debug, here it is set to INFO to avoid logging all the login, logout requests
##################

filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'broker_fuzzing.log')
logger = logging.getLogger('keycloak-tool.fuzzing_tests.Test_broker_fuzzing')
logger.setLevel(logging.INFO)
# Use TimedRotatingFileHandler to have rotation of disk log files
filelog = logging.handlers.TimedRotatingFileHandler(filename,
                                                    when="h",
                                                    interval=6,
                                                    backupCount=10)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', '%m/%d/%Y %I:%M:%S %p')
filelog.setFormatter(formatter)
logger.addHandler(filelog)


@pytest.mark.usefixtures('settings', 'import_realm', 'import_realm_external')
class Test_broker_fuzzing():
    """
    Class that contains fuzzing tests on the broker login scenario (CT-TC-WS-FED-BROKER-SIMPLE)
    where we fuzz the parameters of the request from the external IDP to the broker
    """

    def test_security_broker_fuzzing(self, settings):
        """
        This test respects the following use-case:
        - we simulate a login using an external IDP; in this case the external IDP generates a token that is transmitted
        to the broker IDP and used further to allow access to the service provider for the correctly authenticated user
        - for the tests, we fuzz one or more of the parameters 'wa', 'wtrealm', 'wresult' or 'wctx' from the token sent from the
        external IDP to the broker IDP
        - we check what is the return code of the broker IDP when sending the fuzzed token
        - afterwards, we check if Keycloak is still working properly by doing a login and a logout
        Repeat the previous steps an unlimited number of times
        - as output we expect to receive 400 and 414 from Keycloak and for the login and logout to be done
        successfully
        :param settings:
        :return:
        """

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]
        idp_test_realm = settings["idp"]["test_realm"]["name"]
        idp_form_id = settings["idp"]["login_form_update"]
        idp_broker = settings["idp"]["wsfed_broker"]

        # a login WSFED query
        query = "wa=wsignin1.0&" \
                "wreply=http%3A%2F%2F127.0.0.1%3A7000%2Fj_spring_fediz_security_check&" \
                "wtrealm=sp_wsfed1&" \
                "wct=2018-07-10T14%3A43%3A45.921Z&" \
                "wctx=48022b8c-9b80-4446-8487-f94b24439f44"

        initial_redirect_url = "{scheme}://{ip}:{port}/auth/realms/{realm}/protocol/wsfed?{query}".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
            realm=idp_test_realm,
            query=query
        )

        # follow the login flow up to the moment that the external IDP sends the reply (containing the wsfed fields)
        # to the broker
        #for i in range(0,1):
        while True:

            s = Session()

            # Service provider settings
            sp = settings["sps_wsfed"][0]
            sp_ip = sp["ip"]
            sp_port = sp["port"]
            sp_scheme = sp["http_scheme"]
            sp_path = sp["path"]
            sp_message = sp["logged_in_message"]

            # Identity provider settings
            # IDP broker
            idp_ip = settings["idp"]["ip"]
            idp_port = settings["idp"]["port"]
            idp_scheme = settings["idp"]["http_scheme"]
            idp_broker = settings["idp"]["wsfed_broker"]

            idp_client_id = settings["idp"]["master_realm"]["client_id"]
            idp_realm_id = settings["idp"]["master_realm"]["name"]
            idp_realm_test = settings["idp"]["test_realm"]["name"]
            idp_master_username = settings["idp"]["master_realm"]["username"]
            idp_master_password = settings["idp"]["master_realm"]["password"]

            idp_username = settings["idp_external"]["test_realm"]["username"]
            idp_password = settings["idp_external"]["test_realm"]["password"]

            # IDP external
            idp2_ip = settings["idp_external"]["ip"]
            idp2_port = settings["idp_external"]["port"]
            idp2_scheme = settings["idp_external"]["http_scheme"]
            idp2_client_id = settings["idp_external"]["master_realm"]["client_id"]
            idp2_realm_id = settings["idp_external"]["master_realm"]["name"]
            idp2_realm_test = settings["idp_external"]["test_realm"]["name"]
            idp2_master_username = settings["idp_external"]["master_realm"]["username"]
            idp2_master_password = settings["idp_external"]["master_realm"]["password"]

            keycloak_login_form_id = settings["idp"]["login_form_id"]


            # Common header for all the requests
            header = req.get_header()

            response = req.redirect_to_idp(logger, s, initial_redirect_url, header, None)
            keycloak_cookie = response.cookies

            if response.status_code == HTTPStatus.UNAUTHORIZED and response.headers['WWW-Authenticate'] == 'Negotiate':
                response = req.kerberos_form_fallback(logger, s, response, header, {**keycloak_cookie})

            # In the login page we can choose to login with the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')

            div = soup.find("div", {"id": "kc-social-providers"})

            assert div is not None

            # we can have several idp external; choose the one needed for the test
            all_li = div.find_all('li')
            for li in all_li:
                if li.span.text == idp_broker:
                    external_idp_url = "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) + li.a[
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

            req.log_request(logger, req_choose_external_idp)
            response = s.send(prepared_request, allow_redirects=False)
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

            # Redirect to external IDP
            req_redirect_external_idp = Request(
                method=method_form,
                url="{url}".format(url=url_form),
                params=params,
                headers=header
            )

            referer_url = url_form

            prepared_request = req_redirect_external_idp.prepare()

            req.log_request(logger, req_redirect_external_idp)
            response = s.send(prepared_request, allow_redirects=False)
            logger.debug(response.status_code)

            keycloak_cookie2 = response.cookies

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
                                                   credentials_data, {**keycloak_cookie2}, method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            # get the HTTP binding response with the url to the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            try:
                ## we fuzz the values of the token
                params = ['wa', 'wtrealm', 'wresult', 'wctx']
                # choose what parameters are going to be fuzzed
                for i in range(0, len(params)):
                    random.seed(calendar.timegm(time.gmtime()) + random.randint(0, 1000))
                    choice = random.random()
                    if choice > 0.5:  # we fuzz the parameter
                        fuzz_value = fuzz.get_fuzzed_value(logger, token[params[i]])
                        token[params[i]] = fuzz_value
            except Exception as e:
                print("There is a problem with the fuzzer: {e}".format(e=e))
                logger.info("There is a problem with the fuzzer: {e}".format(e=e))

            logger.info("Fuzzed token sent to the broker is {t}".format(t=token))

            req_token_from_external_idp = Request(
                method=method_form,
                url="{url}".format(url=url_form),
                data=token,
                cookies=keycloak_cookie,
                headers=header
            )

            prepared_request = req_token_from_external_idp.prepare()

            req.log_request(logger, req_token_from_external_idp)
            response = s.send(prepared_request, allow_redirects=False)

            # log what status code we get from the broker
            logger.info(response.status_code)

            # check that Keycloak is up there running and able to answer to requests
            # run the wsfed login test
            s = Session()

            response = req.access_sp_ws_fed(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path)

            session_cookie = response.cookies

            redirect_url = response.headers['Location']

            header_redirect_idp = {
                **header,
                'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
                'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
            }

            response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, session_cookie)

            keycloak_cookie = response.cookies

            if response.status_code == HTTPStatus.UNAUTHORIZED and response.headers['WWW-Authenticate'] == 'Negotiate':
                response = req.kerberos_form_fallback(logger, s, response, header,
                                                      {**keycloak_cookie, **session_cookie})

            # In the login page we can choose to login with the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')

            div = soup.find("div", {"id": "kc-social-providers"})

            assert div is not None

            # we can have several idp external; choose the one needed for the test
            all_li = div.find_all('li')
            for li in all_li:
                if li.span.text == idp_broker:
                    external_idp_url = "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) + li.a[
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

            referer_url = url_form

            prepared_request = req_redirect_external_idp.prepare()

            log_request(logger, req_redirect_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            # if we have an identity provider saml, we do an extra redirect
            if idp_broker == "cloudtrust_saml":
                redirect_url = response.headers['Location']
                keycloak_cookie2 = response.cookies
                response = req.redirect_to_idp(logger, s, redirect_url, header, keycloak_cookie2)
            else:
                keycloak_cookie2 = response.cookies

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
                                                   credentials_data, {**keycloak_cookie2, **session_cookie}, method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

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

            logger.debug(response.status_code)

            if response.status_code == HTTPStatus.FOUND:
                new_cookie = response.cookies
                redirect_url = response.headers['Location']
                response = req.redirect_to_idp(logger, s, redirect_url, header, {**keycloak_cookie, **new_cookie})
                response = req.broker_fill_in_form(logger, s, response, header, keycloak_cookie, new_cookie, idp_broker,
                                                   idp_form_id)

            # Get the token from the broker IDP
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
                                                             idp_ip, idp_port, method_form, url_form, token, session_cookie,
                                                             keycloak_cookie2)

            assert response.status_code == HTTPStatus.OK

            # assert that we are logged in
            assert re.search(sp_message, response.text) is not None
            logger.info("Login returned a {code} status code".format(code=response.status_code))

            # cleanup: remove the open sessions of the test user from the broker IDP and external IDP


            # remove the sessions from broker IDP
            # first, obtain the id of the user
            user_repr = req.get_user(s, logger, idp_ip, idp_port, idp_scheme, idp_master_username, idp_master_password, idp_client_id,
                                 idp_realm_id,
                                 idp_realm_test, idp_username)

            user_id = json.loads(user_repr)[0]['id']

            # remove the open sessions
            status_code = req.remove_user_sessions(s, logger, idp_ip, idp_port, idp_scheme, idp_master_username, idp_master_password,
                                               idp_client_id, idp_realm_id,
                                               idp_realm_test, user_id)

            assert status_code == HTTPStatus.NO_CONTENT

            # remove the sessions from the external IDP
            # first, obtain the id of the user
            user_repr = req.get_user(s, logger, idp2_ip, idp2_port, idp2_scheme, idp2_master_username, idp2_master_password,
                                 idp2_client_id,
                                 idp2_realm_id,
                                 idp2_realm_test, idp_username)

            user_id = json.loads(user_repr)[0]['id']

            # remove the open sessions
            status_code = req.remove_user_sessions(s, logger, idp2_ip, idp2_port, idp2_scheme, idp2_master_username,
                                               idp2_master_password,
                                               idp2_client_id, idp2_realm_id,
                                               idp2_realm_test, user_id)

            assert status_code == HTTPStatus.NO_CONTENT






