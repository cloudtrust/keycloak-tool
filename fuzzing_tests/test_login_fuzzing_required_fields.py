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
import re
import random
import time
import calendar
import os
import sys
import fcntl

import helpers.fuzzing as fuzz
import helpers.requests as req

import urllib.parse as url
from bs4 import BeautifulSoup
from requests import Request, Session
from http import HTTPStatus
from logging.handlers import TimedRotatingFileHandler

# Turn off O_NONBLOCK (to avoid BlockingIOError)
#import os,sys,fcntl
#flags = fcntl.fcntl(sys.stdout, fcntl.F_GETFL)
#fcntl.fcntl(sys.stdout, fcntl.F_SETFL, flags&~os.O_NONBLOCK)


flags = fcntl.fcntl(sys.stdout, fcntl.F_GETFL)
#print("Checking the flag of stdout")
#print(flags&os.O_NONBLOCK)

author = "Sonia Bogos"
maintainer = "Sonia Bogos"
version = "0.0.1"

# Logging
# Default to Debug, here it is set to INFO to avoid logging all the login, logout requests
##################

filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'login_fuzz_required_parameter.log')
logger = logging.getLogger('keycloak-tool.fuzzing_tests.Test_login_fuzzing_require_fields')
logger.setLevel(logging.INFO)
# Use TimedRotatingFileHandler to have rotation of disk log files
filelog = logging.handlers.TimedRotatingFileHandler(filename,
                                    when="h",
                                    interval=6,
                                    backupCount=10)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s','%m/%d/%Y %I:%M:%S %p')
filelog.setFormatter(formatter)
logger.addHandler(filelog)


@pytest.mark.usefixtures('settings', 'import_realm')
class Test_fuzzing_wsfed_parameters():
    """

    """
    def test_security_fuzzing_wa_wsfed_parameter(self, settings):
        """
        :param settings:
        :return:
        """

        s = Session()

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]
        idp_test_realm = settings["idp"]["test_realm"]["name"]

        # Common header for all the requests
        header = req.get_header()

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

        while True:
            # split the url in parts
            url_parts = list(url.urlparse(initial_redirect_url))

            # fetch the query part with the wsfed parameters
            query = dict(url.parse_qsl(url_parts[4]))

            # choose what parameters are going to be fuzzed
            random.seed(calendar.timegm(time.gmtime())+random.randint(0,1000))
            choice = random.randint(0, 2)

            # according to the choice, replace the wsfed parameters with their fuzzed versions
            if choice == 0:
                # fuzz both parameters: wa and wtrealm
                query['wa'] = fuzz.get_fuzzed_value(logger, query['wa'])
                query['wtrealm'] = fuzz.get_fuzzed_value(logger, query['wtrealm'])
            if choice == 1:
                # fuzz the wa parameter
                query['wa'] = fuzz.get_fuzzed_value(logger, query['wa'])
            if choice == 2:
                # fuzz the wtrealm parameter
                query['wtrealm'] = fuzz.get_fuzzed_value(logger, query['wtrealm'])


            # recreate the url
            url_parts[4] = url.urlencode(query)
            fuzzed_redirect_url = url.urlunparse(url_parts)

            if fuzzed_redirect_url != initial_redirect_url:
                logger.info("Sending a wsfed login request with the fuzzed url {url}".format(url=fuzzed_redirect_url))
                req_get_keycloak = Request(
                    method='GET',
                    url="{url}".format(url=fuzzed_redirect_url),
                    headers=header
                )

                prepared_request = req_get_keycloak.prepare()
                req.log_request(logger, req_get_keycloak)
                response = s.send(prepared_request, verify=False)
                logger.info(response.status_code)

                #assert response.status_code == HTTPStatus.BAD_REQUEST

                # check that Keycloak is up there running and able to answer to requests
                # run the wsfed login test
                s = Session()

                # Service provider settings
                sp = settings["sps_wsfed"][0]
                sp_ip = sp["ip"]
                sp_port = sp["port"]
                sp_scheme = sp["http_scheme"]
                sp_path = sp["path"]
                sp_message = sp["logged_in_message"]
                sp_logout_path = sp["logout_path"]
                sp_logout_message = sp["logged_out_message"]

                # Identity provider settings
                idp_ip = settings["idp"]["ip"]
                idp_port = settings["idp"]["port"]
                idp_scheme = settings["idp"]["http_scheme"]

                idp_username = settings["idp"]["test_realm"]["username"]
                idp_password = settings["idp"]["test_realm"]["password"]

                keycloak_login_form_id = settings["idp"]["login_form_id"]

                # Common header for all the requests
                header = req.get_header()

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

                if response.status_code == HTTPStatus.UNAUTHORIZED and response.headers[
                    'WWW-Authenticate'] == 'Negotiate':
                    response = req.kerberos_form_fallback(logger, s, response, header,
                                                          {**keycloak_cookie, **session_cookie})

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

                # Get the token from the identity provider
                token = {}
                for input in inputs:
                    token[input.get('name')] = input.get('value')

                (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme,
                                                                 idp_scheme, idp_ip,
                                                                 idp_port, method_form, url_form, token,
                                                                 session_cookie,
                                                                 keycloak_cookie_2, )

                assert response.status_code == HTTPStatus.OK
                logger.info("Login returned a {code} status code".format(code=response.status_code))

                # assert that we are logged in
                assert re.search(sp_message, response.text) is not None

                # run the wsfed logout test
                
                # Access to the SP logout page
                header_sp_logout_page = {
                    **header,
                    'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
                    'Referer': "{scheme}://{ip}:{port}".format(scheme=sp_scheme, ip=sp_ip, port=sp_port)
                }

                req_get_sp_logout_page = Request(
                    method='GET',
                    url="{scheme}://{ip}:{port}/{path}".format(
                        scheme=sp_scheme,
                        port=sp_port,
                        ip=sp_ip,
                        path=sp_logout_path
                    ),
                    headers=header_sp_logout_page,
                    cookies=sp_cookie
                )

                prepared_request = req_get_sp_logout_page.prepare()

                req.log_request(logger, req_get_sp_logout_page)

                response = s.send(prepared_request, verify=False, allow_redirects=False)

                logger.debug(response.status_code)

                redirect_url = response.headers['Location']

                req_sp_logout_redirect = Request(
                    method='GET',
                    url=redirect_url,
                    headers=header_sp_logout_page,
                    cookies={**sp_cookie}
                )

                prepared_request = req_sp_logout_redirect.prepare()

                req.log_request(logger, req_sp_logout_redirect)

                response = s.send(prepared_request, verify=False, allow_redirects=False)

                logger.debug(response.status_code)

                redirect_url = response.headers['Location']

                response = req.redirect_to_idp(logger, s, redirect_url, header, {**sp_cookie, **keycloak_cookie_2})

                assert response.status_code == HTTPStatus.OK

                soup = BeautifulSoup(response.content, 'html.parser')

                form = soup.body.form
                url_form = form.get('action')
                method_form = form.get('method')
                inputs = form.find_all('input')

                # Send the token
                token = {}
                for input in inputs:
                    token[input.get('name')] = input.get('value')

                (response, cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                              idp_ip, idp_port,
                                                              method_form, url_form, token, sp_cookie, sp_cookie, )

                assert response.status_code == HTTPStatus.OK

                # assert we are logged out
                assert re.search(sp_logout_message, response.text) is not None
                logger.info("Logout returned a {code} status code".format(code=response.status_code))





