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

import json

from helpers.logging import log_request

from bs4 import BeautifulSoup
from requests import Request
from http import HTTPStatus


def access_sp_ws_fed(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path):
    """
    Helper dedicated to access the service provider in order to obtain the
    endpoint of the IDP, where the connection protocol is WSFED
    :param logger:
    :param s: session s
    :param header: header used for the request
    :param sp_ip: service provider ip
    :param sp_port: service provider port
    :param sp_scheme: service provider http scheme
    :param sp_path: service provider path
    :return:
    """
    # Access to the SP
    header_sp_page = {
        **header,
        'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
        'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
    }

    req_get_sp_page = Request(
        method='GET',
        url="{scheme}://{ip}:{port}/{path}".format(
            scheme=sp_scheme,
            port=sp_port,
            ip=sp_ip,
            path=sp_path
        ),
        headers=header_sp_page,
    )

    prepared_request = req_get_sp_page.prepare()

    log_request(logger, req_get_sp_page)

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return response


def access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip, idp_port, method, url, token, session_cookie, keycloak_cookie):
    """
    Helper dedicated to access the service provider endpoint with the token obtained from the identity provider.
    Requests done in this method are dependent of the functionality of the servide provider.
    :param logger:
    :param s: session s
    :param header: header used for the requests
    :param sp_ip: service provider ip
    :param sp_port: service provider port
    :param idp_scheme: identity provider http scheme
    :param idp_ip: identity provider ip
    :param idp_port: identity provider port
    :param method: method used to do the request, e.g. GET, POST
    :param url: url used to make the request
    :param token: token obtained from the identity provider
    :param session_cookie: session cookie
    :param keycloak_cookie: keycloak session cookie
    :return:
    """

    # Perform a callback
    header_callback = {
        **header,
        'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
        'Referer': "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port),
    }

    req_sp_with_token = Request(
        method=method,
        url="{url}".format(url=url),
        data=token,
        cookies=session_cookie,
        headers=header_callback
    )

    prepared_request = req_sp_with_token.prepare()

    log_request(logger, req_sp_with_token)

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    sp_cookie = response.cookies

    url_sp = response.headers['Location']

    if url_sp == "/":
        url_sp = "{scheme}://{ip}:{port}".format(ip=sp_ip, port=sp_port, scheme=sp_scheme)

    header_login_sp = {
        **header,
        'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
        'Referer': "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port),
    }

    req_get_sp_page_final = Request(
        method='GET',
        url="{url}".format(url=url_sp),
        cookies={**session_cookie, **keycloak_cookie, **response.cookies},
        headers=header_login_sp
    )

    prepared_request = req_get_sp_page_final.prepare()

    log_request(logger, req_get_sp_page_final)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response, sp_cookie


def redirect_to_idp(logger, s, redirect_url, header, cookie):
    """
    Helper dedicated to perform the redirect request to the identity provider
    :param logger:
    :param s: session s
    :param redirect_url: redirect url
    :param header: header used for the requests
    :param cookie:
    :return:
    """

    req_get_keycloak = Request(
        method='GET',
        url="{url}".format(url=redirect_url),
        cookies=cookie,
        headers=header
    )

    prepared_request = req_get_keycloak.prepare()

    log_request(logger, req_get_keycloak)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response


def send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data, cookie, method):
    """
    Helper dedicated to send the credentials to the identity provider
    :param logger:
    :param s: session s
    :param header: header used for the requests
    :param idp_ip: identity provider ip
    :param idp_port: identity provider port
    :param redirect_url: referer url
    :param url_form: url used for the request
    :param credentials_data: credentials, e.g. password and username
    :param cookie: keycloak cookie
    :param method: method used to do the request, e.g. GET, POST
    :return:
    """

    header_login_keycloak = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
        'Referer': "{host}".format(host=redirect_url),
    }

    req_login_idp = Request(
        method=method,
        url="{url}".format(url=url_form),
        data=credentials_data,
        cookies=cookie,
        headers=header_login_keycloak
    )
    prepared_request = req_login_idp.prepare()

    log_request(logger, req_login_idp)

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return response


def get_access_token(logger, s, data, idp_scheme, idp_port, idp_ip, realm_id):
    """
    Helper dedicated to obtain the access token for Keycloak
    :param logger:
    :param s: session s
    :param data: payload of the request
    :param idp_scheme: identity provider http scheme
    :param idp_port: identity provider port
    :param idp_ip: identity provider ip
    :param realm_id: id of the realm
    :return:
    """
    req_get_access_token = Request(
        method='POST',
        url="{scheme}://{ip}:{port}/auth/realms/{realm}/protocol/openid-connect/token".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
            realm=realm_id
        ),
        data=data
    )

    prepared_request = req_get_access_token.prepare()

    log_request(logger, req_get_access_token)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    access_token = json.loads(response.text)['access_token']

    return access_token


def get_header():

    header = {
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-US,en;q=0.5",
        'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
        'Connection': "keep-alive",
        'Upgrade-Insecure-Requests': "1",
    }
    return header

def kerberos_form_fallback(logger, s, response, header, cookie):

    soup = BeautifulSoup(response.content, 'html.parser')

    form = soup.find("form")

    url_form = form.get('action')
    method_form = form.get('method')

    inputs = form.find_all('input')

    req_kerberos_fallback = Request(
        method=method_form,
        url="{url}".format(url=url_form),
        headers=header,
        cookies=cookie
    )

    prepared_request = req_kerberos_fallback.prepare()

    log_request(logger, req_kerberos_fallback)

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return response



