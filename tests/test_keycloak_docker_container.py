#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018:
#     Sebastien Pasche, sebastien.pasche@elca.ch
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

from sh import docker
import re
import logging
import pytest

# Logging
# Default to Debug
##################

logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('keycloak-tool.tests.service_keycloak_bridge')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('test_settings', scope='classe')
class TestKeycloakContainer(object):
    """
    Checking containter structure and build
    """

    def is_systemd_running_keycloak(self, test_settings):
        """
        Test if keycloak is currently running under systemd management
        :return:
        """

        # Settings
        path_to_run_from = '/root'
        check_keycloak_status = """/usr/bin/busctl \
        get-property org.freedesktop.systemd1 \
        /org/freedesktop/systemd1/unit/nginx_2eservice \
        org.freedesktop.systemd1.Unit ActiveState
        """

        docker_container_name = test_settings['keycloak_container']['name']

        # Challange value
        systemctl_keycloak_validation = '''STRING "active";'''

        # Test
        docker_exec_busctl_get_ActiveState = docker.bake(
            "exec",
            ' -ti',
            docker_container_name,
            check_keycloak_status,
            _cwd=path_to_run_from,
            _iter=True
        )

        logger.debug(docker_exec_busctl_get_ActiveState)

        state = docker_exec_busctl_get_ActiveState()

        logger.debug(state)

        return re.search(
            systemctl_keycloak_validation,
            state
        )