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

import re
import logging
import pytest
import time
import datetime

from sh import docker

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

    def test_is_systemd_running_keycloak(self, test_settings):
        """
        Test if keycloak is currently running under systemd management
        :return:
        """

        # Settings
        path_to_run_from = '/root'
        check_keycloak_status = ("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/keycloak_2eservice",
                                 "org.freedesktop.systemd1.Unit", "ActiveState")

        docker_container_name = test_settings['keycloak_container']['container_name']
        print(docker_container_name)
        # Challange value
        systemctl_keycloak_validation = "active"

        # Test
        docker_exec_busctl_get_ActiveState = docker.bake(
            "exec",
            '-i',
            docker_container_name,
            check_keycloak_status,
            _iter=True
        )

        logger.debug(docker_exec_busctl_get_ActiveState)

        state = docker_exec_busctl_get_ActiveState()

        logger.debug(state)

        assert re.search(
            systemctl_keycloak_validation,
            state.stdout.decode("utf-8")
        ) is not None

    def test_systemd_running_monit(self, test_settings):
        """
        Test to check if systemd is running monit.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        command_monit = (
            "busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/monit_2eservice",
            "org.freedesktop.systemd1.Unit", "ActiveState")
        active_status = '"active"'

        # docker exec -it busctl get-property
        check_service = docker.bake("exec", "-i", container_name, command_monit)
        logger.debug(check_service)

        # check the return value
        monit_status = check_service().stdout.decode("utf-8")
        logger.debug(monit_status)

        status = re.search(active_status, monit_status)
        assert status is not None

    def test_systemd_running_keycloak_bridge(self, test_settings):
        """
        Test to check if systemd is running keycloak bridge.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        command_keycloak_bridge = (
            "busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/keycloak_5fbridge_2eservice",
            "org.freedesktop.systemd1.Unit", "ActiveState")
        active_status = '"active"'

        # docker exec -it busctl get-property
        check_service = docker.bake("exec", "-i", container_name, command_keycloak_bridge)
        logger.debug(check_service)

        # check the return value
        keycloak_bridge_status = check_service().stdout.decode("utf-8")
        logger.debug(keycloak_bridge_status)

        status = re.search(active_status, keycloak_bridge_status)
        assert status is not None

    def test_systemd_running_nginx(self, test_settings):
        """
        Test to check if systemd is running nginx.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        command_nginx = (
            "busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/nginx_2eservice",
            "org.freedesktop.systemd1.Unit", "ActiveState")
        active_status = '"active"'

        # docker exec -it busctl get-property
        check_service = docker.bake("exec", "-i", container_name, command_nginx)
        logger.debug(check_service)

        # check the return value
        nginx_status = check_service().stdout.decode("utf-8")
        logger.debug(nginx_status)

        status = re.search(active_status, nginx_status)
        assert status is not None

    def test_systemd_running_agent(self, test_settings):
        """
        Test to check if systemd is running agent jaeger.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        command_agent = (
            "busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/agent_2eservice",
            "org.freedesktop.systemd1.Unit", "ActiveState")
        active_status = '"active"'

        # docker exec -it busctl get-property
        check_service = docker.bake("exec", "-i", container_name, command_agent)
        logger.debug(check_service)

        # check the return value
        agent_status = check_service().stdout.decode("utf-8")
        logger.debug(agent_status)

        status = re.search(active_status, agent_status)
        assert status is not None

    def test_container_running(self, test_settings):
        """
        Test to check if the container is running.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        running_status = 'running'
        container_name = test_settings['keycloak_container']['container_name']

        # docker inspect --format='{{.State.Status}} container
        check_status = docker.bake("inspect", "--format='{{.State.Status}}'", container_name)
        logger.debug(check_status)

        status = re.search(running_status, check_status().stdout.decode("utf-8"))
        assert status is not None

    def test_monit_restarts_stopped_services(self, test_settings):
        """
        Test to check if monit restarts a stopped service of the container.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        services = test_settings['keycloak_container']['services']

        # logger.info("The following services are tested: ")
        # for service in services:
        #     logger.info(service['name'])

        for service in services:
            service_name = service['name']
            max_timeout = service['timeout']

            stop_service = docker.bake("exec", "-i", container_name, "systemctl", "stop", service_name)
            logger.debug(stop_service)

            stop_service()

            tic_tac = 0
            service_is_up = False

            while (tic_tac < max_timeout) and (service_is_up == False):
                # check if monit started the service
                time.sleep(1)

                check_service = docker.bake("exec", "-i", container_name, "systemctl", "status", service_name)
                logger.info(
                    "Check to see if {service} started after {time} seconds".format(service=service_name, time=tic_tac))
                logger.debug(check_service)

                try:
                    service_status = check_service().exit_code
                    logger.debug(service_status)

                    if (service_status == 0):
                        service_is_up = True
                        logger.info("{service} is running".format(service=service_name))

                except Exception as e:
                    tic_tac = tic_tac + 1

            assert service_is_up == True

    def test_monit_restarts_killed_services(self, test_settings):
        """
        Test to check if monit restarts a killed service of the container.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        services = test_settings['keycloak_container']['services']

        for service in services:
            service_name = service['name']
            max_timeout = service['timeout']

            stop_service = docker.bake("exec", "-i", container_name, "systemctl", "kill", service_name)
            logger.debug(stop_service)

            stop_service()

            tic_tac = 0
            service_is_up = False

            while (tic_tac < max_timeout) and (service_is_up == False):
                # check if monit started the service
                time.sleep(1)

                check_service = docker.bake("exec", "-i", container_name, "systemctl", "status", service_name)
                logger.info(
                    "Check to see if {service} started after {time} seconds".format(service=service_name, time=tic_tac))
                logger.debug(check_service)

                try:
                    service_status = check_service().exit_code
                    logger.debug(service_status)

                    if (service_status == 0):
                        service_is_up = True
                        logger.info("{service} is running".format(service=service_name))

                except Exception as e:
                    tic_tac = tic_tac + 1

            assert service_is_up == True

    def test_no_error_monit_log(self, test_settings):
        """
        Test to check that when running the container systemd starts all the services of the container and there is no
        error in the monit logs.
        As keycloak takes time to start and keycloak bridge is dependent on it, we check if there is no error in the
        monit logs after the time keycloak started (and not since the container started).
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']

        # message in syslog when there are no errors
        no_error_status = "No entries"

        # check the time when the keycloak service has started
        service_name = "keycloak"
        keycloak_is_running = False

        while not keycloak_is_running:

            check_service = docker.bake("exec", "-i", container_name, "systemctl", "status", service_name)
            logger.info( "Check to see if {service} started".format(service=service_name))
            logger.debug(check_service)

            try:
                service_status = check_service().exit_code
                logger.debug(service_status)

                if service_status == 0:
                    keycloak_is_running = True
                    logger.info("{service} is running".format(service=service_name))
                    keycloak_starting_time = datetime.datetime.now()

            except Exception as e:
                pass

        # check in journalctl if there are any errors since the keycloak service started
        get_monit_log = docker.bake("exec", container_name, "journalctl", "-u", "monit", "--since", keycloak_starting_time,
                                    "-p", "err", "-b")
        logger.debug(get_monit_log)

        monit_log = get_monit_log().stdout.decode("utf-8")
        logger.debug(monit_log)

        assert re.search(no_error_status, monit_log) is not None

    def test_systemd_restarts_monit(self, test_settings):
        """
        Test to check that if monit is down then systemd will restart it.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """

        container_name = test_settings['keycloak_container']['container_name']
        service_name = "monit"
        max_timeout = test_settings['keycloak_container']['monit_timeout']

        # kill monit
        stop_service = docker.bake("exec", "-i", container_name, "systemctl", "kill", service_name)
        logger.debug(stop_service)

        stop_service()

        tic_tac = 0
        monit_is_up = False

        while (tic_tac < max_timeout) and (not monit_is_up):
            # check if systemd starts monit

            time.sleep(1)

            check_service = docker.bake("exec", "-i", container_name, "systemctl", "status", service_name)
            logger.info("Check to see if {service} started after {time} seconds".format(service=service_name, time=tic_tac))
            logger.debug(check_service)

            try:
                monit_status = check_service().exit_code
                if (monit_status == 0):
                    monit_is_up = True
                    logger.info("{service} is running".format(service=service_name))

            except Exception as e:
                tic_tac = tic_tac + 1
        assert monit_is_up == True

    # def test_container_exposed_ports(self, test_settings):
    #     """
    #     Test to check if the correct ports are exposed.
    #     :param test_settings: settings of the container, e.g. container name, service name, etc.
    #     :return:
    #     """
    #
    #     container_name = test_settings['keycloak_container']['container_name']
    #     ports = test_settings['keycloak_container']['ports']
    #
    #     check_ports = docker.bake("inspect", "--format='{{.Config.ExposedPorts}}'", container_name)
    #     logger.debug(check_ports)
    #     exposed_ports = check_ports().stdout.decode("utf-8")
    #
    #     for port in ports:
    #         assert re.search(port, exposed_ports) is not None
    #
    def test_monit_always_restarts(self, test_settings):
        """
        Test to check if monit is configured to always restart.
        :param test_settings: settings of the container, e.g. container name, service name, etc.
        :return:
        """
        container_name = test_settings['keycloak_container']['container_name']

        command_monit = (
            "busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/monit_2eservice",
            "org.freedesktop.systemd1.Service", "Restart")
        restart_status = '"always"'

        # docker exec -it busctl get-property
        check_monit_restart = docker.bake("exec", "-i", container_name, command_monit)
        logger.debug(check_monit_restart)

        # check the return value
        monit_restart = check_monit_restart().stdout.decode("utf-8")
        logger.debug(monit_restart)

        status = re.search(restart_status, monit_restart)
        assert status is not None
