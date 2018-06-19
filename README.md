# keycloak-tool
Dev, DevOps and Monitoring tools for RedHat Keycloak

# Setup

```Bash
git clone git@github.com:cloudtrust/keycloak-tool.git
python3.6 -m venv keycloak-tool
cd keycloak-tool
source bin/activate
pip install -r requirements.txt
```

# Infrastructure unit tests

Contains tests related to Keycloak services, container and business functionality

* Service tests to test Keycloak and various component as standalone services
* Container tests to test container build, architecture and plumbing
* Functionnal tests to test end-to-end functionality

## Run test

Test are run from the project root

Run a test file

```Bash
pytest tests/test_service_keycloak.py
======================================================== test session starts ========================================================
platform darwin -- Python 3.6.4, pytest-3.3.2, py-1.5.2, pluggy-0.6.0
rootdir: /Users/XX/Documents/dev/keycloak-tool, inifile:
collected 2 items

tests/test_service_keycloak.py ..                                                                                             [100%]

===================================================== 2 passed in 0.19 seconds ===================================================
```

Run a test file and show debug line

```bash
====================================================== test session starts =======================================================
platform darwin -- Python 3.6.4, pytest-3.3.2, py-1.5.2, pluggy-0.6.0
rootdir: /Users/XX/Documents/dev/keycloak-tool, inifile:
collected 1 item

tests/test_service_keycloak.py 01/25/2018 10:21:15 AM keycloak-tool.tests.service_keycloak DEBUG /Users/spa/Documents/dev/keycloak-tool/tests_config/dev.json
01/25/2018 10:21:15 AM keycloak-tool.tests.service_keycloak DEBUG {
    "keycloak": {
        "hostname": "keycloak.ext.icrc.org",
        "http_scheme": "https",
        "ip": "192.168.16.42"
    },
    "keycloak-bridge": {
        "hostname": "keycloak-bridge.ext.icrc.org",
        "http_scheme": "https",
        "ip": "192.168.16.42"
    }
}
01/25/2018 10:21:15 AM keycloak-tool.tests.service_keycloak DEBUG Disabling https warning
01/25/2018 10:21:15 AM keycloak-tool.tests.service_keycloak DEBUG {
    "headers": {
        "Accept": "text/html; charset = UTF-8",
        "Host": "keycloak.ext.icrc.org"
    },
    "url": "https://192.168.16.42/auth/"
}
01/25/2018 10:21:15 AM urllib3.connectionpool DEBUG Starting new HTTPS connection (1): 192.168.16.42
```
