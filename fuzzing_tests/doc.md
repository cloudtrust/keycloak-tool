
# Fuzzing tests

The fuzzing tests are targeting to see what is the behavior of Keycloak when invalid/random values are used for the WSFED
parameters. 

According to the WSFED specification we need to treat the following parameters: 

"The REQUIRED **wa** field is common to all SignIn messages and is fixed.

The REQUIRED **wtrealm** field MUST contain a URI that the Resource IP/STS and Requestor IP/STS have agreed to use to identify the realm of Resource IP/STS in messages to Requestor IP/STS.

The OPTIONAL **wreply** field specifies the URL to which this message’s response will be POSTed (see Returning Security Tokens).

The OPTIONAL **wctx** field is provided for Resource IP/STS’s use and MUST be returned by Requestor IP/STS unchanged. 

The OPTIONAL **wct** field, if present, MUST contain the current time in UTC using the ISO8601 format (e.g. “2003-04-30T22:47:20Z”).  This field MAY not be available if the requestor is coming via a portal link.  Individual implementations of Requestor IP/STS MAY require this field to be present.

Other options MAY be specified but are not required to be supported."

&nbsp;

We test two scenarios: 
- simple login where we simulate that a service provider is sending an invalid SignIn request:
    1. `login_fuzz_optional_parameter` tests the behavior when the optional parameters `wreply`, `wctx` and/or 
 `wct` are fuzzed 
    2. `login_fuzz_required_parameter` tests the behavior when the required parameters `wa` and/or 
 `wtrealm` are fuzzed 
 
- broker login where the external IDP is sending a fuzzed WSFED token to the broker IDP (`test_broker_fuzzing`)

Once an invalid request is sent to Keycloak, we log the reply and check if Keycloak is functioning correct 
by performing a login action.

The tool used for fuzzing is **randamsa** (https://gitlab.com/akihe/radamsa). 

## Prerequisites

Before being able to launch the tests, one needs:
- one instance of Keycloak that acts as IDP or as broker IDP in the broker test cases
- one instance of Keycloak that acts as external IDP 
- 1 WSFED service provider (SP) used for the broker test

The config file for both the IDP and SP is located at `tests_config/`. 
Pay attention that the config file follows the realms settings (i.e. name of clients, port, ip)
and if you need to change these values you need to import the realm and change the settings accordingly.

## Run tests

In order to launch the three tests, please execute the following command:

```
python3 -m pytest -vs fuzzing_tests/{name_of_the_test}.py --config-file tests_config/{config_file}.json 

```


## Log files

The invalid request, the reply of Keycloak to the invalid request and the information on whether the login done afterwards 
was successful are logged. We have a rotation of the log files every hour and we backup the last six hours. 

```buildoutcfg
filelog = logging.handlers.TimedRotatingFileHandler(filename,
                                                    when="h",
                                                    interval=6,
                                                    backupCount=10)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', '%m/%d/%Y %I:%M:%S %p')
filelog.setFormatter(formatter)
logger.addHandler(filelog)
```

 



























 



 
 