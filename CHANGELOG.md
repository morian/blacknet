# Blacknet changelog

## [2.1.0] - UNRELEASED
- SQL: add a default value for notes on attackers
- Drop compability with Python2, ensure compatibility up to Python3.11
- Upgrade the build system to use `pyproject.toml` with setuptools
- Move console scripts to specific targets within the module
- Add typing annotations on the blacknet module
- Add linting using `ruff`, `isort` and `black`

## [2.0.9] - 2017-08-29
- Fix ping issues when server is not reachable
- Ensure credentials encoding while transmitting to master server
- Add TCP connection keep-alive parameters

## [2.0.8] - 2017-08-23
- Add ping/pong for link checker and automatic reconnect
- Few enhancements on thread safety
- Scrubber bugfixes

## [2.0.7] - 2017-06-10
- Harden communications between master and sensors
- Fix log verbosity on failed connections
- Add systemd example service scripts
- Fix updater script for python3
- Harden scrubber for `corrupted` databases

## [2.0.6] - 2017-06-07
- Work around hung threads
- Fix thread unsafety on database connections
- Add a limit in authentication retries

## [2.0.4] - 2017-06-04
- Rename main server to master
- Rename ssh server to sensor
- Fix sys module import in sensor

## [2.0.3] - 2017-06-03
- Improve Python compatbility
- Fix examples and threading issues

## [2.0.0] - 2017-05-21
- Complete rewrite of all blacknet
- Minor database structure update (to accept public keys)
- Now handles SSH public keys recording
- Integrate SSH Server, Main Server and Website in the same repository
