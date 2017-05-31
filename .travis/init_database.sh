#!/bin/bash

# verbose
set -v

if [ "${DB}" ]
then
	mysql -u root -e 'DROP USER blacknet@localhost;'
	mysql -u root -e 'CREATE USER blacknet@localhost;'
	mysql -u root -e 'DROP DATABASE blacknet_tests;'
	mysql -u root -e 'CREATE DATABASE blacknet_tests;'
	mysql -u root -e 'GRANT ALL ON blacknet_tests.* TO blacknet@localhost;'
	mysql -u root -U blacknet_tests < share/blacknet-install.sql
fi
