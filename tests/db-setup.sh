#!/bin/sh

DB_HOST="$1"
DB_ROOT_PASSWORD="$2"
DB_USER="$3"
DB_PASSWORD="$4"
DB_DATABASE="$5"

CURDIR=$(dirname "$0")
BASEDIR=$(cd "${CURDIR}/../" && pwd)

(
	echo "DROP DATABASE IF EXISTS ${DB_DATABASE};"
	echo "CREATE DATABASE ${DB_DATABASE};"
	echo "GRANT ALL ON ${DB_DATABASE}.* TO ${DB_USER}@'%';"
) | mysql -v --host="${DB_HOST}" --port=3306 -uroot -p"${DB_ROOT_PASSWORD}"

(
	cat "${BASEDIR}/share/blacknet-install.sql"
) | mysql -v --host="${DB_HOST}" --port=3306 -u"${DB_USER}" -p"${DB_PASSWORD}" "${DB_DATABASE}"
