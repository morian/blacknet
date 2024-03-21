from __future__ import annotations

import warnings
from collections.abc import Collection, Iterable
from contextlib import suppress
from threading import Lock
from typing import Any, Optional

import pymysql

from .common import (
    BLACKNET_DEFAULT_LOCID,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_ERROR,
    BLACKNET_LOG_INFO,
)
from .config import BlacknetConfig, BlacknetConfigurationInterface
from .logger import BlacknetLogger

# Forces MySQL to shut up about binlog format
warnings.filterwarnings("ignore", category=pymysql.Warning)

DbConnectionParams = tuple[Optional[str], Optional[str], str, str, str]


class BlacknetDatabaseCursor:
    """Database cursor wrapper for Mysqldb interactions."""

    def __init__(self, bnd: BlacknetDatabase, logger: BlacknetLogger | None = None) -> None:
        """Initialize a new Blacknet Database Cursor from a Mysqldb cursor."""
        self.__bnd = bnd
        self.__logger = logger
        self.__cursor = bnd.database.cursor()

    def __del__(self) -> None:
        """Close the cursor database on instance deletion."""
        self.__cursor.close()

    def execute(self, query: str, args: Iterable[Any] | None = None) -> Any:
        """Execute generic queries to the database."""
        return self.__cursor.execute(query, args)

    def fetchone(self) -> Any:
        """Fetch a single row from the cursor."""
        return self.__cursor.fetchone()

    def fetchall(self) -> list[Any]:
        """Fetch all rows from the cursor."""
        return self.__cursor.fetchall()

    def insert_attacker(self, args: Collection[Any]) -> None:
        """Insert a new attacker to the database."""
        query = (
            "INSERT INTO `attackers` (id,ip,dns,first_seen,last_seen,locId,n_attempts) "
            "VALUES (%s,%s,%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s),%s,%s);"
        )
        return self.execute(query, args)

    def insert_session(self, args: Collection[Any]) -> int:
        """Insert a new attack session to the database."""
        query = (
            "INSERT INTO `sessions` (attacker_id,first_attempt,last_attempt,target) "
            "VALUES (%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s),%s);"
        )
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_attempt(self, args: Collection[Any]) -> int:
        """Insert a single password attempt to the database."""
        query = (
            "INSERT INTO `attempts` "
            "(attacker_id, session_id, user, password, target, date, client) "
            "VALUES (%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),%s);"
        )
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_pubkey(self, args: Collection[Any]) -> int:
        """Insert a new public key to the database."""
        query = "INSERT INTO `pubkeys` (name,fingerprint,data,bits)" "VALUES (%s,%s,%s,%s);"
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_attempts_pubkeys(self, att_id: int, key_id: int) -> None:
        """Insert a single public key attempt to the database."""
        query = "INSERT INTO `attempts_pubkeys` (attempt_id, pubkey_id) " "VALUES(%s,%s);"
        return self.execute(query, [att_id, key_id])

    def update_attempts_count(self, table: str, t_id: int, count: int) -> None:
        """Update the number of attempts for a provided table."""
        query = f"UPDATE `{table}s` SET n_attempts = %s WHERE id = %s;"  # noqa: S608
        return self.execute(query, [count, t_id])

    def update_dates(self, table: str, t_id: int, first_seen: int, last_seen: int) -> None:
        """Update dates of first and last attempts for a provided table."""
        lsf = "last_seen" if table == "attacker" else "last_attempt"
        fsf = "first_seen" if table == "attacker" else "first_attempt"
        query = (
            f"UPDATE `{table}s` "  # noqa: S608
            f"SET {fsf} = FROM_UNIXTIME(%s), {lsf} = FROM_UNIXTIME(%s) "
            "WHERE id = %s;"
        )
        return self.execute(query, [first_seen, last_seen, t_id])

    def update_session_last_seen(self, ses_id: int, time: int) -> None:
        """Update the last_seen field of a given attack session."""
        query = (
            "UPDATE `sessions` "
            "SET last_attempt = FROM_UNIXTIME(%s) "
            "WHERE id = %s AND last_attempt < FROM_UNIXTIME(%s);"
        )
        return self.execute(query, [time, ses_id, time])

    def update_attacker_first_seen(self, atk_id: int, time: int) -> None:
        """Update the first_seen field of a given attacker."""
        query = (
            "UPDATE `attackers` SET first_seen = FROM_UNIXTIME(%s) "
            "WHERE id = %s AND first_seen > FROM_UNIXTIME(%s);"
        )
        return self.execute(query, [time, atk_id, time])

    def update_attacker_last_seen(self, atk_id: int, time: int) -> None:
        """Update the last_seen field of a given attacker."""
        query = (
            "UPDATE `attackers` SET last_seen = FROM_UNIXTIME(%s) "
            "WHERE id = %s AND last_seen < FROM_UNIXTIME(%s);"
        )
        return self.execute(query, [time, atk_id, time])

    def check_pubkey(self, fp: str) -> int | None:
        """Find the current ID for the provided pubkey fingerprint."""
        query = "SELECT id FROM `pubkeys` WHERE fingerprint = %s;"
        res = self.execute(query, [fp])
        if res:
            return self.fetchone()[0]
        return None

    def check_attacker(self, aid: int) -> tuple[int, int] | None:
        """Fetch first_seen and last_seen from the provided attacker id."""
        query = (
            "SELECT UNIX_TIMESTAMP(first_seen), UNIX_TIMESTAMP(last_seen) "
            "FROM `attackers` WHERE id = %s;"
        )
        res = self.execute(query, [aid])
        if res:
            return self.fetchone()
        return None

    def check_session(self, atk_id: int, sensor: str) -> tuple[int, int] | None:
        """List all sessions and last attempts for a provided attacker id."""
        query = (
            "SELECT id, UNIX_TIMESTAMP(last_attempt) "
            "FROM `sessions` "
            "WHERE attacker_id = %s AND target = %s "
            "ORDER BY last_attempt DESC LIMIT 1;"
        )
        res = self.execute(query, [atk_id, sensor])
        if res:
            return self.fetchone()
        return None

    def get_locid(self, atk_id: int) -> int:
        """Find the location of an attacker in the geolocation database."""
        query = (
            "SELECT locId "
            "FROM `blocks` "
            "WHERE %s BETWEEN startIpNum AND endIpNum LIMIT 1;"
        )
        res = self.execute(query, [atk_id])
        if res:
            return self.__cursor.fetchone()[0]
        return BLACKNET_DEFAULT_LOCID

    # In use for geolocation updater
    def truncate(self, table: str) -> None:
        """Truncate the provided table."""
        return self.execute("TRUNCATE %s;" % table)

    def optimize(self, table: str) -> None:
        """Optimize the provided table."""
        return self.execute("OPTIMIZE TABLE %s;" % table)

    def insert_block(self, row: Collection[Any]) -> None:
        """Insert a new geolocation block to the database."""
        query = "INSERT INTO `blocks` (startIpNum,endIpNum,locId) VALUES (%s,%s,%s);"
        return self.execute(query, row)

    def insert_location(self, row: list[Any]) -> None:
        """Insert a new geolocation to the database."""
        query = (
            "INSERT INTO `locations` "
            "(locId,country,region,city,postalCode, "
            "latitude,longitude,metroCode,areaCode) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);"
        )
        # Make sure they are mapped to NULL.
        for i in (7, 8):
            if not len(row[i]):
                row[i] = None
        return self.execute(query, row)

    # Used for blacknet scrubber
    def missing_attackers(self) -> list[int]:
        """Find any attacker that cannot be geolocated."""
        query = (
            "SELECT DISTINCT attacker_id FROM sessions "
            "WHERE attacker_id NOT IN (SELECT id FROM attackers);"
        )
        res = self.execute(query)
        if res:
            return [a[0] for a in self.fetchall()]
        return []

    def recompute_attacker_info(self, atk_id: int) -> tuple[int, int, int] | None:
        """Recompute all fields from a provided attacker."""
        query = (
            "SELECT UNIX_TIMESTAMP(MIN(date)), UNIX_TIMESTAMP(MAX(date)), COUNT(*) "
            "FROM attempts WHERE attacker_id = %s "
            "GROUP BY attacker_id LIMIT 1;"
        )
        res = self.execute(query, [atk_id])
        if res:
            return self.fetchone()
        return None

    def missing_attempts_count(self, table: str) -> list[tuple[int, int, int]]:
        """Find the missing attempts."""
        query = (
            "SELECT " + table + "s.id, " + table + "s.n_attempts, COUNT(*) "
            "FROM " + table + "s "
            "JOIN attempts ON " + table + "s.id = attempts." + table + "_id "
            "GROUP BY " + table + "s.id "
            "HAVING n_attempts != COUNT(*);"
        )
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def missing_dates(self, table: str) -> list[tuple[int, int, int, int, int]]:
        """Find all data mismatches."""
        lsf = "last_seen" if table == "attacker" else "last_attempt"
        fsf = "first_seen" if table == "attacker" else "first_attempt"

        query = (
            "SELECT " + table + "s.id, "
            "UNIX_TIMESTAMP(" + fsf + "), UNIX_TIMESTAMP(" + lsf + "), "
            "UNIX_TIMESTAMP(MIN(attempts.date)), UNIX_TIMESTAMP(MAX(attempts.date)) "
            "FROM " + table + "s JOIN attempts "
            "ON " + table + "s.id = attempts." + table + "_id "
            "GROUP BY " + table + "s.id;"
        )
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def get_attackers_location(self) -> list[tuple[int, int]]:
        """Find all attacker locations."""
        query = "SELECT id, locId FROM attackers ORDER BY id;"
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def update_attacker_location(self, atk_id: int, locid: int) -> None:
        """Update the attacker location."""
        query = "UPDATE `attackers` SET locId = %s WHERE id = %s;"
        return self.execute(query, [locid, atk_id])


class BlacknetDatabase(BlacknetConfigurationInterface):
    """Blacknet database connection management."""

    def __init__(
        self,
        config: BlacknetConfig,
        logger: BlacknetLogger | None = None,
    ) -> None:
        """Get logger and configuration structures from the caller."""
        BlacknetConfigurationInterface.__init__(self, config, "mysql")
        self.__connection_parameters = None  # type: Optional[DbConnectionParams]
        self.__connection_lock = Lock()
        self.__logger = logger
        self.__database = None  # type: Optional[pymysql.Connection[Any]]

    def _get_connection_parameters(self) -> DbConnectionParams:
        if self.has_config("socket"):
            socket = self.get_config("socket")
            host = None
        else:
            host = self.get_config("host")
            socket = None
        user = self.get_config("username")
        password = self.get_config("password")
        database = self.get_config("database")
        return (socket, host, user, password, database)

    @property
    def connection_parameters(self) -> DbConnectionParams:
        """Get connection parameters."""
        if not self.__connection_parameters:
            self.__connection_parameters = self._get_connection_parameters()
        return self.__connection_parameters

    @property
    def database(self) -> pymysql.Connection[Any]:
        """Get a handle on the database instance."""
        if self.__database is None:
            self.connect()
            if self.__database is None:
                raise Exception("Could not connect to the database!")
        return self.__database

    def log(self, message: str, level: int = BLACKNET_LOG_DEFAULT) -> None:
        """Write something to the attached logger."""
        if self.__logger:
            self.__logger.write(message, level)

    def log_error(self, message: str) -> None:
        """Write an error message to the logger."""
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message: str) -> None:
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def reload(self) -> None:
        """Reload database configuration."""
        params = self._get_connection_parameters()

        if params != self.connection_parameters:
            self.__connection_parameters = params
            self.disconnect()

    def connect(self, params: DbConnectionParams | None = None) -> None:
        """Connect to the database."""
        if not params:
            params = self.connection_parameters
        socket, host, user, passwd, database = params

        self.__connection_lock.acquire()
        try:
            if not self.__database:
                kwargs = {
                    "host": host,
                    "user": user,
                    "password": passwd,
                    "db": database,
                    "unix_socket": socket,
                    "charset": "utf8",
                }
                self.__database = pymysql.connect(**kwargs)  # type: ignore
                self.log_info("pymysql: database connection successful")
        except Exception as e:
            self.log_error("database: %s" % e)
        finally:
            self.__connection_lock.release()

    def disconnect(self) -> None:
        """Disconnect from the database."""
        with self.__connection_lock:
            if self.__database:
                with suppress(BaseException):
                    self.__database.commit()
                    self.__database.close()
                self.__database = None

    def escape_string(self, query: str) -> str:
        """Manually escape a query using the datbase."""
        if self.__database is not None:
            return self.__database.escape_string(query)
        return query

    def commit(self) -> None:
        """Commit all changes to the database now."""
        if self.__database:
            self.__database.commit()

    def cursor(self) -> BlacknetDatabaseCursor:
        """Build a database cursor from the database."""
        return BlacknetDatabaseCursor(self, self.__logger)
