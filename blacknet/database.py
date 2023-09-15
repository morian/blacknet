import warnings
from contextlib import suppress
from threading import Lock

import pymysql

from .common import (
    BLACKNET_DEFAULT_LOCID,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_ERROR,
    BLACKNET_LOG_INFO,
)
from .config import BlacknetConfigurationInterface

# Forces MySQL to shut up about binlog format
warnings.filterwarnings("ignore", category=pymysql.Warning)


class BlacknetDatabaseCursor:
    """Database cursor wrapper for Mysqldb interactions."""

    def __init__(self, bnd, logger):
        """Initialize a new Blacknet Database Cursor from a Mysqldb cursor."""
        self.__bnd = bnd
        self.__logger = logger
        self.__cursor = bnd.database.cursor()

    def __del__(self):
        """Close the cursor database on instance deletion."""
        self.__cursor.close()

    def execute(self, query, args=None):
        """Execute generic queries to the database."""
        return self.__cursor.execute(query, args)

    def fetchone(self):
        """Fetch a single row from the cursor."""
        return self.__cursor.fetchone()

    def fetchall(self):
        """Fetch all rows from the cursor."""
        return self.__cursor.fetchall()

    def insert_attacker(self, args):
        """Insert a new attacker to the database."""
        query = (
            "INSERT INTO `attackers` (id,ip,dns,first_seen,last_seen,locId,n_attempts) "
            "VALUES (%s,%s,%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s),%s,%s);"
        )
        return self.execute(query, args)

    def insert_session(self, args):
        """Insert a new attack session to the database."""
        query = (
            "INSERT INTO `sessions` (attacker_id,first_attempt,last_attempt,target) "
            "VALUES (%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s),%s);"
        )
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_attempt(self, args):
        """Insert a single password attempt to the database."""
        query = (
            "INSERT INTO `attempts` "
            "(attacker_id, session_id, user, password, target, date, client) "
            "VALUES (%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),%s);"
        )
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_pubkey(self, args):
        """Insert a new public key to the database."""
        query = "INSERT INTO `pubkeys` (name,fingerprint,data,bits)" "VALUES (%s,%s,%s,%s);"
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_attempts_pubkeys(self, att_id, key_id):
        """Insert a single public key attempt to the database."""
        query = "INSERT INTO `attempts_pubkeys` (attempt_id, pubkey_id) " "VALUES(%s,%s);"
        return self.execute(query, [att_id, key_id])

    def update_attempts_count(self, table: str, t_id: int, count: int):
        """Update the number of attempts for a provided table."""
        query = "UPDATE `" + table + "s` SET n_attempts = %s WHERE id = %s;"
        return self.execute(query, [count, t_id])

    def update_dates(self, table: str, t_id: int, first_seen: int, last_seen: int):
        """Update dates of first and last attempts for a provided table."""
        lsf = "last_seen" if table == "attacker" else "last_attempt"
        fsf = "first_seen" if table == "attacker" else "first_attempt"
        query = (
            "UPDATE `" + table + "s` "
            "SET " + fsf + " = FROM_UNIXTIME(%s), " + lsf + " = FROM_UNIXTIME(%s) "
            "WHERE id = %s;"
        )
        return self.execute(query, [first_seen, last_seen, t_id])

    def update_session_last_seen(self, ses_id: int, time: int):
        """Update the last_seen field of a given attack session."""
        query = (
            "UPDATE `sessions` "
            "SET last_attempt = FROM_UNIXTIME(%s) "
            "WHERE id = %s AND last_attempt < FROM_UNIXTIME(%s);"
        )
        return self.execute(query, [time, ses_id, time])

    def update_attacker_first_seen(self, atk_id: int, time: int):
        """Update the first_seen field of a given attacker."""
        query = (
            "UPDATE `attackers` SET first_seen = FROM_UNIXTIME(%s) "
            "WHERE id = %s AND first_seen > FROM_UNIXTIME(%s);"
        )
        return self.execute(query, [time, atk_id, time])

    def update_attacker_last_seen(self, atk_id, time):
        """Update the last_seen field of a given attacker."""
        query = (
            "UPDATE `attackers` SET last_seen = FROM_UNIXTIME(%s) "
            "WHERE id = %s AND last_seen < FROM_UNIXTIME(%s);"
        )
        return self.execute(query, [time, atk_id, time])

    def check_pubkey(self, fp: str):
        """Find the current ID for the provided pubkey fingerprint."""
        query = "SELECT id FROM `pubkeys` WHERE fingerprint = %s;"
        res = self.execute(query, [fp])
        if res:
            return self.fetchone()[0]
        return None

    def check_attacker(self, aid: int):
        """Fetch first_seen and last_seen from the provided attacker id."""
        query = (
            "SELECT UNIX_TIMESTAMP(first_seen), UNIX_TIMESTAMP(last_seen) "
            "FROM `attackers` WHERE id = %s;"
        )
        res = self.execute(query, [aid])
        if res:
            return self.fetchone()
        return None

    def check_session(self, atk_id: int, sensor: str):
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
    def truncate(self, table: str):
        """Truncate the provided table."""
        return self.execute("TRUNCATE %s;" % table)

    def optimize(self, table: str):
        """Optimize the provided table."""
        return self.execute("OPTIMIZE TABLE %s;" % table)

    def insert_block(self, row):
        """Insert a new geolocation block to the database."""
        query = "INSERT INTO `blocks` (startIpNum,endIpNum,locId) VALUES (%s,%s,%s);"
        return self.execute(query, row)

    def insert_location(self, row):
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
    def missing_attackers(self):
        """Find any attacker that cannot be geolocated."""
        query = (
            "SELECT DISTINCT attacker_id FROM sessions "
            "WHERE attacker_id NOT IN (SELECT id FROM attackers);"
        )
        res = self.execute(query)
        if res:
            return [a[0] for a in self.fetchall()]
        return []

    def recompute_attacker_info(self, atk_id: int):
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

    def missing_attempts_count(self, table: str):
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

    def missing_dates(self, table: str):
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

    def get_attackers_location(self):
        """Find all attacker locations."""
        query = "SELECT id, locId FROM attackers ORDER BY id;"
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def update_attacker_location(self, atk_id: int, locid: int):
        """Update the attacker location."""
        query = "UPDATE `attackers` SET locId = %s WHERE id = %s;"
        return self.execute(query, [locid, atk_id])


class BlacknetDatabase(BlacknetConfigurationInterface):
    """Blacknet database connection management."""

    def __init__(self, config, logger=None):
        """Get logger and configuration structures from the caller."""
        BlacknetConfigurationInterface.__init__(self, config, "mysql")
        self.__connection_parameters = None
        self.__connection_lock = Lock()
        self.__logger = logger
        self.__database = None

    def _get_connection_parameters(self):
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
    def connection_parameters(self):
        """Get connection parameters."""
        if not self.__connection_parameters:
            self.__connection_parameters = self._get_connection_parameters()
        return self.__connection_parameters

    @property
    def database(self):
        """Get a handle on the database instance."""
        if not self.__database:
            self.connect()
        return self.__database

    def log(self, message, level=BLACKNET_LOG_DEFAULT):
        """Write something to the attached logger."""
        if self.__logger:
            self.__logger.write(message, level)

    def log_error(self, message):
        """Write an error message to the logger."""
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message):
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def reload(self):
        """Reload database configuration."""
        params = self._get_connection_parameters()

        if params != self.connection_parameters:
            self.__connection_parameters = params
            self.disconnect()

    def connect(self, params=None):
        """Connect to the database."""
        if not params:
            params = self.connection_parameters
        (socket, host, user, passwd, database) = params

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
                self.__database = pymysql.connect(**kwargs)
                self.log_info("pymysql: database connection successful")
        except Exception as e:
            self.log_error("database: %s" % e)
        finally:
            self.__connection_lock.release()

    def disconnect(self):
        """Disconnect from the database."""
        self.__connection_lock.acquire()
        if self.__database:
            with suppress(BaseException):
                self.__database.commit()
                self.__database.close()
            self.__database = None
        self.__connection_lock.release()

    def escape_string(self, query: str) -> str:
        """Manually escape a query using the datbase."""
        return self.__database.escape_string(query)

    def commit(self):
        """Commit all changes to the database now."""
        if self.__database:
            self.__database.commit()

    def cursor(self):
        """Build a database cursor from the database."""
        return BlacknetDatabaseCursor(self, self.__logger)
