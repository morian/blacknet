import pymysql
import warnings

from threading import Lock

from .config import BlacknetConfigurationInterface
from .common import *

# Forces MySQL to shut up about binlog format
warnings.filterwarnings('ignore', category=pymysql.Warning)

class BlacknetDatabaseCursor(object):
    """ Database cursor wrapper for Mysqldb interactions. """


    def __init__(self, bnd, logger):
        """ Initialize a new Blacknet Database Cursor from a Mysqldb cursor. """
        self.__bnd = bnd
        self.__cursor = None
        self.__logger = logger
        self.__cursor = bnd.database.cursor()


    def __del__(self):
        if self.__cursor:
            self.__cursor.close()


    def log(self, message, level=BLACKNET_LOG_DEFAULT):
        if self.__logger:
            self.__logger.write(message, level)


    def __database_reload(self):
        self.__cursor.close()
        self.__bnd.disconnect()
        self.__cursor = self.__bnd.database.cursor()


    def execute(self, query, args=None):
        """ Execute generic queries to the database. """
        return self.__cursor.execute(query, args)


    def fetchone(self):
        return self.__cursor.fetchone()

    def fetchall(self):
        return self.__cursor.fetchall()

    def insert_attacker(self, args):
        query = 'INSERT INTO `attackers` (id,ip,dns,first_seen,last_seen,locId,n_attempts) ' \
                'VALUES (%s,%s,%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s),%s,%s);'
        return self.execute(query, args)


    def insert_session(self, args):
        query = 'INSERT INTO `sessions` (attacker_id,first_attempt,last_attempt,target) ' \
                'VALUES (%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s),%s);'
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_attempt(self, args):
        query = 'INSERT INTO `attempts` '                                          \
                '(attacker_id, session_id, user, password, target, date, client) ' \
                'VALUES (%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),%s);'
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_pubkey(self, args):
        query = 'INSERT INTO `pubkeys` (name,fingerprint,data,bits)'      \
                'VALUES (%s,%s,%s,%s);'
        self.execute(query, args)
        return self.__cursor.lastrowid

    def insert_attempts_pubkeys(self, att_id, key_id):
        query = 'INSERT INTO `attempts_pubkeys` (attempt_id, pubkey_id) ' \
                'VALUES(%s,%s);'
        return self.execute(query, [att_id, key_id])

    def update_attempts_count(self, table, t_id, count):
        query = 'UPDATE `' + table + 's` SET n_attempts = %s WHERE id = %s;'
        return self.execute(query, [count, t_id])

    def update_dates(self, table, t_id, first_seen, last_seen):
        lsf = 'last_seen' if table == 'attacker' else 'last_attempt'
        fsf = 'first_seen' if table == 'attacker' else 'first_attempt'
        query = 'UPDATE `' + table + 's` '                   \
                'SET ' + fsf + ' = FROM_UNIXTIME(%s), ' + lsf + ' = FROM_UNIXTIME(%s) ' \
                'WHERE id = %s;'
        return self.execute(query, [first_seen, last_seen, t_id])

    def update_session_last_seen(self, ses_id, time):
        query = 'UPDATE `sessions` '                                      \
                'SET last_attempt = FROM_UNIXTIME(%s) '                   \
                'WHERE id = %s AND last_attempt < FROM_UNIXTIME(%s);'
        return self.execute(query, [time, ses_id, time])

    def update_attacker_first_seen(self, atk_id, time):
        query  = 'UPDATE `attackers` SET first_seen = FROM_UNIXTIME(%s) ' \
                 'WHERE id = %s AND first_seen > FROM_UNIXTIME(%s);'
        return self.execute(query, [time, atk_id, time])

    def update_attacker_last_seen(self, atk_id, time):
        query  = 'UPDATE `attackers` SET last_seen = FROM_UNIXTIME(%s) '  \
                 'WHERE id = %s AND last_seen < FROM_UNIXTIME(%s);'
        return self.execute(query, [time, atk_id, time])

    def check_pubkey(self, fp):
        query = 'SELECT id FROM `pubkeys` WHERE fingerprint = %s;'
        res = self.execute(query, [fp])
        if res:
            return self.fetchone()[0]

    def check_attacker(self, aid):
        query = 'SELECT UNIX_TIMESTAMP(first_seen), UNIX_TIMESTAMP(last_seen) ' \
                'FROM `attackers` WHERE id = %s;'
        res = self.execute(query, [aid])
        if res:
            return self.fetchone()

    def check_session(self, atk_id, sensor):
        query = 'SELECT id, UNIX_TIMESTAMP(last_attempt) '   \
                'FROM `sessions` '                           \
                'WHERE attacker_id = %s AND target = %s '    \
                'ORDER BY last_attempt DESC LIMIT 1;'
        res = self.execute(query, [atk_id, sensor])
        if res:
            return self.fetchone()

    def get_locid(self, atk_id):
        query = 'SELECT locId from `blocks` WHERE %u BETWEEN startIpNum AND endIpNum LIMIT 1;' % atk_id
        res = self.execute(query)
        if res:
            return self.__cursor.fetchone()[0]

    # In use for geolocation updater
    def truncate(self, table):
        return self.execute('TRUNCATE %s;' % table)

    def optimize(self, table):
        return self.execute('OPTIMIZE TABLE %s;' % table)

    def insert_block(self, row):
        query = 'INSERT INTO `blocks` (startIpNum,endIpNum,locId) VALUES (%s,%s,%s);'
        return self.execute(query, row)

    def insert_location(self, row):
        query = 'INSERT INTO `locations` (locId,country,region,city,postalCode,latitude,longitude,metroCode,areaCode) ' \
                'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);'
        return self.execute(query, row)

    # Used for blacknet scrubber
    def missing_attackers(self):
        query = 'SELECT DISTINCT attacker_id FROM sessions ' \
                'WHERE attacker_id NOT IN (SELECT id FROM attackers);'
        res = self.execute(query)
        if res:
            return [a[0] for a in self.fetchall()]
        return []

    def recompute_attacker_info(self, atk_id):
        query = 'SELECT UNIX_TIMESTAMP(MIN(date)), UNIX_TIMESTAMP(MAX(date)), COUNT(*) ' \
                'FROM attempts WHERE attacker_id = %s '  \
                'GROUP BY attacker_id LIMIT 1;'
        res = self.execute(query, [atk_id])
        if res:
            return self.fetchone()

    def missing_attempts_count(self, table):
        query = 'SELECT ' + table + 's.id, ' + table + 's.n_attempts, COUNT(*) ' \
                'FROM ' + table + 's '                                           \
                'JOIN attempts ON ' + table + 's.id = attempts.' + table + '_id '\
                'GROUP BY ' + table + 's.id '                                    \
                'HAVING n_attempts != COUNT(*);'
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def missing_dates(self, table):
        lsf = 'last_seen' if table == 'attacker' else 'last_attempt'
        fsf = 'first_seen' if table == 'attacker' else 'first_attempt'

        query = 'SELECT ' + table + 's.id, '                                             \
                'UNIX_TIMESTAMP(' + fsf + '), UNIX_TIMESTAMP(' + lsf + '), '             \
                'UNIX_TIMESTAMP(MIN(attempts.date)), UNIX_TIMESTAMP(MAX(attempts.date)) '\
                'FROM ' + table + 's JOIN attempts '                                     \
                'ON ' + table + 's.id = attempts.' + table + '_id '                      \
                'GROUP BY ' + table + 's.id;'
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def get_attackers_location(self):
        query = 'SELECT id, locId FROM attackers;'
        res = self.execute(query)
        if res:
            return self.fetchall()
        return []

    def update_attacker_location(self, atk_id, locId):
        query = 'UPDATE `attackers` SET locId = %s WHERE id = %s;'
        return self.execute(query, [locId, atk_id])


class BlacknetDatabase(BlacknetConfigurationInterface):
    """ Blacknet database connection management. """


    def __init__(self, config, logger=None):
        """ Get logger and configuration structures from the caller.  """

        BlacknetConfigurationInterface.__init__(self, config, 'mysql')
        self.__connection_parameters = None
        self.__connection_lock = Lock()
        self.__logger = logger
        self.__database = None


    def _get_connection_parameters(self):
        if self.has_config('socket'):
            socket = self.get_config('socket')
            host = None
        else:
            host = self.get_config('host')
            socket = None
        user = self.get_config('username')
        password = self.get_config('password')
        database = self.get_config('database')
        return (socket, host, user, password, database)


    @property
    def connection_parameters(self):
        if not self.__connection_parameters:
            self.__connection_parameters = self._get_connection_parameters()
        return self.__connection_parameters


    @property
    def database(self):
        if not self.__database:
            self.connect()
        return self.__database


    def log(self, message, level=BLACKNET_LOG_DEFAULT):
        if self.__logger:
            self.__logger.write(message, level)


    def reload(self):
        params = self._get_connection_parameters()
        if params != self.connection_parameters:
            self.reconnect(params)
            self.__connection_parameters = params


    def connect(self, params=None):
        if not params:
            params = self.connection_parameters
        (socket, host, user, passwd, database) = params

        self.__connection_lock.acquire()
        try:
            if not self.__database:
                kwargs = {
                    'host': host,
                    'user': user,
                    'password': passwd,
                    'db': database,
                    'unix_socket': socket,
                    'charset': 'utf8',
                }
                self.__database = pymysql.connect(**kwargs)
                self.log("pymysql: database connection successful", BLACKNET_LOG_INFO)
        except Exception as e:
            self.log('database: %s' % e, BLACKNET_LOG_ERROR)
        finally:
            self.__connection_lock.release()


    def disconnect(self):
        self.__connection_lock.acquire()
        if self.__database:
            try:
                self.__database.commit()
                self.__database.close()
            except:
                pass
            self.__database = None
        self.__connection_lock.release()


    def reconnect(self, params=None):
        self.disconnect()
        self.connect(params)


    def escape_string(self, string):
        return self.__database.escape_string(string)


    def commit(self):
        if self.__database:
            self.__database.commit()


    def cursor(self):
        return BlacknetDatabaseCursor(self, self.__logger)

