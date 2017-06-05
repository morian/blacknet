from datetime import datetime
from threading import Lock

from .config import BlacknetConfigurationInterface
from .common import *


class BlacknetLogger(BlacknetConfigurationInterface):
    """ Custom logger for Blacknet instances """


    def __init__(self, role, config):
        BlacknetConfigurationInterface.__init__(self, config, role)

        self.__write_lock = Lock()
        self.__handle = None
        self.__logpath = None
        self.__loglvl = None
        self.open()


    def __del__(self):
        self.close()


    @property
    def logpath(self):
        if self.__logpath is None:
            self.__logpath = self.get_config('log_file')
        return self.__logpath


    @property
    def loglvl(self):
        if self.__loglvl is None:
            if self.has_config('log_level'):
                self.__loglvl = int(self.get_config('log_level'))
            else:
                self.__loglvl = BLACKNET_LOG_DEFAULT
        return self.__loglvl


    def open(self, logpath=None):
        if not logpath:
            logpath = self.logpath
        self.__handle = open(logpath, 'a')


    def close(self):
        if self.__handle:
            self.__handle.close()
            self.__handle = None
            self.__logpath = None


    def reload(self):
        # Force reload (lazy) of log level.
        self.__loglvl = None

        # Check for new log path.
        logpath = self.get_config('log_file')

        if logpath != self.logpath:
            self.write("redirecting log file to %s" % logpath, BLACKNET_LOG_INFO)
            self.close()
            self.open(logpath)
            self.__logpath = logpath


    def write(self, message, level=BLACKNET_LOG_DEFAULT):
        if self.loglvl >= level:
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.__write_lock.acquire()
            self.__handle.write("%s %s\n" % (date, message))
            self.__handle.flush()
            self.__write_lock.release()
