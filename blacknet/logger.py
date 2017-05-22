import datetime

from config import BlacknetConfigurationInterface
from threading import Lock


class BlacknetLogger(BlacknetConfigurationInterface):
    """ Custom logger for BlackNet instances """


    def __init__(self, role, config):
        BlacknetConfigurationInterface.__init__(self, config, role)

        self.__write_lock = Lock()
        self.__handle = None
        self.__logpath = None
        self.open()


    def __del__(self):
        self.close()


    @property
    def logpath(self):
        if not self.__logpath:
            self.__logpath = self.get_config('log_file')
        return self.__logpath


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
        logpath = self.get_config('log_file')

        if logpath != self.logpath:
            self.write("redirecting log file to %s" % logpath)
            self.close()
            self.open(logpath)
            self.__logpath = logpath


    def write(self, message):
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.__write_lock.acquire()
        self.__handle.write("%s %s\n" % (date, message))
        self.__handle.flush()
        self.__write_lock.release()
