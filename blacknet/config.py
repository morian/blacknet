import re
import os
import ConfigParser

from common import *



class BlacknetConfigError(ConfigParser.Error):
    pass


class BlacknetConfig(ConfigParser.ConfigParser):
    """ Blacknet configuration parser class """


    def __init__(self):
        ConfigParser.ConfigParser.__init__(self)
        self.__confpath = None


    def reload(self):
        """ reload the same configuration file """

        if self.__confpath:
            self.read(self.__confpath)


    def load(self, cfg_file=None):
        """ find and load configuration file from standard locations """

        found = (cfg_file is not None)

        if not found:
            for f in BLACKNET_CONFIG_DIRS:
                fname = "%s/blacknet.cfg" % f
                if os.path.isfile(fname):
                    cfg_file = fname
                    found = True
                    break

        if not found:
            raise BlacknetConfigError("No configuration file found.")

        self.read(cfg_file)
        self.__confpath = cfg_file


class BlacknetConfigurationInterface(object):
    """ Blacknet interface for configuration operations """


    def __init__(self, config, role):
        self._config = config
        self._role = role


    @property
    def config(self):
        return self._config


    def has_config(self, key):
        return self._config.has_option(self._role, key)


    def get_config(self, key):
        return self._config.get(self._role, key)


    def reload(self):
        self._config.reload()




class BlacknetBlacklist(BlacknetConfigurationInterface):
    """ Blacknet IP and users blacklisting (filtered) """


    def __init__(self, config):
        BlacknetConfigurationInterface.__init__(self, config, 'server')

        self.__extra_file = None
        self.__blacklist = {}
        self._load()


    def _read(self, filename):
        fd = open(filename, 'r')

        line = True
        section = None
        while line:
            line = fd.readline()
            if re.match('^\[.+\]$', line):
                section = line[1:len(line)-2]
                if not self.__blacklist.has_key(section):
                    self.__blacklist[section] = []
            elif section is not None:
                res = re.match('^(.*)(?:[;#]|$)', line)
                if res is not None:
                    data = res.groups()
                    username = data[0].rstrip('\n')
                    if username:
                        if username not in self.__blacklist[section]:
                            self.__blacklist[section].append(username)
        fd.close()

    def read(self, files):
        """ Load the configuration in the global variables. """
        for filename in files:
            try:
                self._read(filename)
            except:
                pass


    def has(self, sensor, username):
        resp = False
        if self.__blacklist.has_key(sensor) and username in self.__blacklist[sensor]:
            resp = True
        if self.__blacklist.has_key('*') and username in self.__blacklist['*']:
            resp = True
        return resp


    def _load(self):
        """ load blacklists from standard location and extra configuration """

        files = ["%s/blacklist.cfg" % path for path in BLACKNET_BLACKLIST_DIRS]
        if self.extra_file:
            files.append(self.extra_file)
        self.read(files)


    @property
    def extra_file(self):
        if not self.__extra_file and self.has_config('blacklist_file'):
            self.__extra_file = self.get_config('blacklist_file')
        return self.__extra_file


    def reload(self):
        """ reload blacklist files file """
        self.__extra_file = None
        self.__blacklist = {}
        self._load()

