import os
import re
from configparser import ConfigParser
from contextlib import suppress
from typing import Optional

from .common import BLACKNET_BLACKLIST_DIRS, BLACKNET_CONFIG_DIRS


class BlacknetConfig(ConfigParser):
    """Blacknet configuration parser class."""

    def __init__(self) -> None:
        """Create a new configuration for blacknet."""
        super().__init__()
        self.__confpath = None  # type: Optional[str]

    def reload(self) -> None:
        """Reload the same configuration file."""
        if self.__confpath:
            self.read(self.__confpath)

    def load(self, cfg_file: Optional[str] = None) -> None:
        """Find and load configuration file from standard locations."""
        if cfg_file is None:
            for f in BLACKNET_CONFIG_DIRS:
                fname = os.path.join(f, "blacknet.cfg")
                if os.path.isfile(fname):
                    cfg_file = fname
                    break

        if cfg_file is None:
            raise Exception("No configuration file found.")

        self.read(cfg_file)
        self.__confpath = cfg_file


class BlacknetConfigurationInterface:
    """Blacknet interface for configuration operations."""

    def __init__(self, config: BlacknetConfig, role: str) -> None:
        """Initialize the interface for all components using configuration."""
        self._config = config
        self._role = role

    @property
    def config(self) -> BlacknetConfig:
        """Get the contained configuration."""
        return self._config

    def has_config(self, key: str) -> bool:
        """Check whether the configuration has the provided key."""
        return self._config.has_option(self._role, key)

    def get_config(self, key: str) -> str:
        """Get a configuration entry."""
        return self._config.get(self._role, key)

    def reload(self) -> None:
        """Reload the configuration file."""
        self._config.reload()


class BlacknetBlacklist(BlacknetConfigurationInterface):
    """Blacknet IP and users blacklisting (filtered)."""

    def __init__(self, config: BlacknetConfig) -> None:
        """Create a blacklist configuration class."""
        super().__init__(config, "server")

        self.__extra_file = None  # type: Optional[str]
        self.__blacklist = {}  # type: dict[str, list[str]]
        self._load()

    def _read(self, filename: str) -> None:
        with open(filename) as fd:
            section = None

            for line in map(str.rstrip, fd):
                if re.match(r"^\[.+\]$", line):
                    section = line[1 : len(line) - 2]
                    if section not in self.__blacklist:
                        self.__blacklist[section] = []
                elif section is not None:
                    res = re.match("^(.*)(?:[;#]|$)", line)
                    if res is not None:
                        data = res.groups()
                        username = data[0].rstrip("\n")
                        if username:
                            if username not in self.__blacklist[section]:
                                self.__blacklist[section].append(username)

    def read(self, files: list[str]) -> None:
        """Load the configuration in the global variables."""
        with suppress(Exception):
            for filename in files:
                self._read(filename)

    def has(self, sensor: str, username: str) -> bool:
        """Tells whether the blacklist has a matching sensor/username."""
        resp = False
        if sensor in self.__blacklist and username in self.__blacklist[sensor]:
            resp = True
        if "*" in self.__blacklist and username in self.__blacklist["*"]:
            resp = True
        return resp

    def _load(self) -> None:
        """Load blacklists from standard location and extra configuration."""
        files = [os.path.join(path, "blacklist.cfg") for path in BLACKNET_BLACKLIST_DIRS]
        if self.extra_file:
            files.append(self.extra_file)
        self.read(files)

    @property
    def extra_file(self) -> Optional[str]:
        """List of extra blacklist files."""
        if not self.__extra_file and self.has_config("blacklist_file"):
            self.__extra_file = self.get_config("blacklist_file")
        return self.__extra_file

    def reload(self) -> None:
        """Reload blacklist files."""
        self.__extra_file = None
        self.__blacklist = {}
        self._load()
