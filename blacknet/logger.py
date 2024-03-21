from __future__ import annotations

from datetime import datetime
from io import TextIOWrapper  # noqa: F401
from threading import Lock

from .common import BLACKNET_LOG_DEFAULT, BLACKNET_LOG_INFO
from .config import BlacknetConfig, BlacknetConfigurationInterface


class BlacknetLogger(BlacknetConfigurationInterface):
    """Custom logger for Blacknet instances."""

    def __init__(self, role: str, config: BlacknetConfig) -> None:
        """Instanciate a new logger."""
        super().__init__(config, role)

        self.__write_lock = Lock()
        self.__handle = None  # type: TextIOWrapper | None
        self.__logpath = None  # type: str | None
        self.__loglvl = None  # type: int | None
        self.open()

    def __del__(self) -> None:
        """Close the logger on destruction."""
        self.close()

    @property
    def logpath(self) -> str:
        """Get the logging current logging path."""
        if self.__logpath is None:
            self.__logpath = self.get_config("log_file")
        return self.__logpath

    @property
    def loglvl(self) -> int:
        """Get the current log level."""
        if self.__loglvl is None:
            if self.has_config("log_level"):
                self.__loglvl = int(self.get_config("log_level"))
            else:
                self.__loglvl = BLACKNET_LOG_DEFAULT
        return self.__loglvl

    def open(self, logpath: str | None = None) -> None:
        """Open a new log file."""
        if not logpath:
            logpath = self.logpath
        self.__handle = open(logpath, "a")  # noqa: SIM115

    def close(self) -> None:
        """Close the current log handle."""
        if self.__handle:
            self.__handle.close()
            self.__handle = None
            self.__logpath = None

    def reload(self) -> None:
        """Reload the logging configuration."""
        # Force reload (lazy) of log level.
        self.__loglvl = None

        # Check for new log path.
        logpath = self.get_config("log_file")

        if logpath != self.logpath:
            self.write("redirecting log file to %s" % logpath, BLACKNET_LOG_INFO)
            self.close()
            self.open(logpath)
            self.__logpath = logpath

    def write(self, message: str, level: int = BLACKNET_LOG_DEFAULT) -> None:
        """Write a new message to the output log file."""
        if self.loglvl >= level and self.__handle is not None:
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with self.__write_lock:
                self.__handle.write(f"{date} {message}\n")
                self.__handle.flush()
