from __future__ import annotations

import errno
import grp
import os
import pwd
import select
import socket
from threading import Thread
from typing import Callable, Optional, Union

from .common import (
    BLACKNET_LOG_CRITICAL,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_ERROR,
    BLACKNET_LOG_INFO,
    BLACKNET_SSL_DEFAULT_LISTEN,
    BLACKNET_SSL_DEFAULT_PORT,
)
from .config import BlacknetConfig, BlacknetConfigurationInterface
from .logger import BlacknetLogger

SocketPermissionType = tuple[Optional[str], Optional[str], Optional[int]]
ListenInterfaceType = Union[str, tuple[str, int]]
TimeFunc = Callable[[], None]


class BlacknetThread(Thread):
    """Subclass used for all threads."""

    def __init__(self, server: BlacknetServer, client: socket.socket) -> None:
        """Initialize a new worker thread."""
        super().__init__()
        self.started = False

    def disconnect(self) -> None:
        """Disconnect from the client."""
        return


class BlacknetServer(BlacknetConfigurationInterface):
    """Blacknet TCP Server Instance (used for both SSH server and SSL server)."""

    # default listening interface when no config is found.
    _default_listen = BLACKNET_SSL_DEFAULT_LISTEN

    def __init__(self, role: str, cfg_file: str | None = None) -> None:
        """Instanciate a new blacknet server."""
        self.__listen_interfaces = None  # type: Optional[list[ListenInterfaceType]]
        self.__socket_permissions = None  # type: Optional[SocketPermissionType]

        self._interfaces = {}  # type: dict[ListenInterfaceType, socket.socket]
        self._threads = []  # type: list[BlacknetThread]

        config = BlacknetConfig()
        config.load(cfg_file)

        super().__init__(config, role)

        self._logger = BlacknetLogger(role, config)
        self.log_info("== %s is starting" % self.__class__.__name__)

        self._listen_start_stop()

    @property
    def logger(self) -> BlacknetLogger:
        """Get a reference to the current logger."""
        return self._logger

    @property
    def socket_permissions(self) -> tuple[str | None, str | None, int | None]:
        """Get socket permissions."""
        socket_permissions = self.__socket_permissions
        if socket_permissions is None:
            owner, group, mode = (None, None, None)

            if self.has_config("listen_owner"):
                owner = self.get_config("listen_owner")
            if self.has_config("listen_group"):
                group = self.get_config("listen_group")
            if self.has_config("listen_mode"):
                try:
                    mode_string = self.get_config("listen_mode")
                    mode = int(mode_string, 8)
                except ValueError as e:
                    self.log_error("socket mode: %s" % e)
            socket_permissions = (owner, group, mode)
            self.__socket_permissions = socket_permissions
        return socket_permissions

    @property
    def listen_interfaces(self) -> list[ListenInterfaceType]:
        """List of listening interfaces."""
        if self.__listen_interfaces is None:
            listen_string = self._default_listen
            listen = []  # type: list[ListenInterfaceType]

            if self.has_config("listen"):
                listen_string = self.get_config("listen")

            for interface in listen_string.split(","):
                interface = interface.strip()
                if interface.startswith("/"):
                    listen.append(interface)
                else:
                    addr = interface.split(":")
                    address = addr[0]
                    port = BLACKNET_SSL_DEFAULT_PORT

                    if len(addr) > 1:
                        try:
                            port = int(addr[1])
                        except ValueError as e:
                            self.log_error("address port: %s" % e)
                    listen.append((address, port))
            self.__listen_interfaces = listen
        return self.__listen_interfaces

    def log(self, message: str, level: int = BLACKNET_LOG_DEFAULT) -> None:
        """Write something to the attached logger."""
        if self._logger:
            self._logger.write(message, level)

    def log_critical(self, message: str) -> None:
        """Write a critical error message to the logger."""
        self.log(message, BLACKNET_LOG_CRITICAL)

    def log_error(self, message: str) -> None:
        """Write an error message to the logger."""
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message: str) -> None:
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def reload(self) -> None:
        """Reload instance configuration."""
        self.log_info("reloading configuration")
        BlacknetConfigurationInterface.reload(self)

        if self._logger is not None:
            self._logger.reload()
        self.__listen_interfaces = None
        self.__socket_permissions = None
        self._listen_start_stop()

    def _listen_start_stop(self) -> None:
        interfaces = self.listen_interfaces

        current_interfaces = self._interfaces.keys()
        started_interfaces = []
        stopped_interfaces = []

        # List old interfaces to stop.
        for itf1 in current_interfaces:
            if itf1 not in interfaces:
                stopped_interfaces.append(itf1)

        # List new interfaces to start.
        for itf2 in interfaces:
            if itf2 not in current_interfaces:
                started_interfaces.append(itf2)

        # Change permissions on UNIX sockets to apply new ones.
        for itf3 in interfaces:
            if not isinstance(itf3, tuple) and (itf3 in current_interfaces):
                self._permissions_apply(itf3)

        # Stop listening on listed interfaces.
        for itf4 in stopped_interfaces:
            self._listen_stop(itf4)

        # Start listening on listed interfaces.
        for itf5 in started_interfaces:
            self._listen_start(itf5)

    def _listen_start(self, interface: ListenInterfaceType) -> None:
        if isinstance(interface, str):
            if os.path.exists(interface):
                os.remove(interface)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(interface)
            self._permissions_apply(interface)
            name = interface
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(interface)
            name = "%s:%u" % interface
        sock.listen(5)

        self._interfaces[interface] = sock
        self.log_info("starting interface %s" % name)

    def _listen_stop(self, interface: ListenInterfaceType) -> None:
        sock = self._interfaces.pop(interface, None)
        if sock:
            name = interface if isinstance(interface, str) else "%s:%u" % interface
            self.log_info(f"stopping interface {name}")
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

            if isinstance(interface, str):
                os.remove(interface)

    def _permissions_apply(self, filepath: str) -> None:
        owner, group, mode = self.socket_permissions
        if owner or group:
            uid = os.getuid()
            gid = os.getgid()

            if owner:
                uid = pwd.getpwnam(owner).pw_uid
            if group:
                gid = grp.getgrnam(group).gr_gid
            os.chown(filepath, uid, gid)
        if mode:
            os.chmod(filepath, mode)

    def _threads_cleanup(self) -> None:
        for thr in self._threads:
            if not thr.started and not thr.is_alive():
                thr.join()
                self._threads.remove(thr)

    def _threads_killer(self) -> None:
        for thr in self._threads:
            if thr.is_alive():
                thr.disconnect()
            if thr.started:
                thr.join()
            self._threads.remove(thr)

    def serve(
        self,
        threadclass: type[BlacknetThread] = BlacknetThread,
        timeout: float | None = None,
        timefunc: TimeFunc | None = None,
    ) -> None:
        """Serve new connections into new threads."""
        self._threads_cleanup()

        sockets = self._interfaces.values()
        try:
            acceptable = select.select(sockets, [], [], timeout)
            if timefunc is not None and not len(acceptable[0]):
                timefunc()
            for sock in acceptable[0]:
                client, address = sock.accept()
                t = threadclass(self, client)
                self._threads.append(t)
                t.start()
        except InterruptedError:
            pass
        except OSError as e:
            error = e.args[0]
            if error != errno.EINTR:
                self.log_error("select error: %s" % e)
        except Exception as e:
            self.log_error("error: %s" % e)

    def shutdown(self) -> None:
        """Stop all interfaces and shutdown the server."""
        # Force expected interfaces to be an empty list.
        self.__listen_interfaces = []
        self._listen_start_stop()
        self._threads_killer()
        self.log_info("== %s stopped" % self.__class__.__name__)
        logger = self._logger
        if logger is not None:
            logger.close()
