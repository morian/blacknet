import errno
import grp
import os
import pwd
import select
import socket
from threading import Thread
from typing import Optional, Union  # noqa: F401

from .common import (
    BLACKNET_LOG_CRITICAL,
    BLACKNET_LOG_DEBUG,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_ERROR,
    BLACKNET_LOG_INFO,
    BLACKNET_SSL_DEFAULT_LISTEN,
    BLACKNET_SSL_DEFAULT_PORT,
)
from .config import BlacknetConfig, BlacknetConfigurationInterface
from .logger import BlacknetLogger


class BlacknetServer(BlacknetConfigurationInterface):
    """Blacknet TCP Server Instance (used for both SSH server and SSL server)."""

    # default listening interface when no config is found.
    _default_listen = BLACKNET_SSL_DEFAULT_LISTEN

    def __init__(self, role: str, cfg_file=None):
        """Instanciate a new blacknet server."""
        self.__listen_interfaces = None  # type: Optional[list[Union[str, tuple[str, int]]]]
        self.__socket_permissions = None  # type: Optional[tuple[str, str, int]]

        self._interfaces = {}
        self._threads = []
        self._logger = None

        config = BlacknetConfig()
        config.load(cfg_file)

        super().__init__(config, role)

        self._logger = BlacknetLogger(role, config)
        self.log_info("== %s is starting" % self.__class__.__name__)

        self._listen_start_stop()

    @property
    def socket_permissions(self) -> tuple[str, str, int]:
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
    def listen_interfaces(self):
        """List of listening interfaces."""
        if self.__listen_interfaces is None:
            listen_string = self._default_listen
            listen = []  # type: list[Union[str, tuple[str, int]]]

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

    def log(self, message: str, level=BLACKNET_LOG_DEFAULT) -> None:
        """Write something to the attached logger."""
        if self._logger:
            self._logger.write(message, level)

    def log_critical(self, message):
        """Write a critical message to the logger."""
        self.log(message, BLACKNET_LOG_CRITICAL)

    def log_error(self, message):
        """Write an error message to the logger."""
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message):
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def log_debug(self, message):
        """Write a debug message to the logger."""
        self.log(message, BLACKNET_LOG_DEBUG)

    def reload(self):
        """Reload instance configuration."""
        self.log_info("reloading configuration")
        BlacknetConfigurationInterface.reload(self)
        self._logger.reload()

        self.__listen_interfaces = None
        self.__socket_permissions = None
        self._listen_start_stop()

    def _listen_start_stop(self):
        interfaces = self.listen_interfaces

        current_interfaces = self._interfaces.keys()
        started_interfaces = []
        stopped_interfaces = []

        # List old interfaces to stop.
        for itf in current_interfaces:
            if itf not in interfaces:
                stopped_interfaces.append(itf)

        # List new interfaces to start.
        for itf in interfaces:
            if itf not in current_interfaces:
                started_interfaces.append(itf)

        # Change permissions on UNIX sockets to apply new ones.
        for itf in interfaces:
            if not isinstance(itf, tuple) and (itf in current_interfaces):
                self._permissions_apply(itf)

        # Stop listening on listed interfaces.
        for itf in stopped_interfaces:
            self._listen_stop(itf)

        # Start listening on listed interfaces.
        for itf in started_interfaces:
            self._listen_start(itf)

    def _listen_start(self, interface):
        unix_socket = not isinstance(interface, tuple)
        name = interface if unix_socket else "%s:%u" % interface

        if unix_socket:
            if os.path.exists(interface):
                os.remove(interface)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(interface)
            self._permissions_apply(interface)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(interface)
        sock.listen(5)

        self._interfaces[interface] = sock
        self.log_info("starting interface %s" % name)

    def _listen_stop(self, interface):
        sock = self._interfaces.pop(interface, None)
        if sock:
            unix_socket = sock.family == socket.AF_UNIX
            name = interface if unix_socket else "%s:%u" % interface

            self.log_info("stopping interface %s" % name)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

            if unix_socket:
                os.remove(interface)

    def _permissions_apply(self, filepath):
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

    def _threads_cleanup(self):
        for thr in self._threads:
            if not thr.started and not thr.is_alive():
                thr.join()
                self._threads.remove(thr)

    def _threads_killer(self):
        for thr in self._threads:
            if thr.is_alive():
                thr.disconnect()
            if thr.started:
                thr.join()
            self._threads.remove(thr)

    def serve(self, threadclass=Thread, timeout=None, timefunc=None):
        """Serve new connections into new threads."""
        self._threads_cleanup()

        sockets = self._interfaces.values()
        try:
            acceptable = select.select(sockets, [], [], timeout)
            if not len(acceptable[0]) and timefunc:
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

    def shutdown(self):
        """Stop all interfaces and shutdown the server."""
        # Force expected interfaces to be an empty list.
        self.__listen_interfaces = []
        self._listen_start_stop()
        self._threads_killer()
        self.log_info("== %s stopped" % self.__class__.__name__)
        logger = self._logger
        self._logger = None
        logger.close()
