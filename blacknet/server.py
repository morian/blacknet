import errno
import grp
import os
import pwd
import select
import socket

from threading import Thread

from .config import BlacknetConfig, BlacknetConfigurationInterface
from .logger import BlacknetLogger
from .common import *


# Backward compatibility
try:
    InterruptedError = InterruptedError
except:
    InterruptedError = OSError



class BlacknetServer(BlacknetConfigurationInterface):
    """ Blacknet TCP Server Instance (used for both SSH server and SSL server) """

    # default listening interface when no config is found.
    _default_listen = BLACKNET_SSL_DEFAULT_LISTEN


    def __init__(self, role, cfg_file=None):
        self.__listen_interfaces = None
        self.__socket_permissions = None

        self._interfaces = {}
        self._threads = []
        self._logger = None

        config = BlacknetConfig()
        config.load(cfg_file)

        BlacknetConfigurationInterface.__init__(self, config, role)

        self._logger = BlacknetLogger(role, config)
        self.log_info("== %s is starting" % self.__class__.__name__)

        self._listen_start_stop()


    @property
    def socket_permissions(self):
        if self.__socket_permissions is None:
            owner, group, mode = (None, None, None)

            if self.has_config('listen_owner'):
                owner = self.get_config('listen_owner')
            if self.has_config('listen_group'):
                group = self.get_config('listen_group')
            if self.has_config('listen_mode'):
                try:
                    mode_string = self.get_config('listen_mode')
                    mode = int(mode_string, 8)
                except ValueError as e:
                    self.log_error("socket mode: %s" % e)
            self.__socket_permissions = (owner, group, mode)
        return self.__socket_permissions


    @property
    def listen_interfaces(self):
        if self.__listen_interfaces is None:
            listen_string = self._default_listen
            listen = []

            if self.has_config('listen'):
                listen_string = self.get_config('listen')

            for interface in listen_string.split(','):
                interface = interface.strip()
                if interface.startswith('/'):
                    listen.append(interface)
                else:
                    addr = interface.split(':')
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


    def log(self, message, level=BLACKNET_LOG_DEFAULT):
        if self._logger:
            self._logger.write(message, level)

    def log_critical(self, message):
        self.log(message, BLACKNET_LOG_CRITICAL)

    def log_error(self, message):
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message):
        self.log(message, BLACKNET_LOG_INFO)

    def log_debug(self, message):
        self.log(message, BLACKNET_LOG_DEBUG)

    def reload(self):
        """ reload instance configuration """

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
            if isinstance(itf, str) and (itf in current_interfaces):
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
            unix_socket = (sock.family == socket.AF_UNIX)
            name = interface if unix_socket else "%s:%u" % interface

            self.log_info("stopping interface %s" % name)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

            if unix_socket:
                os.remove(interface)


    def _permissions_apply(self, filepath):
        (owner, group, mode) = self.socket_permissions
        if owner or group:
            uid = os.getuid()
            gid = os.getgid()

            if owner:
                uid = pwd.getpwnam(owner).pw_uid
            if group:
                gid = pwd.getgrnam(group).gr_gid
            os.chown(filepath, uid, gid)
        if mode:
            os.chmod(filepath, mode)


    def _threads_cleanup(self):
        for thr in self._threads:
            if not thr.is_alive():
                thr.join()
                self._threads.remove(thr)


    def _threads_killer(self):
        for thr in self._threads:
            if thr.is_alive():
                thr.disconnect()
            thr.join()
            self._threads.remove(thr)


    def serve(self, threadclass=Thread):
        """ serve new connections into new threads """

        self._threads_cleanup()

        sockets = self._interfaces.values()
        try:
            acceptable = select.select(sockets, [], [])[0]
            for sock in acceptable:
                client, address = sock.accept()
                t = threadclass(self, client)
                self._threads.append(t)
                t.start()
        except InterruptedError:
            pass
        except socket.error as e:
            if e.errno != errno.EINTR:
                self.log_error("socket error: %s" % e)
            raise
        except select.error as e:
            error = e.args[0]
            if error != errno.EINTR:
                self.log_error("select error: %s" % e)
        except Exception as e:
            self.log_error("error: %s" % e)


    def shutdown(self):
        # Force expected interfaces to be an empty list.
        self.__listen_interfaces = []
        self._listen_start_stop()
        self._threads_killer()
        self.log_info("== %s stopped" % self.__class__.__name__)
        self._logger.close()
