import os
import socket
import time
from binascii import hexlify
from contextlib import suppress
from threading import Event, Lock
from typing import Any, Optional

import paramiko
from paramiko import RSAKey
from paramiko.common import AUTH_FAILED

from .client import BlacknetClient
from .common import (
    BLACKNET_LOG_DEBUG,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_INFO,
    BLACKNET_PING_INTERVAL,
    BLACKNET_SSH_AUTH_RETRIES,
    BLACKNET_SSH_CLIENT_TIMEOUT,
    BLACKNET_SSH_DEFAULT_BANNER,
    BLACKNET_SSH_DEFAULT_LISTEN,
    blacknet_ensure_unicode,
)
from .server import BlacknetServer, BlacknetThread


class BlacknetSSHSession(paramiko.ServerInterface):
    """SSH session to collect data from."""

    def __init__(self, transport: paramiko.Transport, blacknet: BlacknetClient) -> None:
        """Handle a new SSH attack session."""
        self.__transport = transport
        self.__client_version = None  # type: Optional[str]
        self.__peer_name = None  # type: Optional[str]
        self.__allowed_auths = ["publickey", "password"]
        self.auth_failed_count = 0
        # This needs to be a user-configured value at some point.
        self.auth_failed_limit = BLACKNET_SSH_AUTH_RETRIES
        self.blacknet = blacknet

    @property
    def peer_name(self) -> str:
        """Get the peer name."""
        if not self.__peer_name:
            peer = self.__transport.getpeername()
            self.__peer_name = peer[0]
        return self.__peer_name

    @property
    def client_version(self) -> str:
        """Get the banner from the remote attacker."""
        if not self.__client_version:
            self.__client_version = self.__transport.remote_version
        return self.__client_version

    def get_allowed_auths(self, username: str) -> str:
        """Allowed authentication methods."""
        return ",".join(self.__allowed_auths)

    def __auth_common_obj(self, username: str) -> dict[str, Any]:
        obj = {}  # type: dict[str, Any]
        obj["client"] = self.peer_name
        obj["version"] = blacknet_ensure_unicode(self.client_version)
        obj["user"] = blacknet_ensure_unicode(username)
        obj["time"] = int(time.time())
        return obj

    def __auth_failed_inc(self) -> None:
        # reset the auth_fail counter to be able to handle faster retries
        self.auth_failed_count += 1
        auth_handler = self.__transport.auth_handler
        if auth_handler is not None:
            if self.auth_failed_count >= self.auth_failed_limit:
                auth_handler.auth_fail_count = 1000
            else:
                auth_handler.auth_fail_count = 0

    def check_auth_password(self, username: str, password: str) -> int:
        """Handle a password authentication."""
        with suppress(BaseException):
            obj = self.__auth_common_obj(username)
            obj["passwd"] = blacknet_ensure_unicode(password)
            self.blacknet.send_ssh_credential(obj)

        self.__auth_failed_inc()
        return AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Handle a public key authentication."""
        # remove publickey authentication after one call.
        self.__allowed_auths.remove("publickey")

        with suppress(BaseException):
            obj = self.__auth_common_obj(username)
            obj["k64"] = key.get_base64()
            obj["ksize"] = key.get_bits()
            obj["kfp"] = hexlify(key.get_fingerprint())
            obj["ktype"] = key.get_name()
            self.blacknet.send_ssh_publickey(obj)

        self.__auth_failed_inc()
        return AUTH_FAILED


class BlacknetSensor(BlacknetServer):
    """BlacknetSensor (SSH Server) main class.

    Inherits from BlacknetServer for all the thread management
    and configuratiion parsing.
    """

    # default listening interface when no config is found.
    _default_listen = BLACKNET_SSH_DEFAULT_LISTEN

    def __init__(self, cfg_file: Optional[str] = None) -> None:
        """Create a new SSH sensor."""
        super().__init__("honeypot", cfg_file)
        self.__ssh_banner = None  # type: Optional[str]

        self.ssh_host_key = None  # type: Optional[RSAKey]
        self.ssh_host_hash = None  # type: Optional[str]
        self.__ssh_private_key_check()

        self.blacknet = BlacknetClient(self.config, self._logger)

    @property
    def ssh_banner(self) -> str:
        """SSH banner to expose to attackers."""
        if not self.__ssh_banner:
            if self.has_config("ssh_banner"):
                self.__ssh_banner = self.get_config("ssh_banner")
            else:
                self.__ssh_banner = BLACKNET_SSH_DEFAULT_BANNER
        return self.__ssh_banner

    def __ssh_private_key_check(self) -> None:
        prvfile = self.get_config("ssh_keys")
        pubfile = "%s.pub" % prvfile
        prv = None

        if not os.path.exists(prvfile):
            try:
                self.log_info("generating %s" % prvfile)
                prv = RSAKey.generate(bits=1024)
                prv.write_private_key_file(prvfile)
            except Exception as e:
                self.log_critical("error: %s" % e)
                raise

        if not os.path.exists(pubfile):
            try:
                self.log_info("generating %s" % pubfile)
                pub = RSAKey(filename=prvfile)
                with open(pubfile, "w") as f:
                    f.write(f"{pub.get_name()} {pub.get_base64()}")
            except Exception as e:
                self.log_critical("error: %s" % e)
                raise

        if not prv:
            prv = RSAKey(filename=prvfile)
        self.ssh_host_key = prv
        self.ssh_host_hash = hexlify(prv.get_fingerprint()).decode("ascii")
        self.log_info("SSH fingerprint: %s" % self.ssh_host_hash)

    def reload(self) -> None:
        """Reload server configuration."""
        super().reload()
        self.__ssh_private_key_check()
        self.blacknet.reload()

    def do_ping(self) -> None:
        """Send a ping request to the server."""
        # Send ping only on real TCP links (not local sockets).
        if not self.blacknet.server_is_sockfile:
            self.blacknet.send_ping()

    def serve(self) -> None:  # type: ignore[override]
        """Serve new connections into new threads."""
        super().serve(BlacknetSensorThread, BLACKNET_PING_INTERVAL, self.do_ping)

    def shutdown(self) -> None:
        """Close the sensor, disconnect from everything."""
        self.blacknet.disconnect()
        super().shutdown()


class BlacknetSensorThread(BlacknetThread):
    """Separate thread to handle SSH incoming connection requests."""

    def __init__(self, bns: BlacknetSensor, client: socket.socket) -> None:
        """Spawn a new sensor thread to handle a SSH client."""
        super().__init__(bns, client)

        self.started = False
        self.__connection_lock = Lock()
        self.__bns = bns

        peername = client.getpeername()
        self.__peer_ip = peername[0] if peername else "local"
        self.__client = client
        self.__transport = None  # type: Optional[paramiko.Transport]
        self.__auth_retries = 0

    def __del__(self) -> None:
        """Disconnect on thread deletion."""
        self.disconnect()

    def run(self) -> None:
        """Thread entry point."""
        self.started = True
        self.log_debug("SSH: starting session")

        t = paramiko.Transport(self.__client)
        t.local_version = self.__bns.ssh_banner
        with suppress(BaseException):
            t.load_server_moduli()
        if self.__bns.ssh_host_key is not None:
            t.add_server_key(self.__bns.ssh_host_key)
        self.__transport = t

        ssh_server = BlacknetSSHSession(t, self.__bns.blacknet)
        try:
            t.start_server(server=ssh_server, event=Event())
            t.join(BLACKNET_SSH_CLIENT_TIMEOUT)
        except Exception as e:
            self.log_debug("SSH: %s" % e)
        self.__auth_retries = ssh_server.auth_failed_count
        self.disconnect()

    def log(self, message: str, level: int = BLACKNET_LOG_DEFAULT) -> None:
        """Write something to the attached logger."""
        if self.__bns._logger:
            peername = "%s" % (self.__peer_ip)
            self.__bns._logger.write(f"{peername}: {message}", level)

    def log_info(self, message: str) -> None:
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def log_debug(self, message: str) -> None:
        """Write a debug message to the logger."""
        self.log(message, BLACKNET_LOG_DEBUG)

    def disconnect(self) -> None:
        """Disconnect from the SSH attacker."""
        with self.__connection_lock:
            if self.__transport:
                auth_retries = self.__auth_retries
                self.log_debug(f"SSH: stopping session ({auth_retries} failed retries)")
                self.__transport.close()
                self.__transport = None

            if self.__client:
                with suppress(OSError):
                    self.__client.shutdown(socket.SHUT_RDWR)
                self.__client.close()
