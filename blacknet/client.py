import select
import socket
import sys
from contextlib import suppress
from threading import Lock, RLock
from typing import Any, Optional, Union

from msgpack import Packer, Unpacker

from .common import (
    BLACKNET_CLIENT_CONN_RETRIES,
    BLACKNET_CLIENT_GOODBYE_TIMEOUT,
    BLACKNET_CLIENT_PING_TIMEOUT,
    BLACKNET_HELLO,
    BLACKNET_LOG_DEBUG,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_ERROR,
    BLACKNET_LOG_INFO,
    BLACKNET_SSL_DEFAULT_ADDRESS,
    BLACKNET_SSL_DEFAULT_PORT,
    BlacknetMsgType,
)
from .config import BlacknetConfig
from .logger import BlacknetLogger
from .sslif import BlacknetSSLInterface


class BlacknetClient(BlacknetSSLInterface):
    """Holds all the underlying protocol exchanges with BlacknetMasterServer."""

    def __init__(
        self,
        config: BlacknetConfig,
        logger: Optional[BlacknetLogger] = None,
    ) -> None:
        """Initialize a new client for blacknet."""
        super().__init__(config, "honeypot")
        self.__logger = logger
        self.__server_hostname = None  # type: Optional[str]
        self.__server_address = None  # type: Optional[Union[str, tuple[str, int]]]
        self.__server_socket = None  # type: Optional[socket.socket]
        self.__server_error = False
        self.__client_name = None  # type: Optional[str]
        self.__connect_lock = RLock()
        self.__send_lock = Lock()
        self.__packer = Packer()
        self.__unpacker = Unpacker()

    def __del__(self) -> None:
        """Ensure disconnection on delete."""
        self.disconnect()

    def log(self, message: str, level: int = BLACKNET_LOG_DEFAULT) -> None:
        """Write something to the attached logger."""
        if self.__logger:
            self.__logger.write("Honeypot: %s" % message, level)
        else:
            sys.stdout.write("%s\n" % message)
            sys.stdout.flush()

    def log_error(self, message: str) -> None:
        """Write an error message to the logger."""
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message: str) -> None:
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def log_debug(self, message: str) -> None:
        """Write a debug message to the logger."""
        self.log(message, BLACKNET_LOG_DEBUG)

    @property
    def server_hostname(self) -> Optional[str]:
        """Hostname of the blacknet server."""
        if not self.__server_hostname:
            self.__server_hostname = self.ssl_config[2]
        return self.__server_hostname

    @property
    def server_is_sockfile(self) -> bool:
        """Whether the blacknet server is a UNIX socket file."""
        if not self._server_sockfile:
            self._server_sockfile = not isinstance(self.server_address, tuple)
        return self._server_sockfile

    @property
    def server_address(self) -> Union[str, tuple[str, int]]:
        """Get the blacknet server address."""
        if self.__server_address is None:
            self.__server_address = self.__get_server_address()
        return self.__server_address

    def __get_server_address(self) -> Union[str, tuple[str, int]]:
        """Retrieve the blacknet server address and port."""
        if self.has_config("server"):
            server = self.get_config("server").strip()
        else:
            server = f"{BLACKNET_SSL_DEFAULT_ADDRESS}:{BLACKNET_SSL_DEFAULT_PORT}"

        if server.startswith("/"):
            return server

        addr = server.split(":")
        address = addr[0]
        port = BLACKNET_SSL_DEFAULT_PORT
        if len(addr) > 1:
            try:
                port = int(addr[1])
            except ValueError as e:
                self.log_error("address port: %s" % e)
        return (address, port)

    @property
    def client_name(self) -> Optional[str]:
        """Get the name of the current blacknet client."""
        if not self.__client_name and self.has_config("name"):
            self.__client_name = self.get_config("name")
        return self.__client_name

    @property
    def _server_socket(self) -> socket.socket:
        send_handshake = False

        self.__connect_lock.acquire()
        try:
            if not self.__server_socket:
                self.__server_socket = self._connect()
                send_handshake = True
                if self.__server_error:
                    self.log_info("client reconnected successfully")
                else:
                    self.log_info("client connected successfully")
                self.__server_error = False
        except:
            self.__server_error = True
            raise
        finally:
            self.__connect_lock.release()

        if send_handshake:
            self._send_handshake()
        return self.__server_socket

    def _connect(self) -> socket.socket:
        """Connect to the BlacknetMasterServer (without explicit locking)."""
        tries = BLACKNET_CLIENT_CONN_RETRIES

        while tries:
            try:
                if self.server_is_sockfile:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(self.server_address)

                # Set keep-alive parameters to automatically close connection on error.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if not self.server_is_sockfile:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
                    sock.setsockopt(
                        socket.IPPROTO_TCP,
                        socket.TCP_KEEPCNT,
                        BLACKNET_CLIENT_CONN_RETRIES,
                    )
                break
            except OSError as e:
                if tries == BLACKNET_CLIENT_CONN_RETRIES and not self.__server_error:
                    self.log_error("socket error: %s" % e)
                tries -= 1
                if not tries:
                    raise

        if not self.server_is_sockfile:
            sock = self.ssl_context.wrap_socket(sock, server_hostname=self.server_hostname)
        return sock

    def disconnect(self, goodbye: bool = True) -> None:
        """Disconnect from the blacknet server."""
        self.__connect_lock.acquire()
        if self.__server_socket:
            if goodbye:
                with suppress(BaseException):
                    self._send_goodbye()
                    self._recv_goodbye()

            with suppress(OSError):
                self.__server_socket.shutdown(socket.SHUT_RDWR)

            self.__server_socket.close()
            self.__server_socket = None
        self.__connect_lock.release()

    def reload(self) -> None:
        """Reload client configuration."""
        super().reload()
        self.__client_name = None
        self.__server_hostname = None

        new_server_address = self.__get_server_address()
        if self.__server_address and self.__server_address != new_server_address:
            self.__server_address = new_server_address
            self.disconnect()

    def _recv_goodbye(self) -> None:
        try:
            sock = self._server_socket
            acceptable = select.select([sock], [], [], BLACKNET_CLIENT_GOODBYE_TIMEOUT)
            if acceptable[0]:
                buf = self._server_socket.recv(4096)
                self.__unpacker.feed(buf)

                for msgtype, _data in self.__unpacker:
                    # This is the only message type we can receive here.
                    if msgtype == BlacknetMsgType.GOODBYE:
                        self.log_debug("client received goodbye acknowledgement.")
            else:
                self.log_info("client did not receive goodbye from server, quitting.")
        except Exception as e:
            self.log_error("goodbye error: %s" % e)

    def _send(self, msgtype: int, message: Any = None) -> None:
        data = [msgtype, message]
        sock = self._server_socket

        pdata = self.__packer.pack(data)
        plen = len(pdata)

        # Ensure that all data is sent properly.
        while plen > 0:
            sent = sock.send(pdata)
            plen -= sent
            pdata = pdata[sent:]

    def _send_handshake(self) -> None:
        self._send(BlacknetMsgType.HELLO, BLACKNET_HELLO)
        if self.client_name:
            self._send(BlacknetMsgType.CLIENT_NAME, self.client_name)

    def _send_goodbye(self) -> None:
        self._send(BlacknetMsgType.GOODBYE)

    def _send_retry(self, msgtype: int, message: Any, tries: int = 2) -> None:
        while tries > 0:
            self.__send_lock.acquire()
            try:
                self._send(msgtype, message)
                tries = 0
            except Exception:
                self.disconnect(goodbye=False)
                tries -= 1
            finally:
                self.__send_lock.release()

    def send_ssh_credential(self, data: dict[str, Any]) -> None:
        """Send SSH credentials to the blacknet server."""
        self._send_retry(BlacknetMsgType.SSH_CREDENTIAL, data)

    def send_ssh_publickey(self, data: dict[str, Any]) -> None:
        """Send SSH public key to the blacknet server."""
        self._send_retry(BlacknetMsgType.SSH_PUBLICKEY, data)

    def send_ping(self) -> None:
        """Send a keep-alive probe to the server."""
        answered = False

        self.__send_lock.acquire()
        try:
            self._send(BlacknetMsgType.PING)

            sock = self._server_socket
            acceptable = select.select([sock], [], [], BLACKNET_CLIENT_PING_TIMEOUT)
            if acceptable[0]:
                buf = self._server_socket.recv(4096)
                self.__unpacker.feed(buf)

                for msgtype, _data in self.__unpacker:
                    # This is the only message type we can receive here.
                    if msgtype == BlacknetMsgType.PONG:
                        self.log_debug("client received pong acknowledgement.")
                        answered = True
            else:
                self.log_info("client did not receive pong from server, disconnecting.")
        except Exception as e:
            self.log_error("pong error: %s" % e)
        if not answered:
            self.disconnect(goodbye=False)
        self.__send_lock.release()
