from __future__ import annotations

import socket
from contextlib import suppress
from ssl import SSLSocket
from threading import Lock
from typing import Any, Callable

from msgpack import Packer, Unpacker
from pymysql import MySQLError

from .common import (
    BLACKNET_DATABASE_RETRIES,
    BLACKNET_DEFAULT_LOCID,
    BLACKNET_DEFAULT_SESSION_INTERVAL,
    BLACKNET_HELLO,
    BLACKNET_LOG_DEBUG,
    BLACKNET_LOG_DEFAULT,
    BLACKNET_LOG_ERROR,
    BLACKNET_LOG_INFO,
    BLACKNET_LOG_WARNING,
    BlacknetMsgType,
    blacknet_gethostbyaddr,
    blacknet_ip_to_int,
)
from .config import BlacknetBlacklist
from .database import BlacknetDatabase, BlacknetDatabaseCursor
from .server import BlacknetServer, BlacknetThread
from .sslif import BlacknetSSLInterface


class BlacknetMasterServer(BlacknetServer, BlacknetSSLInterface):
    """Main blackNet server class."""

    def __init__(self, cfg_file: str | None = None) -> None:
        """Instanciate a new blacknet server."""
        BlacknetServer.__init__(self, "server", cfg_file)
        BlacknetSSLInterface.__init__(self, self.config, "server")

        self.__test_mode = None  # type: bool | None
        self.__session_interval = None  # type: int | None
        self.blacklist = BlacknetBlacklist(self.config)

    @property
    def session_interval(self) -> int:
        """Currently configuration session interval."""
        if not self.__session_interval:
            if self.has_config("session_interval"):
                self.__session_interval = int(self.get_config("session_interval"))
            else:
                self.__session_interval = BLACKNET_DEFAULT_SESSION_INTERVAL
        return self.__session_interval

    @property
    def test_mode(self) -> bool:
        """Whether we are currently running in test mode."""
        if self.__test_mode is None:
            if self.has_config("test_mode"):
                self.__test_mode = bool(self.get_config("test_mode"))
            else:
                self.__test_mode = False
        return self.__test_mode

    def reload(self) -> None:
        """Reload server configuration."""
        super().reload()
        self.__test_mode = None
        self.__session_interval = None
        self.blacklist.reload()

        # Reload database information.
        for thr in self._threads:
            if isinstance(thr, BlacknetServerThread):
                thr.database.reload()

    def serve(self) -> None:  # type: ignore[override]
        """Serve new connections into new threads."""
        super().serve(BlacknetServerThread)

    def shutdown(self) -> None:
        """Shutdown the server."""
        super().shutdown()


class BlacknetServerThread(BlacknetThread):
    """Server thread handling blacknet client connections."""

    def __init__(self, bns: BlacknetMasterServer, client: socket.socket) -> None:
        """Initialize a new thread for a new client connection."""
        super().__init__(bns, client)

        handler: dict[int, Callable[[Any], bool]] = {
            BlacknetMsgType.HELLO: self.handle_hello,
            BlacknetMsgType.CLIENT_NAME: self.handle_client_name,
            BlacknetMsgType.SSH_CREDENTIAL: self.handle_ssh_credential,
            BlacknetMsgType.SSH_PUBLICKEY: self.handle_ssh_publickey,
            BlacknetMsgType.PING: self.handle_ping,
            BlacknetMsgType.GOODBYE: self.handle_goodbye,
        }
        self.handler = handler
        self.started = False

        self.database = BlacknetDatabase(bns.config, bns.logger)
        self.__blacklist = bns.blacklist
        self.__client = None  # type: socket.socket | None
        self.__connect_lock = Lock()
        self.__cursor = None  # type: BlacknetDatabaseCursor | None
        self.__logger = bns.logger
        self.__mysql_error = 0
        self.__session_interval = bns.session_interval
        self.__unpacker = Unpacker()
        self.__packer = Packer()
        self.__dropped_count = 0
        self.__attempt_count = 0
        self.__atk_cache = {}  # type: dict[int, tuple[int, int]]
        self.__ses_cache = {}  # type: dict[int, tuple[int, int]]
        self.__key_cache = {}  # type: dict[str, int]
        self.__test_mode = bns.test_mode

        peer = client.getpeername()
        self.__peer_ip = peer[0] if peer else "local"
        self.__use_ssl = client.family != socket.AF_UNIX

        client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if self.__use_ssl:
            client = bns.ssl_context.wrap_socket(client, server_side=True)
        self.__client = client

        self.name = self.peername
        self.log_info("starting session (SSL: %s)" % self.__use_ssl)

    def __del__(self) -> None:
        """Close everything when deleted."""
        self.disconnect()
        self.database.disconnect()

    def disconnect(self) -> None:
        """Disconnect from the client."""
        self.__connect_lock.acquire()
        if self.__client:
            self.log_info("stopping session")
            with suppress(OSError):
                self.__client.shutdown(socket.SHUT_RDWR)
            self.__client.close()
            self.__client = None
        self.__connect_lock.release()

    @property
    def peername(self) -> str:
        """Name of the remote sensor (SSL peer)."""
        name = "unknown"
        client = self.__client
        if isinstance(client, SSLSocket):
            cert = client.getpeercert()
            if cert and "subject" in cert:
                for item in cert["subject"]:
                    if item[0][0] == "commonName":
                        name = item[0][1]
        return name

    def handle_sensor(self, client: socket.socket) -> None:
        """Run the sensor main handler loop."""
        running = True

        while running:
            try:
                buf = client.recv(8192)
            except OSError as e:
                self.log_warning("socket error: %s" % e)
                break

            if not buf:
                break
            self.__unpacker.feed(buf)

            for msgtype, data in self.__unpacker:
                if msgtype in self.handler:
                    running = self.handler[msgtype](data)
                else:
                    self.handle_unknown(msgtype, data)
            self.database.commit()
        self.disconnect()

    def run(self) -> None:
        """Thread entry point for the current client."""
        self.started = True

        client = self.__client
        if client is not None:
            try:
                self.handle_sensor(client)
            except Exception as e:
                self.log_warning("sensor exception: %s" % e)

    @property
    def cursor(self) -> BlacknetDatabaseCursor:
        """Get the current database cursor."""
        if not self.__cursor:
            cursor = self.database.cursor()
            self.__cursor = cursor
        return self.__cursor

    def log(self, message: str, level: int = BLACKNET_LOG_DEFAULT) -> None:
        """Write something to the attached logger."""
        if self.__logger:
            peername = f"{self.name} ({self.__peer_ip})"
            self.__logger.write(f"{peername}: {message}", level)

    def log_error(self, message: str) -> None:
        """Write an error message to the logger."""
        self.log(message, BLACKNET_LOG_ERROR)

    def log_warning(self, message: str) -> None:
        """Write a warning message to the logger."""
        self.log(message, BLACKNET_LOG_WARNING)

    def log_info(self, message: str) -> None:
        """Write an informational message to the logger."""
        self.log(message, BLACKNET_LOG_INFO)

    def log_debug(self, message: str) -> None:
        """Write a debug message to the logger."""
        self.log(message, BLACKNET_LOG_DEBUG)

    def __mysql_retry(self, function: Callable[..., Any], *args: Any) -> Any:
        """Wrap a function to retry on MySQL error."""
        saved_exception = None  # type: BaseException | None

        for _retry in range(BLACKNET_DATABASE_RETRIES):
            try:
                res = function(*args)
                self.__mysql_error = 0
                return res
            except MySQLError as e:
                if self.__mysql_error != e.args[0]:
                    self.__mysql_error = e.args[0]
                    self.log_warning("MySQL: %s" % e)

                self.__cursor = None
                self.database.disconnect()
                saved_exception = e

        if isinstance(saved_exception, BaseException):
            raise saved_exception
        return None

    ## -- Message handling functions -- ##
    def handle_unknown(self, msgtype: BlacknetMsgType, data: bytes) -> None:
        """Handle an unknown message type."""
        self.log_error(f"unknown msgtype {msgtype}")

    def handle_hello(self, data: Any) -> bool:
        """Handle a hello packet."""
        if not isinstance(data, str):
            self.log_error("bad payload type received in HELLO.")
            return False

        if data != BLACKNET_HELLO:
            self.log_error(
                f"client reported buggy hello (got {data}, expected {BLACKNET_HELLO})"
            )
            return False
        return True

    def handle_ping(self, data: Any) -> bool:
        """Handle a ping request from the client."""
        client = self.__client
        if client:
            self.log_debug("responding to ping request.")
            output = [BlacknetMsgType.PONG, None]
            client.send(self.__packer.pack(output))
        return True

    def handle_goodbye(self, data: Any) -> bool:
        """Handle a goodbye request from the client."""
        client = self.__client
        if client:
            output = [BlacknetMsgType.GOODBYE, None]
            client.send(self.__packer.pack(output))
        return False

    def handle_client_name(self, data: Any) -> bool:
        """Client is telling us its name."""
        if not isinstance(data, str):
            self.log_error("bad payload type received in CLIENT_NAME.")
            return False

        if data != self.name:
            self.log_info("changing client name to %s" % data)
            self.name = data
        return True

    def __add_ssh_attacker(self, data: dict[str, Any]) -> int:
        cursor = self.cursor

        ip = data["client"]
        time = data["time"]
        atk_id = blacknet_ip_to_int(ip)

        if atk_id not in self.__atk_cache:
            res = cursor.check_attacker(atk_id)
            if res is None:
                locid = cursor.get_locid(atk_id)
                if locid == BLACKNET_DEFAULT_LOCID:
                    self.log_info("no gelocation for client %s" % ip)
                dns = blacknet_gethostbyaddr(ip)
                args = (atk_id, ip, dns, time, time, locid, 0)
                cursor.insert_attacker(args)
                first_seen, last_seen = (time, time)
            else:
                first_seen, last_seen = res
            self.__atk_cache[atk_id] = (first_seen, last_seen)
        else:
            first_seen, last_seen = self.__atk_cache[atk_id]

        # Check attacker dates to update first_seen and last_seen fields.
        if first_seen and time < first_seen:
            self.__atk_cache[atk_id] = (time, last_seen)
            cursor.update_attacker_first_seen(atk_id, time)

        if last_seen and time > last_seen:
            self.__atk_cache[atk_id] = (first_seen, time)
            cursor.update_attacker_last_seen(atk_id, time)

        return atk_id

    def __add_ssh_session(self, data: dict[str, Any], atk_id: int) -> int:
        cursor = self.cursor
        sensor = self.name
        time = data["time"]

        if atk_id not in self.__ses_cache:
            res = cursor.check_session(atk_id, sensor)
            if res is None:
                ses_id, last_seen = (0, 0)
            else:
                ses_id, last_seen = res
        else:
            ses_id, last_seen = self.__ses_cache[atk_id]

        session_limit = last_seen + self.__session_interval
        if time > session_limit:
            args = (atk_id, time, time, sensor)
            ses_id = cursor.insert_session(args)
        else:
            cursor.update_session_last_seen(ses_id, time)
        self.__ses_cache[atk_id] = (ses_id, time)

        return ses_id

    def __add_ssh_attempt(self, data: dict[str, Any], atk_id: int, ses_id: int) -> int:
        cursor = self.cursor
        # This happen while registering a pubkey authentication
        password = data.get("passwd")
        args = (
            atk_id,
            ses_id,
            data["user"],
            password,
            self.name,
            data["time"],
            data["version"],
        )
        return cursor.insert_attempt(args)

    def __add_ssh_pubkey(self, data: dict[str, Any], att_id: int) -> int:
        cursor = self.cursor
        fingerprint = data["kfp"]

        if fingerprint not in self.__key_cache:
            res = cursor.check_pubkey(fingerprint)
            if res is None:
                args = (data["ktype"], data["kfp"], data["k64"], data["ksize"])
                key_id = cursor.insert_pubkey(args)
            else:
                key_id = res
            self.__key_cache[fingerprint] = key_id
        else:
            key_id = self.__key_cache[fingerprint]

        cursor.insert_attempts_pubkeys(att_id, key_id)
        return key_id

    def check_blacklist(self, data: dict[str, str]) -> None:
        """Check provided data against the configured blacklist."""
        user = data["user"]
        if self.__blacklist.has(self.peername, user):
            client = data["client"]
            version = data["version"]
            msg = f"blacklisted user {user} from {client} using {version}"
            self.log_info(msg)
            raise Exception(msg)

    def __handle_ssh_common(self, data: dict[str, str]) -> tuple[int, int, int]:
        if self.__test_mode:
            data["client"] = "1.0.204.42"

        self.check_blacklist(data)
        atk_id = self.__mysql_retry(self.__add_ssh_attacker, data)
        ses_id = self.__mysql_retry(self.__add_ssh_session, data, atk_id)
        att_id = self.__mysql_retry(self.__add_ssh_attempt, data, atk_id, ses_id)
        return (atk_id, ses_id, att_id)

    def handle_ssh_credential(self, data: dict[str, Any]) -> bool:
        """Handle received SSH credentials."""
        try:
            atk_id, ses_id, att_id = self.__handle_ssh_common(data)
        except Exception as e:
            self.log_info("credential error: %s" % e)
            self.__dropped_count += 1
        else:
            self.__attempt_count += 1
        return True

    def handle_ssh_publickey(self, data: dict[str, Any]) -> bool:
        """Handle received SSH public key."""
        try:
            atk_id, ses_id, att_id = self.__handle_ssh_common(data)
            self.__mysql_retry(self.__add_ssh_pubkey, data, att_id)
        except Exception as e:
            self.log_info("pubkey error: %s" % e)
            self.__dropped_count += 1
        else:
            self.__attempt_count += 1
        return True
