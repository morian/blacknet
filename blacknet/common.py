import os
import socket
import struct
from contextlib import suppress
from typing import Union


# Blacknet Message Types between server and client.
class BlacknetMsgType:
    """Message opcodes used in client/server communication."""

    HELLO = 0
    CLIENT_NAME = 1
    SSH_CREDENTIAL = 2
    SSH_PUBLICKEY = 3
    PING = 10
    PONG = 11
    GOODBYE = 16


# General directories to look for configuration files.
BLACKNET_CONFIG_DIRS = ["/etc/blacknet", os.path.expanduser("~/.blacknet")]
# General directories to look for blacklist files.
BLACKNET_BLACKLIST_DIRS = ["/etc/blacknet", os.path.expanduser("~/.blacknet")]


# Log levels
BLACKNET_LOG_EMERG = 0
BLACKNET_LOG_ALERT = 1
BLACKNET_LOG_CRITICAL = 2
BLACKNET_LOG_ERROR = 3
BLACKNET_LOG_WARNING = 4
BLACKNET_LOG_NOTICE = 5
BLACKNET_LOG_INFO = 6
BLACKNET_LOG_DEBUG = 7

# Both default log level when configuration is missing
# and log level when writing log messages with no level specified.
BLACKNET_LOG_DEFAULT = BLACKNET_LOG_INFO


# This is the content of the HELLO string the client is supposed to send
# to the server instance.
BLACKNET_HELLO = "CPE1704TKS"

# Default listening / connection interface for SSL server (blacknet server)
# in configuration file.
BLACKNET_SSL_DEFAULT_ADDRESS = "127.0.0.1"
BLACKNET_SSL_DEFAULT_PORT = 10443
BLACKNET_SSL_DEFAULT_LISTEN = f"{BLACKNET_SSL_DEFAULT_ADDRESS}:{BLACKNET_SSL_DEFAULT_PORT}"
# Default session interval is set to 1 hour.
BLACKNET_DEFAULT_SESSION_INTERVAL = 3600

# Default listening / connection interface for SSH server (blacknet client)
BLACKNET_SSH_DEFAULT_ADDRESS = "0.0.0.0"
BLACKNET_SSH_DEFAULT_PORT = 2200
BLACKNET_SSH_DEFAULT_LISTEN = f"{BLACKNET_SSH_DEFAULT_ADDRESS}:{BLACKNET_SSH_DEFAULT_PORT}"
BLACKNET_SSH_DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
BLACKNET_SSH_AUTH_RETRIES = 42  # Max. number of auth retries before disconnecting.

# SSH client maximum socket duration
BLACKNET_SSH_CLIENT_TIMEOUT = 20 * BLACKNET_SSH_AUTH_RETRIES

# Used in select timeout to ping server regularly (5mn here).
BLACKNET_PING_INTERVAL = 5 * 60

# How many times to wait for close acknowledgement.
BLACKNET_CLIENT_GOODBYE_TIMEOUT = 5.0
BLACKNET_CLIENT_PING_TIMEOUT = 3.0
BLACKNET_CLIENT_CONN_RETRIES = 3
BLACKNET_DATABASE_RETRIES = 2
# Stands for "Other country" in geolite-city database.
BLACKNET_DEFAULT_LOCID = 1


# This is the actual list of supported ciphers for SSL
# communications between server and client.
BLACKNET_CIPHERS = [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES256-SHA256",
    "AES256-GCM-SHA384",
]


def blacknet_ensure_unicode(message: Union[str, bytes]) -> str:
    """Ensure a unicode string as output."""

    def blacknet_decode(message: bytes) -> str:
        data = None
        for encoding in ("utf-8", "latin1"):
            try:
                return message.decode(encoding)
            except UnicodeDecodeError:
                pass  # Unicode error
        if not data:
            data = message.decode("utf-8", "ignore")
        return data

    if isinstance(message, bytes):
        return blacknet_decode(message)

    return message


def blacknet_ip_to_int(arg: str) -> int:
    """Convert an IP address to its equivalent integer."""
    return struct.unpack("!I", socket.inet_aton(arg))[0]


def blacknet_int_to_ip(arg: int) -> str:
    """Convert an integer to its corresponding IP address."""
    return socket.inet_ntoa(struct.pack("!I", arg))


def blacknet_gethostbyaddr(ip: str) -> str:
    """Try to perform a reverse DNS lookup."""
    with suppress(BaseException):
        return socket.gethostbyaddr(ip)[0]
    return ""
