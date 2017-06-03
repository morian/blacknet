import os
import socket
import struct
import sys

# Python 2 / 3 checks
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


# Blacknet Message Types between server and client.
class BlacknetMsgType:
    HELLO          =  0
    CLIENT_NAME    =  1
    SSH_CREDENTIAL =  2
    SSH_PUBLICKEY  =  3
    GOODBYE        = 16

# General directories to look for configuration files.
BLACKNET_CONFIG_DIRS = ["/etc/blacknet", os.path.expanduser("~/.blacknet")]
# General directories to look for blacklist files.
BLACKNET_BLACKLIST_DIRS = ["/etc/blacknet", os.path.expanduser("~/.blacknet")]

# This is the content of the HELLO string the client is supposed to send
# to the server instance.
BLACKNET_HELLO = 'CPE1704TKS'

# Default listening / connection interface for SSL server (blacknet server)
# in configuration file.
BLACKNET_SSL_DEFAULT_ADDRESS = '127.0.0.1'
BLACKNET_SSL_DEFAULT_PORT = 10443
BLACKNET_SSL_DEFAULT_LISTEN = "%s:%u" % (BLACKNET_SSL_DEFAULT_ADDRESS, BLACKNET_SSL_DEFAULT_PORT)
# Default session interval is set to 1 hour.
BLACKNET_DEFAULT_SESSION_INTERVAL = 3600

# Default listening / connection interface for SSH server (blacknet client)
BLACKNET_SSH_DEFAULT_ADDRESS = '0.0.0.0'
BLACKNET_SSH_DEFAULT_PORT = 2200
BLACKNET_SSH_DEFAULT_LISTEN = "%s:%u" % (BLACKNET_SSH_DEFAULT_ADDRESS, BLACKNET_SSH_DEFAULT_PORT)
BLACKNET_SSH_DEFAULT_BANNER = 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3'

# How many times to wait for close acknowledgement.
BLACKNET_CLIENT_GOODBYE_TIMEOUT = 5.0
BLACKNET_CLIENT_CONN_RETRIES = 3
BLACKNET_DATABASE_RETRIES = 2


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
]

def blacknet_ensure_unicode(message):
    if PY2 and isinstance(message, str):
        message = message.decode('utf-8')
    return message

def blacknet_ip_to_int(arg):
    return struct.unpack("!I", socket.inet_aton(arg))[0]

def blacknet_int_to_ip(arg):
    return socket.inet_ntoa(struct.pack("!I", arg))

def blacknet_gethostbyaddr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        pass
    return ''
