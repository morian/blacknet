import msgpack
import socket
import sys

from threading import Lock
from ssl_interface import BlacknetSSLInterface
from common import *


class BlacknetClient(BlacknetSSLInterface):
    """ Holds all the underlying protocol exchanges with BlacknetMainServer. """


    def __init__(self, config, logger=None):
        BlacknetSSLInterface.__init__(self, config, 'honeypot')
        self.__logger = logger
        self.__server_hostname = None
        self.__server_address = None
        self.__server_socket = None
        self.__server_error = False
        self.__client_name = None
        self.__connect_lock = Lock()
        self.__send_lock = Lock()
        self.__packer = msgpack.Packer()


    def __del__(self):
        self.disconnect()


    def log(self, message):
        if self.__logger:
            self.__logger.write("Honeypot: %s" % message)
        else:
            sys.stdout.write("%s\n" % message)
            sys.stdout.flush()


    @property
    def server_hostname(self):
        if not self.__server_hostname:
            self.__server_hostname = self.ssl_config[2]
        return self.__server_hostname


    @property
    def server_is_sockfile(self):
        if not self._server_sockfile:
            self._server_sockfile = (type(self.server_address) is str)
        return self._server_sockfile


    @property
    def server_address(self):
        if not self.__server_address:
            self.__server_address = self.__get_server_address()
        return self.__server_address


    def __get_server_address(self):
        if self.has_config('server'):
            server = self.get_config('server').strip()
        else:
            server = "%s:%s" % (BLACKNET_SSL_DEFAULT_ADDRESS, BLACKNET_SSL_DEFAULT_PORT)

        if server.startswith('/'):
            return server

        addr = server.split(':')
        address = addr[0]
        port = BLACKNET_SSL_DEFAULT_PORT
        if len(addr) > 1:
            try:
                port = int(addr[1])
            except ValueError as e:
                self.log("ValueError: %s" % e)
        return (address, port)


    @property
    def client_name(self):
        if not self.__client_name and self.has_config('name'):
            self.__client_name = self.get_config('name')
        return self.__client_name


    @property
    def _server_socket(self):
        send_handshake = False

        self.__connect_lock.acquire()
        try:
            if not self.__server_socket:
                self.__server_socket = self._connect()
                send_handshake = True
                if self.__server_error:
                    self.log("Reconnected successfully")
                    self.__server_error = False
        except:
            self.__server_error = True
            raise
        finally:
            self.__connect_lock.release()

        if send_handshake:
            self._send_handshake()
        return self.__server_socket


    def _connect(self):
        """ Connect to the BlacknetMainServer (without explicit locking) """

        tries = BLACKNET_CLIENT_CONN_RETRIES

        while tries:
            try:
                if self.server_is_sockfile:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(self.server_address)
                break
            except socket.error as e:
                if tries == BLACKNET_CLIENT_CONN_RETRIES and not self.__server_error:
                    self.log("%s" % e)
                tries -= 1
                if not tries:
                    raise

        if not self.server_is_sockfile:
            sock = self.ssl_context.wrap_socket(sock, server_hostname=self.server_hostname)
        return sock


    def disconnect(self):
        self.__connect_lock.acquire()
        if self.__server_socket:
            try:
                self.__server_socket.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                pass
            self.__server_socket.close()
            self.__server_socket = None
            self.__server_error = False
        self.__connect_lock.release()


    def reload(self):
        super(BlacknetClient, self).reload()
        self.__client_name = None
        self.__server_hostname = None

        new_server_address = self.__get_server_address()
        if self.__server_address and self.__server_address != new_server_address:
            self.__server_address = new_server_address
            self.disconnect()


    def _send(self, msgtype, message):
        data = [msgtype, message]
        self._server_socket.send(self.__packer.pack(data))


    def _send_handshake(self):
        self._send(BlacknetMsgType.HELLO, BLACKNET_HELLO)
        if self.client_name:
            self._send(BlacknetMsgType.CLIENT_NAME, self.client_name)


    def _send_retry(self, msgtype, message, tries=2):
        while tries:
            self.__send_lock.acquire()
            try:
                self._send(msgtype, message)
                tries = 0
            except socket.error as e:
                self.disconnect()
                tries -= 1
            finally:
                self.__send_lock.release()


    def send_ssh_credential(self, data):
        self._send_retry(BlacknetMsgType.SSH_CREDENTIAL, data)


    def send_ssh_publickey(self, data):
        self._send_retry(BlacknetMsgType.SSH_PUBLICKEY, data)
