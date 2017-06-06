import msgpack
import os
import paramiko
import socket
import sys
import time

from threading import Lock, Thread
from binascii import hexlify
from paramiko import RSAKey, ECDSAKey
from paramiko.ssh_exception import SSHException
from paramiko.common import AUTH_FAILED

from .client import BlacknetClient
from .server import BlacknetServer
from .common import *


class BlacknetSSHSession(paramiko.ServerInterface):
    """ SSH session to collect data from """

    def __init__(self, transport, blacknet):
        self.__transport = transport
        self.__client_version = None
        self.__peer_name = None
        self.__allowed_auths = ['publickey', 'password']
        self.blacknet = blacknet


    @property
    def peer_name(self):
        if not self.__peer_name:
            peer = self.__transport.getpeername()
            self.__peer_name = peer[0]
        return self.__peer_name

    @property
    def client_version(self):
        if not self.__client_version:
            self.__client_version = self.__transport.remote_version
        return self.__client_version


    def get_allowed_auths(self, username):
        return ','.join(self.__allowed_auths)


    def __auth_common_obj(self, username):
        obj = {}
        obj['client'] = self.peer_name
        obj['version'] = blacknet_ensure_unicode(self.client_version)
        obj['user'] = blacknet_ensure_unicode(username)
        obj['time'] = int(time.time())
        return obj


    def check_auth_password(self, username, password):
        # reset the auth_fail counter to be able to handle faster retries
        self.__transport.auth_handler.auth_fail_count = 0

        try:
            obj = self.__auth_common_obj(username)
            obj['passwd'] = blacknet_ensure_unicode(password)
            self.blacknet.send_ssh_credential(obj)
        except:
            pass

        return AUTH_FAILED


    def check_auth_publickey(self, username, key):
        # remove publickey authentication after one call.
        self.__allowed_auths.remove('publickey')

        try:
            obj = self.__auth_common_obj(username)
            obj['k64'] = key.get_base64()
            obj['ksize'] = key.get_bits()
            obj['kfp'] = hexlify(key.get_fingerprint())
            obj['ktype'] = key.get_name()
            self.blacknet.send_ssh_publickey(obj)
        except:
            pass

        return AUTH_FAILED


class BlacknetSensor(BlacknetServer):
    """
    BlacknetSensor (SSH Server) main class.
    Inherits from BlacknetServer for all the thread management
    and configuratiion parsing.
    """

    # default listening interface when no config is found.
    _default_listen = BLACKNET_SSH_DEFAULT_LISTEN


    def __init__(self, cfg_file=None):
        super(BlacknetSensor, self).__init__('honeypot', cfg_file)
        self.__ssh_banner = None

        self.ssh_host_key = None
        self.ssh_host_hash = None
        self.__ssh_private_key_check()

        self.blacknet = BlacknetClient(self.config, self._logger)


    @property
    def ssh_banner(self):
        if not self.__ssh_banner:
            if self.has_config('ssh_banner'):
                self.__ssh_banner = self.get_config('ssh_banner')
            else:
                self.__ssh_banner = BLACKNET_SSH_DEFAULT_BANNER
        return self.__ssh_banner


    def __ssh_private_key_check(self):
        prvfile = self.get_config('ssh_keys')
        pubfile = "%s.pub" % prvfile
        prv = None

        if not os.path.exists(prvfile):
            try:
                self.log("generating %s" % prvfile, BLACKNET_LOG_DEFAULT)
                prv = RSAKey.generate(bits=1024)
                prv.write_private_key_file(prvfile)
            except Exception as e:
                self.log("error: %s" % e, BLACKNET_LOG_CRITICAL)
                raise

        if not os.path.exists(pubfile):
            try:
                self.log("generating %s" % pubfile, BLACKNET_LOG_DEFAULT)
                pub = RSAKey(filename=prvfile)
                with open(pubfile, 'w') as f:
                    f.write("%s %s" % (pub.get_name(), pub.get_base64()))
            except Exception as e:
                self.log("error: %s" % e, BLACKNET_LOG_CRITICAL)
                raise

        if not prv:
            prv = RSAKey(filename=prvfile)
        self.ssh_host_key = prv
        self.ssh_host_hash = paramiko.py3compat.u(hexlify(prv.get_fingerprint()))
        self.log("SSH fingerprint: %s" % self.ssh_host_hash, BLACKNET_LOG_INFO)


    def reload(self):
        """ reload server configuration """

        super(BlacknetSensor, self).reload()
        self.__ssh_private_key_check()
        self.blacknet.reload()


    def serve(self):
        """ serve new connections into new threads """
        super(BlacknetSensor, self).serve(BlacknetSensorThread)


    def shutdown(self):
        self.blacknet.disconnect()
        super(BlacknetSensor, self).shutdown()


class BlacknetSensorThread(Thread):
    """ Separate thread to handle SSH incoming connection requests. """


    def __init__(self, bns, client):
        super(BlacknetSensorThread, self).__init__()
        self.__connection_lock = Lock()
        self.__bns = bns

        peername = client.getpeername()
        self.__peer_ip = peername[0] if peername else "local"
        self.__client = client
        self.__transport = None


    def __del__(self):
        self.disconnect()


    def run(self):
        self.log("SSH: starting session", BLACKNET_LOG_DEBUG)

        self.__client.settimeout(BLACKNET_SSH_CLIENT_TIMEOUT)

        t = paramiko.Transport(self.__client)
        t.local_version = self.__bns.ssh_banner
        try:
            t.load_server_moduli()
        except:
            pass
        t.add_server_key(self.__bns.ssh_host_key)
        self.__transport = t

        ssh_serv = BlacknetSSHSession(t, self.__bns.blacknet)
        try:
            t.start_server(server=ssh_serv)
            t.join()
        except Exception as e:
            # Clients can mess a log here, make sure to consider these as debug.
            self.log("SSH: %s" % e, BLACKNET_LOG_DEBUG)
        self.disconnect()


    def log(self, message, level=BLACKNET_LOG_DEFAULT):
        if self.__bns._logger:
            peername = "%s" % (self.__peer_ip)
            self.__bns._logger.write("%s: %s" % (peername, message), level)


    def disconnect(self):
        self.__connection_lock.acquire()
        if self.__transport:
            self.log("SSH: stopping session", BLACKNET_LOG_DEBUG)
            self.__transport.close()
            self.__transport = None
            self.__client = None

        if self.__client:
            try:
                self.__client.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            self.__client.close()
            self.__client = None
        self.__connection_lock.release()
