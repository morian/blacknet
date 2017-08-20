import msgpack
import os
import paramiko
import socket
import sys
import time

from threading import Lock, Thread, Event
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
        self.auth_failed_count = 0
        # This needs to be a user-configured value at some point.
        self.auth_failed_limit = BLACKNET_SSH_AUTH_RETRIES
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

    def __auth_failed_inc(self):
        # reset the auth_fail counter to be able to handle faster retries
        self.auth_failed_count += 1

        if self.auth_failed_count >= self.auth_failed_limit:
            self.__transport.auth_handler.auth_fail_count = 1000
        else:
            self.__transport.auth_handler.auth_fail_count = 0


    def check_auth_password(self, username, password):
        try:
            obj = self.__auth_common_obj(username)
            obj['passwd'] = blacknet_ensure_unicode(password)
            self.blacknet.send_ssh_credential(obj)
        except:
            pass

        self.__auth_failed_inc()
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

        self.__auth_failed_inc()
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
                with open(pubfile, 'w') as f:
                    f.write("%s %s" % (pub.get_name(), pub.get_base64()))
            except Exception as e:
                self.log_critical("error: %s" % e)
                raise

        if not prv:
            prv = RSAKey(filename=prvfile)
        self.ssh_host_key = prv
        self.ssh_host_hash = paramiko.py3compat.u(hexlify(prv.get_fingerprint()))
        self.log_info("SSH fingerprint: %s" % self.ssh_host_hash)


    def reload(self):
        """ reload server configuration """

        super(BlacknetSensor, self).reload()
        self.__ssh_private_key_check()
        self.blacknet.reload()


    def do_ping(self):
        # Now this is non-conditional ping after some inactivity.
        self.blacknet.send_ping()

    def serve(self):
        """ serve new connections into new threads """
        super(BlacknetSensor, self).serve(BlacknetSensorThread, BLACKNET_PING_INTERVAL, self.do_ping)


    def shutdown(self):
        self.blacknet.disconnect()
        super(BlacknetSensor, self).shutdown()


class BlacknetSensorThread(Thread):
    """ Separate thread to handle SSH incoming connection requests. """

    def __init__(self, bns, client):
        super(BlacknetSensorThread, self).__init__()

        self.started = False
        self.__connection_lock = Lock()
        self.__bns = bns

        peername = client.getpeername()
        self.__peer_ip = peername[0] if peername else "local"
        self.__client = client
        self.__transport = None
        self.__auth_retries = 0


    def __del__(self):
        self.disconnect()


    def run(self):
        self.started = True
        self.log_debug("SSH: starting session")

        self.__client.settimeout(None)

        t = paramiko.Transport(self.__client)
        t.local_version = self.__bns.ssh_banner
        try:
            t.load_server_moduli()
        except:
            pass
        t.add_server_key(self.__bns.ssh_host_key)
        self.__transport = t

        ssh_server = BlacknetSSHSession(t, self.__bns.blacknet)
        try:
            t.start_server(server=ssh_server, event=Event())
            t.join(BLACKNET_SSH_CLIENT_TIMEOUT)
            if t.is_alive():
                ssh_server.stop_thread()
                t.join()
        except Exception as e:
            self.log_debug("SSH: %s" % e)
        self.__auth_retries = ssh_server.auth_failed_count
        self.disconnect()


    def log(self, message, level=BLACKNET_LOG_DEFAULT):
        if self.__bns._logger:
            peername = "%s" % (self.__peer_ip)
            self.__bns._logger.write("%s: %s" % (peername, message), level)

    def log_error(self, message):
        self.log(message, BLACKNET_LOG_ERROR)

    def log_info(self, message):
        self.log(message, BLACKNET_LOG_INFO)

    def log_debug(self, message):
        self.log(message, BLACKNET_LOG_DEBUG)


    def disconnect(self):
        self.__connection_lock.acquire()
        if self.__transport:
            self.log_debug("SSH: stopping session (%u failed retries)" % self.__auth_retries)
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
