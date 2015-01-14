"""Proxy SFTP storage. Forward each request to another SFTP server."""

import paramiko

from pysftpserver.abstractstorage import SFTPAbstractServerStorage
from pysftpserver.stat_helpers import stat_to_longname

import os
import sys
import socket
from getpass import getuser


def exception_wrapper(method):
    """
    The server class needs not found exceptions to be instances of OSError.
    In Python 3, IOError (thrown by paramiko on fail) is a subclass of OSError.
    In Python 2 instaead, IOError and OSError both derive from EnvironmentError.
    So let's wrap it!
    """
    def _wrapper(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except IOError as e:
            if not isinstance(e, OSError):
                raise OSError(e.errno, e.strerror)
            else:
                raise e

    return _wrapper


class SFTPServerProxyStorage(SFTPAbstractServerStorage):
    """Proxy SFTP storage.
    Uses a Paramiko client to forward requests to another SFTP server.
    """

    @staticmethod
    def flags_to_mode(flags, mode):
        """Convert:
            os module flags and mode -> Paramiko file open mode.
        Note: mode is ignored ATM.
        """
        paramiko_mode = ''
        if flags & os.O_WRONLY or (flags & os.O_WRONLY and flags & os.O_TRUNC):
            paramiko_mode = 'w'
        elif flags & os.O_RDWR and flags & os.O_APPEND:
            paramiko_mode = 'a+'
        elif flags & os.O_RDWR and flags & os.O_CREAT:
            paramiko_mode = 'w+'
        elif flags & os.O_APPEND:
            paramiko_mode = 'a'
        elif flags & os.O_RDWR and flags & os.O_TRUNC:
            paramiko_mode = 'w+'
        elif flags & os.O_RDWR:
            paramiko_mode = 'r+'
        elif flags & os.O_CREAT:
            paramiko_mode = 'w'
        else:  # OS.O_RDONLY fallback to read
            paramiko_mode = 'r'

        if flags & os.O_CREAT and flags & os.O_EXCL:
            paramiko_mode += 'x'

        return paramiko_mode

    def __init__(self, remote,
                 key=None, port=None,
                 ssh_config_path=None, ssh_agent=False,
                 known_hosts_path=None):
        """Home sweet home.

        Init the transport and then the client.
        """
        if '@' in remote:
            self.username, self.hostname = remote.split('@', 1)
        else:
            self.username, self.hostname = None, remote

        self.password = None
        if self.username and ':' in self.username:
            self.username, self.password = self.username.split(':', 1)

        self.port = None

        if ssh_config_path:
            try:
                with open(os.path.expanduser(ssh_config_path)) as c_file:
                    ssh_config = paramiko.SSHConfig()
                    ssh_config.parse(c_file)
                    c = ssh_config.lookup(self.hostname)

                    self.hostname = c.get("hostname", self.hostname)
                    self.username = c.get("user", self.username)
                    self.port = int(c.get("port", port))
                    key = c.get("identityfile", key)
            except Exception as e:
                # it could be safe to continue anyway,
                # because parameters could have been manually specified
                print(
                    "Error while parsing ssh_config file: {}. Trying to continue anyway...".format(e)
                )

        # Set default values
        if not self.username:
            self.username = getuser()  # defaults to current user

        if not self.port:
            self.port = port if port else 22

        self.pkeys = list()
        if ssh_agent:
            try:
                agent = paramiko.agent.Agent()
                self.pkeys.append(*agent.get_keys())

                if not self.pkeys:
                    agent.close()
                    print(
                        "SSH agent didn't provide any valid key. Trying to continue..."
                    )

            except paramiko.SSHException:
                agent.close()
                print(
                    "SSH agent speaks a non-compatible protocol. Ignoring it.")

        if key and not self.password and not self.pkeys:
            key = os.path.expanduser(key)
            try:
                self.pkeys.append(paramiko.RSAKey.from_private_key_file(key))
            except paramiko.PasswordRequiredException:
                print("It seems that your private key is encrypted. Please configure me to use ssh_agent.")
                sys.exit(1)
            except Exception:
                print(
                    "Something went wrong while opening {}. Exiting.".format(
                        key)
                )
                sys.exit(1)
        elif not key and not self.password and not self.pkeys:
            print(
                "You need to specify either a password, an identity or to enable the ssh-agent support."
            )
            sys.exit(1)

        try:
            self.transport = paramiko.Transport((self.hostname, self.port))
        except socket.gaierror:
            print(
                "Hostname not known. Are you sure you inserted it correctly?")
            sys.exit(1)

        try:
            self.transport.start_client()

            if known_hosts_path:
                known_hosts = paramiko.HostKeys()
                known_hosts_path = os.path.realpath(
                    os.path.expanduser(known_hosts_path))

                try:
                    known_hosts.load(known_hosts_path)
                except IOError:
                    print(
                        "Error while loading known hosts file at {}. Exiting...".format(
                            known_hosts_path)
                    )
                    sys.exit(1)

                ssh_host = self.hostname if self.port == 22 else "[{}]:{}".format(
                    self.hostname, self.port)
                pub_k = self.transport.get_remote_server_key()
                if ssh_host in known_hosts.keys() and not known_hosts.check(ssh_host, pub_k):
                    print(
                        "Security warning: "
                        "remote key fingerprint {} for hostname "
                        "{} didn't match the one in known_hosts {}. "
                        "Exiting...".format(
                            pub_k.get_base64(),
                            ssh_host,
                            known_hosts.lookup(self.hostname),
                        )
                    )
                    sys.exit(1)

            if self.password:
                self.transport.auth_password(
                    username=self.username,
                    password=self.password
                )
            else:
                for pkey in self.pkeys:
                    try:
                        self.transport.auth_publickey(
                            username=self.username,
                            key=pkey
                        )
                        break
                    except paramiko.SSHException as e:
                        print(
                            "Authentication with identity {}... failed".format(
                                pkey.get_base64()[:10]
                            )
                        )
                else:  # none of the keys worked
                    raise paramiko.SSHException
        except paramiko.SSHException:
            print(
                "None of the provided authentication methods worked. Exiting."
            )
            self.transport.close()
            sys.exit(1)

        self.client = paramiko.SFTPClient.from_transport(self.transport)

        # Let's retrieve the current dir
        self.client.chdir('.')
        self.home = self.client.getcwd()

    def verify(self, filename):
        """Verify that requested filename is accessible.

        Can always return True in this case.
        """
        return True

    @exception_wrapper
    def stat(self, filename, parent=None, lstat=False, fstat=False):
        """stat, lstat and fstat requests.

        Return a dictionary of stats.
        Filename is an handle in the fstat variant.
        """
        if not lstat and fstat:
            # filename is an handle
            _stat = filename.stat()
        elif lstat:
            _stat = self.client.lstat(filename)
        else:
            try:
                _stat = self.client.stat(
                    filename if not parent
                    else os.path.join(parent, filename)
                )
            except:
                # we could have a broken symlink
                # but lstat could be false:
                # this happens in case of readdir responses
                _stat = self.client.lstat(
                    filename if not parent
                    else os.path.join(parent, filename)
                )

        if fstat:
            longname = None  # not needed in case of fstat
        else:
            longname = stat_to_longname(  # see stat_helpers.py
                _stat, filename
            )

        return {
            b'size': _stat.st_size,
            b'uid': _stat.st_uid,
            b'gid': _stat.st_gid,
            b'perm': _stat.st_mode,
            b'atime': _stat.st_atime,
            b'mtime': _stat.st_mtime,
            b'longname': longname
        }

    @exception_wrapper
    def setstat(self, filename, attrs, fsetstat=False):
        """setstat and fsetstat requests.

        Filename is an handle in the fstat variant.
        """

        if b'size' in attrs and not fsetstat:
            self.client.truncate(filename, attrs[b'size'])
        elif b'size' in attrs:
            filename.truncate(attrs[b'size'])

        _chown = all(k in attrs for k in (b'uid', b'gid'))
        if _chown and not fsetstat:
            self.client.chown(filename, attrs[b'uid'], attrs[b'gid'])
        elif _chown:
            filename.chown(attrs[b'uid'], attrs[b'gid'])

        if b'perm' in attrs and not fsetstat:
            self.client.chmod(filename, attrs[b'perm'])
        elif b'perm' in attrs:
            filename.chmod(attrs[b'perm'])

        _utime = all(k in attrs for k in (b'atime', b'mtime'))
        if _utime and not fsetstat:
            self.client.utime(filename, (attrs[b'atime'], attrs[b'mtime']))
        elif _utime:
            filename.utime((attrs[b'atime'], attrs[b'mtime']))

    @exception_wrapper
    def opendir(self, filename):
        """Return an iterator over the files in filename."""
        return (f.encode() for f in self.client.listdir(filename) + ['.', '..'])

    @exception_wrapper
    def open(self, filename, flags, mode):
        """Return the file handle.

        In Paramiko there are no flags:
        The mode indicates how the file is to be opened:
            'r' for reading,
            'w' for writing (truncating an existing file),
            'a' for appending,
            'r+' for reading/writing,
            'w+' for reading/writing (truncating an existing file),
            'a+' for reading/appending.
            'x' indicates that the operation should only succeed if
                the file was created and did not previously exist.
        """
        paramiko_mode = SFTPServerProxyStorage.flags_to_mode(flags, mode)
        return self.client.open(filename, paramiko_mode)

    @exception_wrapper
    def mkdir(self, filename, mode):
        """Create directory with given mode."""
        self.client.mkdir(filename, mode)

    @exception_wrapper
    def rmdir(self, filename):
        """Remove directory."""
        self.client.rmdir(filename)

    @exception_wrapper
    def rm(self, filename):
        """Remove file."""
        self.client.remove(filename)

    @exception_wrapper
    def rename(self, oldpath, newpath):
        """Move/rename file."""
        self.client.rename(oldpath, newpath)

    @exception_wrapper
    def symlink(self, linkpath, targetpath):
        """Symlink file."""
        self.client.symlink(targetpath, linkpath)

    @exception_wrapper
    def readlink(self, filename):
        """Readlink of filename."""
        l = self.client.readlink(filename)
        return l.encode()

    def write(self, handle, off, chunk):
        """Write chunk at offset of handle."""
        try:
            handle.seek(off)
            handle.write(chunk)
        except:
            return False
        else:
            return True

    def read(self, handle, off, size):
        """Read from the handle size, starting from offset off."""
        handle.seek(off)
        return handle.read(size)

    @exception_wrapper
    def close(self, handle):
        """Close the file handle."""
        handle.close()
