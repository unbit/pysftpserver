"""Proxy SFTP storage. Forward each request to another SFTP server."""

import paramiko

from pysftpserver.abstractstorage import SFTPAbstractServerStorage
from pysftpserver.stat_helpers import stat_to_longname

import os


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

    def __init__(self, remote, user, password, port=22):
        # TODO: SSH agent, pk authentication, and so on...
        """Home sweet home.

        Init the transport and then the client.
        """
        transport = paramiko.Transport((remote, port))
        transport.connect(username=user, password=password)

        self.client = paramiko.SFTPClient.from_transport(transport)

    def verify(self, filename):
        """Verify that requested filename is accessible.

        Can always return True in this case.
        """
        return True

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
                _stat = self.client.stat(
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

    def setstat(self, filename, attrs, fsetstat=False):
        """setstat and fsetstat requests.

        Filename is an handle in the fstat variant.
        """

        if 'size' in attrs and not fsetstat:
            self.client.truncate(filename, attrs['size'])
        elif 'size' in attrs:
            filename.truncate(attrs['size'])

        _chown = all(k in attrs for k in ('uid', 'gid'))
        if _chown and not fsetstat:
            self.client.chown(filename, attrs['uid'], attrs['gid'])
        elif _chown:
            filename.chown(attrs['uid'], attrs['gid'])

        if 'perm' in attrs and not fsetstat:
            self.client.chmod(filename, attrs['perm'])
        elif 'perm' in attrs:
            filename.chmod(attrs['perm'])

        _utime = all(k in attrs for k in ('atime', 'mtime'))
        if _utime and not fsetstat:
            self.client.utime(filename, (attrs['atime'], attrs['mtime']))
        elif _utime:
            filename.utime((attrs['atime'], attrs['mtime']))

    def opendir(self, filename):
        """Return an iterator over the files in filename."""
        return (f.encode() for f in self.client.listdir(filename) + ['.', '..'])

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

    def mkdir(self, filename, mode):
        """Create directory with given mode."""
        self.client.mkdir(filename, mode)

    def rmdir(self, filename):
        """Remove directory."""
        self.client.rmdir(filename)

    def rm(self, filename):
        """Remove file."""
        self.client.remove(filename)

    def rename(self, oldpath, newpath):
        """Move/rename file."""
        self.client.rename(oldpath, newpath)

    def symlink(self, linkpath, targetpath):
        """Symlink file."""
        self.client.symlink(linkpath, targetpath)

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

    def close(self, handle):
        """Close the file handle."""
        handle.close()
