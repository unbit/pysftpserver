"""General SFTP storage. Subclass it the way you want!"""

import os
import itertools

from pysftpserver.abstractstorage import SFTPAbstractServerStorage
from pysftpserver.futimes import futimes
from pysftpserver.stat_helpers import stat_to_longname


class SFTPServerStorage(SFTPAbstractServerStorage):
    """Simple storage class. Subclass it and override the methods."""

    def __init__(self, home, umask=None):
        """Home sweet home.

        Set your home to something comfortable and chdir to it.
        You should support umask changing too.
        """
        self.home = os.path.realpath(home)
        os.chdir(self.home)
        if umask:
            os.umask(umask)

    def verify(self, filename):
        """Verify that requested filename is accessible.

        In this simple storage class this is always True
        (and thus possibly insecure).
        """
        return True

    def stat(self, filename, lstat=False, fstat=False, parent=None):
        """stat, lstat and fstat requests.

        Return a dictionary of stats.
        Filename is an handle in the fstat variant.
        If parent is not None, then filename is inside parent,
        and a join is needed.
        This happens in case of readdir responses:
        a filename (not a path) has to be returned,
        but the stat call need (obviously) a full path.
        """
        if not lstat and fstat:
            # filename is an handle
            _stat = os.fstat(filename)
        elif lstat:
            _stat = os.lstat(filename)
        else:
            _stat = os.stat(
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
            'size': _stat.st_size,
            'uid': _stat.st_uid,
            'gid': _stat.st_gid,
            'perm': _stat.st_mode,
            'atime': _stat.st_atime,
            'mtime': _stat.st_mtime,
            'longname': longname
        }

    def setstat(self, filename, attrs, fsetstat=False):
        """setstat and fsetstat requests.

        Filename is an handle in the fstat variant.
        If you're using Python < 3.3,
        you could find useful the futimes file / function.
        """
        if not fsetstat:
            f = os.open(filename, os.O_WRONLY)
            chown = os.chown
            chmod = os.chmod
        else:  # filename is a fd
            f = filename
            chown = os.fchown
            chmod = os.fchmod

        if 'size' in attrs:
            os.ftruncate(f, attrs['size'])
        if all(k in attrs for k in ('uid', 'gid')):
            chown(filename, attrs['uid'], attrs['gid'])
        if 'perm' in attrs:
            chmod(filename, attrs['perm'])

        if all(k in attrs for k in ('atime', 'mtime')):
            if not fsetstat:
                os.utime(filename, (attrs['atime'], attrs['mtime']))
            else:
                futimes(filename, (attrs['atime'], attrs['mtime']))

    def opendir(self, filename):
        """Return an iterator over the files in filename."""
        return itertools.chain(iter([b'.', b'..']), iter(os.listdir(filename)))

    def open(self, filename, flags, mode):
        """Return the file handle."""
        return os.open(filename, flags, mode)

    def mkdir(self, filename, mode):
        """Create directory with given mode."""
        os.mkdir(filename, mode)

    def rmdir(self, filename):
        """Remove directory."""
        os.rmdir(filename)

    def rm(self, filename):
        """Remove file."""
        os.remove(filename)

    def rename(self, oldpath, newpath):
        """Move/rename file."""
        os.rename(oldpath, newpath)

    def symlink(self, linkpath, targetpath):
        """Symlink file."""
        os.symlink(targetpath, linkpath)

    def readlink(self, filename):
        """Readlink of filename."""
        return os.readlink(filename)

    def write(self, handle, off, chunk):
        """Write chunk at offset of handle."""
        os.lseek(handle, off, os.SEEK_SET)
        rlen = os.write(handle, chunk)
        if rlen == len(chunk):
            return True

    def read(self, handle, off, size):
        """Read from the handle size, starting from offset off."""
        os.lseek(handle, off, os.SEEK_SET)
        return os.read(handle, size)

    def close(self, handle):
        """Close the file handle."""
        try:
            handle.close()
        except AttributeError:
            pass
