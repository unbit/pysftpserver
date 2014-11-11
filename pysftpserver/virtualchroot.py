from pysftpserver.server import SFTPServerStorage, SFTPForbidden
from pysftpserver.futimes import futimes
import os


class SFTPServerVirtualChroot(SFTPServerStorage):

    def __init__(self, home, umask=None):
        self.home = os.path.realpath(home)
        self.parent = os.path.split(self.home)[0]
        os.chdir(self.home)
        if umask:
            os.umask(umask)

    def verify(self, filename):
        # verify if the absolute path is under the specified dir
        filename = os.path.realpath(filename)
        if not filename.startswith(self.home + '/') and filename != self.home:
            raise SFTPForbidden()
        return filename

    def stat(self, filename, lstat=False, fstat=False):
        if not lstat and fstat:
            # filename is actually an handle
            _stat = os.fstat(filename)
        elif lstat:
            _stat = os.lstat(filename)
        else:
            _stat = os.stat(filename)
        return {
            'size': _stat.st_size,
            'uid': _stat.st_uid,
            'gid': _stat.st_gid,
            'perm': _stat.st_mode,
            'atime': _stat.st_atime,
            'mtime': _stat.st_mtime,
        }

    def setattrs(self, filename, attrs, fsetstat=False):
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
        return (['.', '..'] + os.listdir(filename)).__iter__()

    def open(self, filename, flags, mode):
        return os.open(filename, flags, mode)

    def mkdir(self, filename, mode):
        os.mkdir(filename, mode)

    def rmdir(self, filename):
        os.rmdir(filename)

    def rm(self, filename):
        os.remove(filename)

    def rename(self, oldpath, newpath):
        os.rename(oldpath, newpath)

    def symlink(self, linkpath, targetpath):
        os.symlink(targetpath, linkpath)

    def readlink(self, filename):
        return os.readlink(filename)

    def write(self, handle, off, chunk):
        os.lseek(handle, off, os.SEEK_SET)
        rlen = os.write(handle, chunk)
        if rlen == len(chunk):
            return True

    def read(self, handle, off, size):
        os.lseek(handle, off, os.SEEK_SET)
        return os.read(handle, size)

    def close(self, handle):
        try:
            handle.close()
        except AttributeError:
            pass
