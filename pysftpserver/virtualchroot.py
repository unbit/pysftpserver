from pysftpserver import SFTPServerStorage,SFTPForbidden
import os
import os.path

class SFTPServerVirtualChroot(SFTPServerStorage):
    def __init__(self, home):
        self.home = os.path.realpath(home)
        self.parent = os.path.split(self.home)[0]
        os.chdir(self.home)

    # verify if the absolute path is under the specified dir
    def verify(self, filename):
        filename = os.path.realpath(filename)
        if not filename.startswith(self.home + '/') and filename != self.home:
                raise SFTPForbidden()
        return filename

    def stat(self, filename, lstat=False):
        if not lstat:
            _stat = os.stat(filename)
        else:
            _stat = os.lstat(filename)
        return {
                   'size': _stat.st_size,
                   'uid': _stat.st_uid,
                   'gid': _stat.st_gid,
                   'mode': _stat.st_mode,
                   'atime': _stat.st_atime,
                   'mtime': _stat.st_mtime,
               }

    def opendir(self, filename):
        return (['.', '..'] + os.listdir(filename)).__iter__()

    def open(self, filename, mode, attrs):
        return open(filename, mode)

    def mkdir(self, filename, attrs):
        os.mkdir(filename)

    def rmdir(self, filename):
        os.rmdir(filename)

    def write(self, handle, off, chunk):
        os.lseek(handle.fileno(), off, os.SEEK_SET)
        rlen = os.write(handle.fileno(), chunk)
        if rlen == len(chunk):
            return True

    def read(self, handle, off, size):
        os.lseek(handle.fileno(), off, os.SEEK_SET)
        return os.read(handle.fileno(), size)

    def close(self, handle):
        try:
            handle.close()
        except AttributeError:
            pass
