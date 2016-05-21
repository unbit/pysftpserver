"""The SftpHook interface allows to define custom reactions to SftpServer
actions."""


class SftpHook:
    """A collection of callbacks hooked to specific methods on the server.

    Each method is named according to the server method to which it is
    hooked.

    Attributes:
        server (SftpServer): the server instance.
    """
    server = None

    def init(self):
        pass

    def realpath(self, filename):
        pass

    def stat(self, filename):
        pass

    def lstat(self, filename):
        pass

    def fstat(self, handle_id):
        pass

    def setstat(self, filename, attrs):
        pass

    def fsetstat(self, handle_id, attrs):
        pass

    def opendir(self, filename):
        pass

    def readdir(self, handle_id):
        pass

    def close(self, handle_id):
        pass

    def open(self, filename, flags, attrs):
        pass

    def read(self, handle_id, offset, size):
        pass

    def write(self, handle_id, offset, chunk):
        pass

    def mkdir(self, filename, attrs):
        pass

    def rmdir(self, filename):
        pass

    def rm(self, filename):
        pass

    def rename(self, oldpath, newpath):
        pass

    def symlink(self, linkpath, targetpath):
        pass

    def readlink(self, filename):
        pass
