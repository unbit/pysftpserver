"""Abstract SFTP storage. Subclass it the way you want!"""


class SFTPAbstractServerStorage:
    """Abstract storage class. Subclass it and override the methods."""

    def __init__(self, home, **kwargs):
        """Home sweet home.

        Init your class here.
        """
        return

    def verify(self, filename):
        """This methods can verify be used to verify
        that user has permission to access filename.
        """
        return True

    def stat(self, filename, parent=None, lstat=False, fstat=False):
        """stat, lstat and fstat requests.

        Return a dictionary of stats.
        Filename is an handle in the fstat variant.
        """
        return {}

    def setstat(self, filename, attrs, fsetstat=False):
        """setstat and fsetstat requests.

        Filename is an handle in the fstat variant.
        If you're using Python < 3.3,
        you could find useful the futimes file / function.
        """
        return

    def opendir(self, filename):
        """Return an iterator over the files in filename."""
        return iter([b'.', b'..'])

    def open(self, filename, flags, mode):
        """Return the file handle."""
        return None

    def mkdir(self, filename, mode):
        """Create directory with given mode."""
        return

    def rmdir(self, filename):
        """Remove directory."""
        return

    def rm(self, filename):
        """Remove file."""
        return

    def rename(self, oldpath, newpath):
        """Move/rename file."""
        return

    def symlink(self, linkpath, targetpath):
        """Symlink file."""
        return

    def readlink(self, filename):
        """Readlink of filename."""
        return

    def write(self, handle, off, chunk):
        """Write chunk at offset of handle."""
        return

    def read(self, handle, off, size):
        """Read from the handle size, starting from offset off."""
        return None

    def close(self, handle):
        """Close the file handle."""
        return
