"""An example of SFTPStorage that limits each session to a virtual chroot."""

from pysftpserver.storage import SFTPServerStorage
from pysftpserver.pysftpexceptions import SFTPForbidden
import os


class SFTPServerVirtualChroot(SFTPServerStorage):
    """Storage + virtual chroot.

    The only thing that changes is the verify method.
    """

    def verify(self, filename):
        """Check that filename is inside the chroot (self.home)."""
        filename = filename.decode()
        # verify if the absolute path is under the specified dir
        filename = os.path.realpath(filename)
        if not filename.startswith(self.home + '/') and filename != self.home:
            raise SFTPForbidden()
        return filename
