"""MongoDB GridFS SFTP storage."""

from pysftpserver.abstractstorage import SFTPAbstractServerStorage
from pysftpserver.pysftpexceptions import SFTPNotFound
import pymongo
import gridfs


class SFTPServerMongoStorage(SFTPAbstractServerStorage):
    """MongoDB GridFS SFTP storage class."""

    def __init__(self, remote, port, db_name):
        """Home sweet home.

        Instruct the client to connect to your MongoDB.
        """
        client = pymongo.MongoClient(remote, port)
        db = client[db_name]
        self.gridfs = gridfs.GridFS(db)

    def open(self, filename, flags, mode):
        """Return the file handle."""
        filename = filename.decode()
        if self.gridfs.exists(filename=filename):
            return self.gridfs.find({'filename': filename})[0]

        raise SFTPNotFound

    def read(self, handle, off, size):
        """Read size from the handle. Offset is ignored."""
        return handle.read(size)

    def close(self, handle):
        """Close the file handle."""
        handle.close()
