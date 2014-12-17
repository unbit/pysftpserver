import unittest
import os
from shutil import rmtree

import pymongo
import gridfs

from pysftpserver.server import *
from pysftpserver.mongostorage import SFTPServerMongoStorage
from pysftpserver.tests.utils import *

"""To run this tests you must have an instance of MongoDB running somewhere."""
REMOTE = "localhost"
PORT = 1727
DB_NAME = "mydb"


class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        client = pymongo.MongoClient(REMOTE, PORT)
        db = client[DB_NAME]
        cls.gridfs = gridfs.GridFS(db)

    def setUp(self):
        os.chdir(t_path())
        self.home = 'home'

        if not os.path.isdir(self.home):
            os.mkdir(self.home)

        self.server = SFTPServer(
            SFTPServerMongoStorage(REMOTE, PORT, DB_NAME),
            logfile=t_path('log'),
            raise_on_error=True
        )

    def tearDown(self):
        os.chdir(t_path())
        rmtree(self.home)

    def test_read(self):
        s = b"This is a test file."
        f_name = "test"  # put expects a non byte string!
        b_f_name = b"test"

        f = self.gridfs.put(s, filename=f_name)
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b_f_name),
            sftpint(SSH2_FXF_CREAT),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        self.server.output_queue = b''  # reset the output queue
        self.server.input_queue = sftpcmd(
            SSH2_FXP_READ,
            sftpstring(handle),
            sftpint64(0),
            sftpint(len(s)),
        )
        self.server.process()
        data = get_sftpdata(self.server.output_queue)

        self.assertEqual(s, data)

        self.server.output_queue = b''  # reset output queue
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        # Cleanup!
        self.gridfs.delete(f)

    @classmethod
    def tearDownClass(cls):
        os.unlink(t_path("log"))  # comment me to see the log!
        rmtree(t_path("home"), ignore_errors=True)
