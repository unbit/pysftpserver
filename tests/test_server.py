import unittest
import os
import struct
import random
import stat
from shutil import rmtree

from pysftpserver.server import *
from pysftpserver.virtualchroot import *
from tests.utils import t_path


def _sftpstring(s):
    return struct.pack('>I', len(s)) + s


def _sftpint(n):
    return struct.pack('>I', n)


def _sftpint64(n):
    return struct.pack('>Q', n)


def _sftpcmd(cmd, *args):
    msg = struct.pack('>BI', cmd, random.randrange(1, 0xffffffff))
    for arg in args:
        msg += arg
    return _sftpint(len(msg)) + msg


def _get_sftphandle(blob):
    slen, = struct.unpack('>I', blob[9:13])
    return blob[13:13 + slen]


def _get_sftpint(blob):
    value, = struct.unpack('>I', blob[5:9])
    return int(value)


def _getUMask():
    current_umask = os.umask(0)
    os.umask(current_umask)

    return current_umask


class ServerTest(unittest.TestCase):

    def setUp(self):
        os.chdir(t_path())
        self.home = 'testhome'

        if not os.path.isdir(self.home):
            os.mkdir(self.home)

        self.server = SFTPServer(
            SFTPServerVirtualChroot(self.home),
            logfile=t_path("log"),
            raise_on_error=True
        )

    def tearDown(self):
        os.chdir(t_path())
        rmtree(self.home)

    def test_mkdir(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_MKDIR, _sftpstring('foo'), _sftpint(0))
        self.server.process()
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_MKDIR, _sftpstring('foo'), _sftpint(0))
        self.assertRaises(SFTPException, self.server.process)

        os.rmdir('foo')

    def test_mkdir_forbidden(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_MKDIR, _sftpstring('../foo'), _sftpint(0))
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = _sftpcmd(
            SSH2_FXP_MKDIR, _sftpstring('/foo'), _sftpint(0))
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_open_already_existing(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_OPEN,
            _sftpstring('services'),
            _sftpint(SSH2_FXF_CREAT),
            _sftpint(0)
        )
        self.server.process()
        handle = _get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = ''
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_CLOSE,
            _sftpstring(handle)
        )
        self.server.process()

        self.server.input_queue = _sftpcmd(
            SSH2_FXP_OPEN,
            _sftpstring('services'),
            _sftpint(SSH2_FXF_CREAT | SSH2_FXF_EXCL),
            _sftpint(0)
        )
        self.assertRaises(SFTPException, self.server.process)

        os.unlink('services')

    def test_open_forbidden(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_OPEN, _sftpstring('/etc/services'), _sftpint(SSH2_FXF_CREAT), _sftpint(0)
        )
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = _sftpcmd(
            SSH2_FXP_OPEN, _sftpstring('../../foo'), _sftpint(SSH2_FXF_CREAT), _sftpint(0)
        )
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_remove(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_OPEN,
            _sftpstring('services'),
            _sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            _sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            _sftpint(0644)
        )
        self.server.process()
        handle = _get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = ''
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_CLOSE,
            _sftpstring(handle)
        )
        self.server.process()

        self.server.input_queue = _sftpcmd(
            SSH2_FXP_REMOVE,
            _sftpstring('services'),
            _sftpint(0)
        )
        self.server.process()

    def test_remove_notfound(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_REMOVE,
            _sftpstring('services'),
            _sftpint(0)
        )
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_remove_forbidden(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_REMOVE,
            _sftpstring('/etc/services'),
            _sftpint(0)
        )
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_mkdir_notfound(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_MKDIR, _sftpstring('bad/ugly'), _sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_init(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_INIT, _sftpint(2), _sftpint(0)
        )
        self.server.process()
        version = _get_sftpint(self.server.output_queue)
        self.assertEqual(version, SSH2_FILEXFER_VERSION)

    def test_rmdir_notfound(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_RMDIR, _sftpstring('bad/ugly'), _sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_copy_services(self):
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_OPEN,
            _sftpstring('services'),
            _sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            _sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            _sftpint(0644)
        )
        self.server.process()
        handle = _get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = ''
        etc_services = open('/etc/services').read()
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_WRITE,
            _sftpstring(handle),
            _sftpint64(0),
            _sftpstring(etc_services)
        )
        self.server.process()

        # reset output queue
        self.server.output_queue = ''
        self.server.input_queue = _sftpcmd(
            SSH2_FXP_CLOSE,
            _sftpstring(handle)
        )
        self.server.process()

        self.assertEqual(etc_services, open('services').read())
        self.assertEqual(
            0644,
            stat.S_IMODE(os.lstat('services').st_mode)
        )

        os.unlink('services')

    @classmethod
    def tearDownClass(self):
        os.unlink(t_path("log"))
        rmtree(t_path("testhome"), ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
