from __future__ import print_function

import unittest
import os
import stat
from shutil import rmtree

from pysftpserver.server import *
from pysftpserver.virtualchroot import *
from pysftpserver.tests.utils import *


class ServerTest(unittest.TestCase):

    def setUp(self):
        os.chdir(t_path())
        self.home = 'home'

        if not os.path.isdir(self.home):
            os.mkdir(self.home)

        self.server = SFTPServer(
            SFTPServerVirtualChroot(self.home),
            logfile=t_path('log'),
            raise_on_error=True
        )

    def tearDown(self):
        os.chdir(t_path())
        rmtree(self.home)

    def test_mkdir(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'foo'), sftpint(0))
        self.server.process()

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'foo'), sftpint(0))
        self.assertRaises(SFTPException, self.server.process)

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_RMDIR, sftpstring(b'foo')
        )
        self.server.process()

        self.assertRaises(OSError, os.rmdir, 'foo')

    def test_mkdir_forbidden(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'../foo'), sftpint(0))
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'/foo'), sftpint(0))
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_open_already_existing(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_EXCL),
            sftpint(0)
        )
        self.assertRaises(SFTPException, self.server.process)

        os.unlink('services')

    def test_stat(self):
        with open("/etc/services") as f:
            with open("services", 'a') as f_bis:
                f_bis.write(f.read())

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_STAT,
            sftpstring(b'services')
        )
        self.server.process()
        stat = get_sftpstat(self.server.output_queue)
        self.assertEqual(stat['size'], os.path.getsize("/etc/services"))
        self.assertEqual(stat['uid'], os.getuid())

        os.unlink('services')

    def test_lstat(self):
        os.symlink("foo", "link")

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_LSTAT,
            sftpstring(b'link')
        )
        self.server.process()
        stat = get_sftpstat(self.server.output_queue)
        self.assertEqual(stat['size'], len("foo"))
        self.assertEqual(stat['uid'], os.getuid())

        os.unlink('link')

    def test_fstat(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_FSTAT,
            sftpstring(handle)
        )
        self.server.process()
        stat = get_sftpstat(self.server.output_queue)
        self.assertEqual(stat['size'], 0)
        self.assertEqual(stat['uid'], os.getuid())

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        os.unlink('services')

    def test_setstat(self):
        atime = 1415626110
        mtime = 1415626120
        size = 10**2

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = b''
        etc_services = open('/etc/services', 'rb').read()
        self.server.input_queue = sftpcmd(
            SSH2_FXP_WRITE,
            sftpstring(handle),
            sftpint64(0),
            sftpstring(etc_services)
        )
        self.server.process()

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_SETSTAT,
            sftpstring(b'services'),
            sftpint(
                SSH2_FILEXFER_ATTR_SIZE |
                SSH2_FILEXFER_ATTR_PERMISSIONS |
                SSH2_FILEXFER_ATTR_ACMODTIME
            ),
            sftpint64(size),  # 1000 bytes
            sftpint(33152),  # 0o100600
            sftpint(atime),
            sftpint(mtime)
        )
        self.server.process()

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        self.assertEqual(
            0o600,
            stat.S_IMODE(os.lstat('services').st_mode)
        )

        self.assertEqual(
            atime,
            os.lstat('services').st_atime
        )

        self.assertEqual(
            mtime,
            os.lstat('services').st_mtime
        )

        self.assertEqual(
            size,
            os.lstat('services').st_size
        )

        os.unlink('services')

    def test_fsetstat(self):
        atime = 1415626110
        mtime = 1415626120
        size = 10**2

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = b''
        etc_services = open('/etc/services', 'rb').read()
        self.server.input_queue = sftpcmd(
            SSH2_FXP_WRITE,
            sftpstring(handle),
            sftpint64(0),
            sftpstring(etc_services)
        )
        self.server.process()

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_FSETSTAT,
            sftpstring(handle),
            sftpint(
                SSH2_FILEXFER_ATTR_SIZE |
                SSH2_FILEXFER_ATTR_PERMISSIONS |
                SSH2_FILEXFER_ATTR_ACMODTIME
            ),
            sftpint64(size),  # 1000 bytes
            sftpint(33152),  # 0o100600
            sftpint(atime),
            sftpint(mtime)
        )
        self.server.process()

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        self.assertEqual(
            0o600,
            stat.S_IMODE(os.lstat('services').st_mode)
        )

        self.assertEqual(
            atime,
            os.lstat('services').st_atime
        )

        self.assertEqual(
            mtime,
            os.lstat('services').st_mtime
        )

        self.assertEqual(
            size,
            os.lstat('services').st_size
        )

        os.unlink('services')

    def test_open_forbidden(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN, sftpstring(
                b'/etc/services'), sftpint(SSH2_FXF_CREAT), sftpint(0)
        )
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN, sftpstring(
                b'../../foo'), sftpint(SSH2_FXF_CREAT), sftpint(0)
        )
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_read_subdir(self):
        f = {b'.', b'..', b'bar'}  # files inside foo
        os.mkdir("foo")
        foobar_path = os.path.join("foo", "bar")
        with open(foobar_path, 'a') as stream:
            print("foobar", file=stream)
        # bar_size = os.lstat(foobar_path).st_size

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPENDIR,
            sftpstring(b'foo')
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        l = set()
        while (True):
            # reset output queue
            self.server.output_queue = b''
            self.server.input_queue = sftpcmd(
                SSH2_FXP_READDIR,
                sftpstring(handle),
            )
            try:
                self.server.process()
                filename = get_sftpname(self.server.output_queue)
                l.add(filename)
            except:
                break
        self.assertEqual(l, f)

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle),
        )
        self.server.process()

        rmtree("foo")

    def test_remove(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        self.server.input_queue = sftpcmd(
            SSH2_FXP_REMOVE,
            sftpstring(b'services'),
            sftpint(0)
        )
        self.server.process()

    def test_rename(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle),
        )
        self.server.process()

        self.server.input_queue = sftpcmd(
            SSH2_FXP_RENAME,
            sftpstring(b'services'),
            sftpstring(b'other_services'),
        )
        self.server.process()
        self.assertIn('other_services', os.listdir('.'))

    def test_remove_notfound(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_REMOVE,
            sftpstring(b'services'),
            sftpint(0)
        )
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_remove_forbidden(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_REMOVE,
            sftpstring(b'/etc/services'),
            sftpint(0)
        )
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_rename_forbidden(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_RENAME,
            sftpstring(b'services'),
            sftpstring(b'/etc/other_services'),
        )
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_RENAME,
            sftpstring(b'/etc/services'),
            sftpstring(b'/etc/other_services'),
        )
        self.assertRaises(SFTPForbidden, self.server.process)

    def test_mkdir_notfound(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'bad/ugly'), sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_readdir(self):
        f = {b'.', b'..', b'foo', b'bar'}
        os.mkdir("foo")
        os.close(os.open("bar", os.O_CREAT))

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPENDIR,
            sftpstring(b'.')
        )
        self.server.process()

        handle = get_sftphandle(self.server.output_queue)

        l = set()
        while (True):
            # reset output queue
            self.server.output_queue = b''
            self.server.input_queue = sftpcmd(
                SSH2_FXP_READDIR,
                sftpstring(handle),
            )
            try:
                self.server.process()
                filename = get_sftpname(self.server.output_queue)
                l.add(filename)
            except:
                break
        self.assertEqual(l, f)

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle),
        )
        self.server.process()

        os.unlink("bar")
        os.rmdir("foo")

    def test_symlink(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(b'bad/ugly'), sftpstring(b'bad/ugliest'), sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(b'/bad/ugly'), sftpstring(b'bad/ugliest'), sftpint(0))
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(b'bad/ugly'), sftpstring(b'/bad/ugliest'), sftpint(0))
        self.assertRaises(SFTPForbidden, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(b'ugly'), sftpstring(b'ugliest'), sftpint(0))
        self.server.process()
        self.assertIn('ugly', os.listdir('.'))

    def test_readlink(self):
        os.symlink("infound", "foo")

        self.server.input_queue = sftpcmd(
            SSH2_FXP_READLINK, sftpstring(b'foo'), sftpint(0))
        self.server.process()
        link = get_sftpname(self.server.output_queue)
        self.assertEqual(link, b"infound")

    def test_init(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_INIT, sftpint(2), sftpint(0)
        )
        self.server.process()
        version = get_sftpint(self.server.output_queue)
        self.assertEqual(version, SSH2_FILEXFER_VERSION)

    def test_rmdir_notfound(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_RMDIR, sftpstring(b'bad/ugly'), sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_copy_services(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE | SSH2_FXF_READ),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)

        # reset output queue
        self.server.output_queue = b''
        etc_services = open('/etc/services', 'rb').read()
        etc_services_size = \
            os.lstat('/etc/services').st_size  # size of the whole file
        self.server.input_queue = sftpcmd(
            SSH2_FXP_WRITE,
            sftpstring(handle),
            sftpint64(0),
            sftpstring(etc_services)
        )
        self.server.process()

        # reset output queue
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_READ,
            sftpstring(handle),
            sftpint64(0),
            sftpint(
                etc_services_size
            )
        )
        self.server.process()
        data = get_sftpdata(self.server.output_queue)

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_READ,
            sftpstring(handle),
            sftpint64(etc_services_size),
            sftpint(1)  # wait for the EOF
        )
        # EOF status is raised as an exception
        self.assertRaises(SFTPException, self.server.process)

        # reset output queue
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_CLOSE,
            sftpstring(handle)
        )
        self.server.process()

        self.assertEqual(
            etc_services,
            open('services', 'rb').read()
        )
        self.assertEqual(
            etc_services,
            data
        )
        self.assertEqual(
            0o644,
            stat.S_IMODE(os.lstat('services').st_mode)
        )
        self.assertEqual(
            etc_services_size,
            os.lstat('services').st_size
        )

        os.unlink('services')

    @classmethod
    def tearDownClass(cls):
        os.unlink(t_path("log"))  # comment me to see the log!
        rmtree(t_path("home"), ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
