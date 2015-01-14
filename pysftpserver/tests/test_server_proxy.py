#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function

import threading
import logging
import socket
import select
import paramiko
import os
import unittest
import stat

from shutil import rmtree

from pysftpserver.tests.stub_sftp import StubServer, StubSFTPServer
from pysftpserver.tests.utils import *
from pysftpserver.server import *
from pysftpserver.proxystorage import SFTPServerProxyStorage


REMOTE_ROOT = t_path("server_root")
LOCAL_ROOT = t_path("local_folder")

remote_file = lambda file_path: os.path.join(REMOTE_ROOT, file_path)


event = threading.Event()

# attach existing loggers (use --nologcapture option to see output)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def _start_sftp_server():
    """Start the SFTP local server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    sock.bind(('localhost', 2223))
    sock.listen(10)

    reads = {sock}
    others = set()

    while not event.is_set():
        ready_to_read, _, _ = \
            select.select(
                reads,
                others,
                others,
                1)

        if sock in ready_to_read:
            client_socket, address = sock.accept()
            ts = paramiko.Transport(client_socket)

            host_key = paramiko.RSAKey.from_private_key_file(
                t_path('server_id_rsa')
            )
            ts.add_server_key(host_key)
            server = StubServer()
            ts.set_subsystem_handler(
                'sftp', paramiko.SFTPServer, StubSFTPServer)
            ts.start_server(server=server)

    sock.close()


def setup_module():
    """Setup in a new thread the SFTP local server."""
    os.chdir(t_path())
    os.mkdir(REMOTE_ROOT)

    t = threading.Thread(target=_start_sftp_server, name="server")
    t.start()


def teardown_module():
    """Stop the SFTP server by setting its event.

    Clean remaining directories (in case of failures).
    """
    event.set()
    rmtree(REMOTE_ROOT, ignore_errors=True)


class TestProxyServer(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        os.mkdir(LOCAL_ROOT)
        os.chdir(LOCAL_ROOT)

    def setUp(self):
        """Before running each test, create a server instance and create the required directories."""
        self.server = SFTPServer(
            SFTPServerProxyStorage(
                "test:secret@localhost",
                port=2223
            ),
            logfile=t_path('log'),
            raise_on_error=True
        )

    def test_mkdir(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'foo'), sftpint(0))
        self.server.process()

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'foo'), sftpint(0))
        self.assertRaises(SFTPException, self.server.process)

        self.assertTrue(os.path.exists(remote_file("foo")) and os.path.isdir(remote_file("foo")))

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_RMDIR, sftpstring(b'foo')
        )
        self.server.process()

        self.assertFalse(os.path.exists(remote_file("foo")))

    def test_stat(self):
        with open("/etc/services") as f:
            with open(remote_file("services"), 'a') as f_bis:
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

        os.unlink(remote_file("services"))

    def test_lstat(self):
        os.symlink("foo", remote_file("link"))

        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_LSTAT,
            sftpstring(b'link')
        )
        self.server.process()
        stat = get_sftpstat(self.server.output_queue)
        self.assertEqual(stat['size'], len("foo"))
        self.assertEqual(stat['uid'], os.getuid())

        os.unlink(remote_file("link"))

    def test_fstat(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_READ | SSH2_FXF_WRITE | SSH2_FXF_CREAT),
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

        os.unlink(remote_file("services"))

    def test_setstat(self):
        atime = 1415626110
        mtime = 1415626120
        size = 10 ** 2

        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE | SSH2_FXP_READ),
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
            sftpint64(size),  # 100 bytes
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
            stat.S_IMODE(os.lstat(remote_file('services')).st_mode))

        self.assertEqual(
            atime,
            os.lstat(remote_file('services')).st_atime)

        self.assertEqual(
            mtime,
            os.lstat(remote_file('services')).st_mtime)

        self.assertEqual(
            size,
            os.lstat(remote_file('services')).st_size)

        os.unlink(remote_file('services'))

    def test_fsetstat(self):
        atime = 1415626110
        mtime = 1415626120
        size = 10 ** 2

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
            stat.S_IMODE(os.lstat(remote_file('services')).st_mode)
        )

        self.assertEqual(
            atime,
            os.lstat(remote_file('services')).st_atime
        )

        self.assertEqual(
            mtime,
            os.lstat(remote_file('services')).st_mtime
        )

        self.assertEqual(
            size,
            os.lstat(remote_file('services')).st_size
        )

        os.unlink(remote_file('services'))

    def test_read_subdir(self):
        f = {b'.', b'..', b'bar'}  # files inside foo
        os.mkdir(remote_file("foo"))
        foobar_path = os.path.join(remote_file("foo"), "bar")
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

        rmtree(remote_file("foo"))

    def test_open_not_found(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(b'services'),
            sftpint(SSH2_FXF_READ),
            sftpint(0),
        )
        self.assertRaises(SFTPNotFound, self.server.process)

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
        self.assertIn('other_services', os.listdir(REMOTE_ROOT))

        os.unlink(remote_file('other_services'))

    def test_remove_notfound(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_REMOVE,
            sftpstring(b'services'),
            sftpint(0)
        )
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_mkdir_notfound(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(b'bad/ugly'), sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_readdir(self):
        f = {b'.', b'..', b'foo', b'bar'}
        os.mkdir(remote_file("foo"))
        os.close(os.open(remote_file("bar"), os.O_CREAT))

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

        os.unlink(remote_file("bar"))
        os.rmdir(remote_file("foo"))

    def test_symlink(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(b'bad/ugly'), sftpstring(b'bad/ugliest'), sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(b'ugly'), sftpstring(b'ugliest'), sftpint(0))
        self.server.process()
        self.assertIn('ugly', os.listdir(REMOTE_ROOT))

    def test_readlink(self):
        os.symlink("infound", remote_file("foo"))

        self.server.input_queue = sftpcmd(
            SSH2_FXP_READLINK, sftpstring(b'foo'), sftpint(0))
        self.server.process()
        link = get_sftpname(self.server.output_queue)
        self.assertEqual(link, b"infound")

    def test_readdir_broken_symlink(self):
        os.symlink("infound", remote_file("foo"))

        self.server.input_queue = sftpcmd(
            SSH2_FXP_READLINK, sftpstring(b'foo'), sftpint(0))
        self.server.process()
        link = get_sftpname(self.server.output_queue)
        self.assertEqual(link, b"infound")
        self.server.output_queue = b''

        f = {b'.', b'..', b'foo'}
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

        r_services = remote_file('services')
        self.assertEqual(
            etc_services,
            open(r_services, 'rb').read()
        )
        self.assertEqual(
            etc_services,
            data
        )
        self.assertEqual(
            0o644,
            stat.S_IMODE(os.lstat(r_services).st_mode)
        )
        self.assertEqual(
            etc_services_size,
            os.lstat(r_services).st_size
        )

        os.unlink(r_services)

    def tearDown(self):
        """Clean any leftover."""
        for f in os.listdir(LOCAL_ROOT):
            try:
                os.unlink(f)
            except:
                rmtree(f)

        for f in os.listdir(REMOTE_ROOT):
            f = remote_file(f)
            try:
                os.unlink(f)
            except:
                rmtree(f)

    @classmethod
    def teardown_class(cls):
        """Clean the created directories."""
        rmtree(LOCAL_ROOT, ignore_errors=True)
        os.unlink(t_path("log"))  # comment me to see the log!


if __name__ == "__main__":
    unittest.main()
