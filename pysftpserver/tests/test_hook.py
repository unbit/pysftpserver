from __future__ import print_function

import os
import pickle
from shutil import rmtree
import unittest

from pysftpserver.hook import SftpHook
from pysftpserver.server import (SSH2_FILEXFER_ATTR_ACMODTIME,
                                 SSH2_FILEXFER_ATTR_PERMISSIONS,
                                 SSH2_FILEXFER_ATTR_SIZE, SSH2_FXF_CREAT,
                                 SSH2_FXF_READ, SSH2_FXF_WRITE, SSH2_FXP_CLOSE,
                                 SSH2_FXP_FSETSTAT, SSH2_FXP_FSTAT,
                                 SSH2_FXP_INIT, SSH2_FXP_LSTAT, SSH2_FXP_MKDIR,
                                 SSH2_FXP_OPEN, SSH2_FXP_OPENDIR,
                                 SSH2_FXP_READ, SSH2_FXP_READDIR,
                                 SSH2_FXP_READLINK, SSH2_FXP_REALPATH,
                                 SSH2_FXP_REMOVE, SSH2_FXP_RENAME,
                                 SSH2_FXP_RMDIR, SSH2_FXP_SETSTAT,
                                 SSH2_FXP_STAT, SSH2_FXP_SYMLINK,
                                 SSH2_FXP_WRITE, SFTPServer)
from pysftpserver.storage import SFTPServerStorage
from pysftpserver.tests.utils import (get_sftphandle, sftpcmd, sftpint,
                                      sftpint64, sftpstring, t_path)


class TestHook(SftpHook):

    def __init__(self, code_length=6, *args, **kwargs):
        self._results = dict()
        super().__init__(*args, **kwargs)

    def _get_results_key(self, function_name, suffix=''):
        return (function_name + suffix and '_' + suffix or '').encode()

    def get_result(self, function_name, suffix=''):
        return self._results.get(self._get_results_key(function_name, suffix))

    def set_result(self, function_name, value, suffix=''):
        self._results[self._get_results_key(function_name, suffix)] = value

    def init(self):
        self.set_result('init', b'init hooked')

    def realpath(self, filename):
        self.set_result('realpath', filename)

    def stat(self, filename):
        self.set_result('stat', filename)

    def lstat(self, filename):
        self.set_result('lstat', filename)

    def fstat(self, handle_id):
        filename, is_dir = self.server.get_filename_from_handle_id(handle_id)
        self.set_result('fstat', filename)

    def setstat(self, filename, attrs):
        self.set_result('setstat', filename, 'filename')
        self.set_result('setstat', pickle.dumps(attrs), 'attrs')

    def fsetstat(self, handle_id, attrs):
        filename, is_dir = self.server.get_filename_from_handle_id(handle_id)
        self.set_result('fsetstat', filename, 'filename')
        self.set_result('fsetstat', pickle.dumps(attrs), 'attrs')

    def opendir(self, filename):
        self.set_result('opendir', filename)

    def readdir(self, handle_id):
        filename, is_dir = self.server.get_filename_from_handle_id(handle_id)
        self.set_result('readdir', filename)

    def close(self, handle_id):
        filename, is_dir = self.server.get_filename_from_handle_id(handle_id)
        self.set_result('close', filename)

    def open(self, filename, flags, attrs):
        self.set_result('open', filename, 'filename')
        self.set_result('open', flags, 'flags')
        self.set_result('open', pickle.dumps(attrs), 'attrs')

    def read(self, handle_id, offset, size):
        filename, is_dir = self.server.get_filename_from_handle_id(handle_id)
        self.set_result('read', filename, 'filename')
        self.set_result('read', offset, 'offset')
        self.set_result('read', size, 'size')

    def write(self, handle_id, offset, chunk):
        filename, is_dir = self.server.get_filename_from_handle_id(handle_id)
        self.set_result('write', filename, 'filename')
        self.set_result('write', offset, 'offset')
        self.set_result('write', chunk, 'chunk')

    def mkdir(self, filename, attrs):
        self.set_result('mkdir', filename, 'filename')
        self.set_result('mkdir', pickle.dumps(attrs), 'attrs')

    def rmdir(self, filename):
        self.set_result('rmdir', filename)

    def rm(self, filename):
        self.set_result('rm', filename)

    def rename(self, oldpath, newpath):
        self.set_result('rename', oldpath, 'oldpath')
        self.set_result('rename', newpath, 'newpath')

    def symlink(self, linkpath, targetpath):
        self.set_result('symlink', linkpath, 'linkpath')
        self.set_result('symlink', targetpath, 'targetpath')

    def readlink(self, filename):
        self.set_result('readlink', filename)


class ServerTest(unittest.TestCase):

    def setUp(self):
        os.chdir(t_path())
        self.home = 'home'
        if not os.path.isdir(self.home):
            os.mkdir(self.home)
        self.hook = TestHook()
        self.server = SFTPServer(
            SFTPServerStorage(self.home),
            hook=self.hook,
            logfile=t_path('log'),
            raise_on_error=True
        )

    def tearDown(self):
        os.chdir(t_path())
        rmtree(self.home)

    @classmethod
    def tearDownClass(cls):
        os.unlink(t_path('log'))  # comment me to see the log!
        rmtree(t_path('home'), ignore_errors=True)

    def test_init(self):
        self.server.input_queue = sftpcmd(
            SSH2_FXP_INIT, sftpint(2), sftpint(0))
        self.server.process()
        self.assertEqual(self.hook.get_result('init'), b'init hooked')

    def test_realpath(self):
        filename = b'services'
        flags = SSH2_FXF_CREAT | SSH2_FXF_WRITE
        perm = 0o100600
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(flags),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(perm),
        )
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_REALPATH,
                                          sftpstring(filename))
        self.server.process()
        self.assertEqual(self.hook.get_result('realpath'), filename)
        os.unlink(filename)

    def test_stat(self):
        filename = b'services'
        with open('/etc/services') as f:
            with open(filename, 'a') as f_bis:
                f_bis.write(f.read())
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_STAT, sftpstring(filename))
        self.server.process()
        self.assertEqual(self.hook.get_result('stat'), filename)
        os.unlink(filename)

    def test_lstat(self):
        linkname = b'link'
        os.symlink('foo', linkname)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_LSTAT, sftpstring(linkname))
        self.server.process()
        self.assertEqual(self.hook.get_result('lstat'), linkname)
        os.unlink(linkname)

    def test_fstat(self):
        filename = b'services'
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_FSTAT, sftpstring(handle))
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.assertEqual(self.hook.get_result('fstat'), filename)
        os.unlink(filename)

    def test_setstat(self):
        filename = b'services'
        attrs = {
            b'size': 10**2,
            b'perm': 0o100600,
            b'atime': 1415626110,
            b'mtime': 1415626120,
        }
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
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
            sftpstring(filename),
            sftpint(
                SSH2_FILEXFER_ATTR_SIZE |
                SSH2_FILEXFER_ATTR_PERMISSIONS |
                SSH2_FILEXFER_ATTR_ACMODTIME
            ),
            sftpint64(attrs[b'size']),
            sftpint(attrs[b'perm']),
            sftpint(attrs[b'atime']),
            sftpint(attrs[b'mtime']),
        )
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.assertEqual(self.hook.get_result('setstat', 'filename'), filename)
        self.assertEqual(
            pickle.loads(self.hook.get_result('setstat', 'attrs')), attrs)
        os.unlink(filename)

    def test_fsetstat(self):
        filename = b'services'
        attrs = {
            b'size': 10**2,
            b'perm': 0o100600,
            b'atime': 1415626110,
            b'mtime': 1415626120,
        }
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(0)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
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
            sftpint64(attrs[b'size']),
            sftpint(attrs[b'perm']),
            sftpint(attrs[b'atime']),
            sftpint(attrs[b'mtime']),
        )
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.assertEqual(self.hook.get_result('fsetstat', 'filename'),
                         filename)
        self.assertEqual(
            pickle.loads(self.hook.get_result('fsetstat', 'attrs')), attrs)
        os.unlink(filename)

    def test_opendir(self):
        dirname = b'foo'
        os.mkdir(dirname)
        self.server.input_queue = sftpcmd(SSH2_FXP_OPENDIR,
                                          sftpstring(dirname))
        self.server.process()
        self.assertEqual(self.hook.get_result('opendir'), dirname)
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        rmtree(dirname)

    def test_readdir(self):
        dirname = b'foo'
        os.mkdir(dirname)
        self.server.input_queue = sftpcmd(SSH2_FXP_OPENDIR,
                                          sftpstring(dirname))
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_READDIR, sftpstring(handle))
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.assertEqual(self.hook.get_result('readdir'), dirname)
        os.rmdir(dirname)

    def test_close(self):
        filename = b'services'
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(0),
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.assertEqual(self.hook.get_result('close'), filename)
        os.unlink(filename)

    def test_open(self):
        filename = b'services'
        flags = SSH2_FXF_CREAT | SSH2_FXF_WRITE
        perm = 0o100600
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(flags),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(perm),
        )
        self.server.process()
        self.assertEqual(self.hook.get_result('open', 'filename'), filename)
        self.assertEqual(self.hook.get_result('open', 'flags'), flags)
        self.assertEqual(pickle.loads(self.hook.get_result('open', 'attrs')),
                         {b'perm': perm})
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        os.unlink(filename)

    def test_read(self):
        filename = b'services'
        read_offset = 2
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE | SSH2_FXF_READ),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644),
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        chunk = open('/etc/services', 'rb').read()
        size = (os.lstat('/etc/services').st_size)
        self.server.input_queue = sftpcmd(
            SSH2_FXP_WRITE,
            sftpstring(handle),
            sftpint64(0),
            sftpstring(chunk),
        )
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_READ,
            sftpstring(handle),
            sftpint64(read_offset),
            sftpint(size),
        )
        self.server.process()
        self.assertEqual(self.hook.get_result('read', 'filename'), filename)
        self.assertEqual(self.hook.get_result('read', 'offset'), read_offset)
        self.assertEqual(self.hook.get_result('read', 'size'), size)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        os.unlink(filename)

    def test_write(self):
        filename = b'services'
        write_offset = 5
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE | SSH2_FXF_READ),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644),
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        chunk = open('/etc/services', 'rb').read()
        self.server.input_queue = sftpcmd(
            SSH2_FXP_WRITE,
            sftpstring(handle),
            sftpint64(write_offset),
            sftpstring(chunk),
        )
        self.server.process()
        self.assertEqual(self.hook.get_result('write', 'filename'), filename)
        self.assertEqual(self.hook.get_result('write', 'offset'), write_offset)
        self.assertEqual(self.hook.get_result('write', 'chunk'), chunk)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        os.unlink(filename)

    def test_mkdir(self):
        dirname = b'foo'
        # sftpint(0) means no attrs
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(dirname), sftpint(0))
        self.server.process()
        self.server.output_queue = b''
        self.assertEqual(self.hook.get_result('mkdir', 'filename'), dirname)
        self.assertEqual(pickle.loads(self.hook.get_result('mkdir', 'attrs')),
                         dict())
        os.rmdir(dirname)

    def test_rmdir(self):
        dirname = b'foo'
        # sftpint(0) means no attrs
        self.server.input_queue = sftpcmd(
            SSH2_FXP_MKDIR, sftpstring(dirname), sftpint(0))
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_RMDIR, sftpstring(dirname))
        self.server.process()
        self.assertEqual(self.hook.get_result('rmdir'), dirname)

    def test_rm(self):
        filename = b'services'
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(filename),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_REMOVE,
            sftpstring(filename),
            sftpint(0)
        )
        self.server.process()
        self.assertEqual(self.hook.get_result('rm'), filename)

    def test_rename(self):
        oldpath = b'services'
        newpath = b'other_services'
        self.server.input_queue = sftpcmd(
            SSH2_FXP_OPEN,
            sftpstring(oldpath),
            sftpint(SSH2_FXF_CREAT | SSH2_FXF_WRITE),
            sftpint(SSH2_FILEXFER_ATTR_PERMISSIONS),
            sftpint(0o644)
        )
        self.server.process()
        handle = get_sftphandle(self.server.output_queue)
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(SSH2_FXP_CLOSE, sftpstring(handle))
        self.server.process()
        self.server.output_queue = b''
        self.server.input_queue = sftpcmd(
            SSH2_FXP_RENAME,
            sftpstring(oldpath),
            sftpstring(newpath),
        )
        self.server.process()
        self.assertEqual(self.hook.get_result('rename', 'oldpath'), oldpath)
        self.assertEqual(self.hook.get_result('rename', 'newpath'), newpath)
        os.unlink(newpath)

    def test_symlink(self):
        linkpath = b'ugly'
        targetpath = b'ugliest'
        self.server.input_queue = sftpcmd(
            SSH2_FXP_SYMLINK, sftpstring(linkpath), sftpstring(targetpath),
            sftpint(0))
        self.server.process()
        self.assertEqual(self.hook.get_result('symlink', 'linkpath'), linkpath)
        self.assertEqual(self.hook.get_result('symlink', 'targetpath'),
                         targetpath)

    def test_readlink(self):
        linkpath = b'ugly'
        targetpath = b'ugliest'
        os.symlink(linkpath, targetpath)
        self.server.input_queue = sftpcmd(
            SSH2_FXP_READLINK, sftpstring(targetpath), sftpint(0))
        self.server.process()
        self.assertEqual(self.hook.get_result('readlink'), targetpath)


if __name__ == '__main__':
    unittest.main()
