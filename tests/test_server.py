import unittest
from pysftpserver import *
import os
import os.path
import struct


def _sftpstring(s):
    return struct.pack('>I', len(s)) + s

def _sftpint(n):
    return struct.pack('>I', n)

def _sftpcmd(cmd, sid, *args):
    msg = struct.pack('B', cmd)
    msg += _sftpint(sid)
    for arg in args:
        msg += arg
    return _sftpint(len(msg)) + msg

class ServerTest(unittest.TestCase):

    def setUp(self):
        self.home = 'testhome'
        if not os.path.isdir(self.home):        
            os.mkdir(self.home)
        self.server = SFTPServer(self.home, raise_on_error=True)
        if os.path.exists('foo'):
            os.rmdir('foo')
        self.sid_counter = 0
    
    def test_mkdir(self):
        self.sid_counter += 1 
        self.server.input_queue = _sftpcmd(SSH2_FXP_MKDIR, self.sid_counter, _sftpstring('foo'), _sftpint(0))
        self.server.process()
        self.server.input_queue = _sftpcmd(SSH2_FXP_MKDIR, self.sid_counter, _sftpstring('foo'), _sftpint(0))
        self.assertRaises(SFTPException, self.server.process)

    def test_mkdir_notfound(self):
        self.sid_counter += 1 
        self.server.input_queue = _sftpcmd(SSH2_FXP_MKDIR, self.sid_counter, _sftpstring('bad/ugly'), _sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_rmdir_notfound(self):
        self.sid_counter += 1 
        self.server.input_queue = _sftpcmd(SSH2_FXP_RMDIR, self.sid_counter, _sftpstring('bad/ugly'), _sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)

    def test_copy_services(self):
        self.sid_counter += 1 
        self.server.input_queue = _sftpcmd(SSH2_FXP_OPEN, self.sid_counter, _sftpstring('foo/services'), _sftpint(0), _sftpint(0))
        self.assertRaises(SFTPNotFound, self.server.process)


def test_suite():
    return unittest.TestLoader().loadTestsFromName(__name__)

if __name__ == "__main__":
    unittest.main()
