#!/usr/bin/python

import os
import sys
import select
import struct
import os.path

sys.stderr = open('/tmp/sftp.log', 'w')

SSH2_FX_OK = 0
SSH2_FX_EOF = 1

SSH2_FXP_INIT = 1
SSH2_FXP_VERSION = 2
SSH2_FXP_OPEN = 3
SSH2_FXP_CLOSE = 4
SSH2_FXP_READ = 5
SSH2_FXP_LSTAT = 7
SSH2_FXP_FSTAT = 8
SSH2_FXP_FSETSTAT = 10
SSH2_FXP_OPENDIR = 11
SSH2_FXP_READDIR = 12
SSH2_FXP_REALPATH = 16
SSH2_FXP_STAT = 17

SSH2_FXP_STATUS = 101
SSH2_FXP_HANDLE = 102
SSH2_FXP_NAME = 104
SSH2_FXP_ATTRS = 105

SSH2_FXP_EXTENDED = 200

SSH2_FILEXFER_VERSION = 3

SSH2_FILEXFER_ATTR_SIZE = 0x00000001
SSH2_FILEXFER_ATTR_UIDGID = 0x00000002
SSH2_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH2_FILEXFER_ATTR_ACMODTIME = 0x00000008

class SFTPServerObject(object):
    def __init__(self, name, cmd=os.stat):
        self.name = os.path.realpath(name)
        self.stat = cmd(self.name)
        self.flags = SSH2_FILEXFER_ATTR_SIZE | SSH2_FILEXFER_ATTR_UIDGID | SSH2_FILEXFER_ATTR_PERMISSIONS | SSH2_FILEXFER_ATTR_ACMODTIME
        self.attrs = struct.pack('>IQIIIII', self.flags, self.stat.st_size,
                         self.stat.st_uid,
                         self.stat.st_gid,
                         self.stat.st_mode,
                         self.stat.st_atime,
                         self.stat.st_mtime)
        self.rel_name = os.path.split(self.name)[1]
        sys.stderr.write("%s\n" % self.rel_name)
        sys.stderr.flush()
        self.long_name = self.name
        

class SFTPServerHandle(object):
    def __init__(self, server, filename):
        self.name = os.path.realpath(filename)
        self.server = server
        if self.server.handle_cnt == 0xffffffffffffffff:
            raise OverflowError()
        self.server.handle_cnt+=1
        # we use a string as the handle key
        self.id = str(self.server.handle_cnt)
        self.server.handles[self.id] = self
        self.isdir = False
        if os.path.isdir(self.name):
            self.isdir = True
        self.is_reading = False

    def close(self):
        del(self.server.handles[self.id])
    

class SFTPServer(object):
    def __init__(self, home, logfile=None, fd_in=0,fd_out=1):
        self.input_queue = ''
        self.output_queue = ''
        self.fd_in = fd_in
        self.fd_out = fd_out
        self.buffer_size = 8192
        self.home = os.path.realpath(home)
        self.handles = {}
        self.handle_cnt = 0
        os.chdir(self.home)

    def log(self, txt):
        if not self.log: return
        self.log.write(txt + '\n')
        self.log.flush()

    def consume_int(self):
        value, = struct.unpack('>I', self.input_queue[0:4])
        self.input_queue = self.input_queue[4:]
        return value
        
    def consume_string(self):
        slen = self.consume_int()
        sys.stderr.write("slen = %d" % slen)
        sys.stderr.flush()
        s = self.input_queue[0:slen]
        self.input_queue = self.input_queue[slen:]
        return s

    def send_msg(self, msg):
        msg_len = struct.pack('>I', len(msg))
        self.output_queue += msg_len + msg

    def send_status(self, sid, status):
        msg = struct.pack('>BII', SSH2_FXP_STATUS, sid, status)
        self.send_msg(msg)

    def run(self):
        while True:
            if self.run_once():
                return

    def run_once(self):
        wait_write = []
        if len(self.output_queue) > 0:
            wait_write = [self.fd_out]
        rlist, wlist, xlist = select.select([self.fd_in], wait_write, [])
        if self.fd_in in rlist:
            buf = os.read(self.fd_in, self.buffer_size) 
            if len(buf) <= 0: return True
            self.input_queue += buf
            self.process()
        if self.fd_out in wlist:
            rlen = os.write(self.fd_out, self.output_queue)
            if rlen <= 0: return True
            self.output_queue = self.output_queue[rlen:]

    def process(self):
        if len(self.input_queue) < 5: return
        msg_len, msg_type = struct.unpack('>IB', self.input_queue[0:5])
        if len(self.input_queue) < msg_len + 4: return
        if msg_type == SSH2_FXP_INIT:
            msg = struct.pack('>BI', SSH2_FXP_VERSION, SSH2_FILEXFER_VERSION)
            self.send_msg(msg)
            self.input_queue = self.input_queue[msg_len + 4:]
        elif msg_type == SSH2_FXP_EXTENDED:
            pass
        else:
            if len(self.input_queue) < 4: return
            self.input_queue = self.input_queue[5:]
            msg_id = self.consume_int()
            if msg_type == SSH2_FXP_FSETSTAT:
                send_status(msg_id, SSH2_FX_OK)
            elif msg_type == SSH2_FXP_REALPATH:
                 self._realpath(msg_id)
            elif msg_type == SSH2_FXP_LSTAT:
                 self._lstat(msg_id)
            elif msg_type == SSH2_FXP_STAT:
                 self._stat(msg_id)
            elif msg_type == SSH2_FXP_OPENDIR:
                 self._opendir(msg_id)
            elif msg_type == SSH2_FXP_READDIR:
                 self._readdir(msg_id)
            elif msg_type == SSH2_FXP_CLOSE:
                 self._close(msg_id)
            else:
                sys.stderr.write("MSG_TYPE = %d\n" % msg_type)
                sys.stderr.flush()

    def send_names(self, sid, items, relative=False):
        msg = struct.pack('>BII', SSH2_FXP_NAME, sid, len(items))
        for item in items:
            if relative:
                msg += struct.pack('>I', len(item.rel_name)) + item.rel_name
                msg += struct.pack('>I', len(item.rel_name)) + item.rel_name
            else:
                msg += struct.pack('>I', len(item.name)) + item.name
                msg += struct.pack('>I', len(item.long_name)) + item.long_name
            msg += item.attrs
        self.send_msg(msg)

    def _realpath(self, sid):
        filename = self.consume_string()
        sys.stderr.write(filename)
        sys.stderr.flush()
        if len(filename) == 0: filename = '.'
        true_path = SFTPServerObject(filename)
        sys.stderr.write("file = %s / %s\n" % (filename, true_path.name))
        sys.stderr.flush()
        self.send_names(sid, [true_path])

    def _stat(self, sid):
        filename = self.consume_string()
        item = SFTPServerObject(filename)
        msg = struct.pack('>BI', SSH2_FXP_ATTRS, sid)
        msg += item.attrs
        self.send_msg(msg) 

    def _lstat(self, sid):
        filename = self.consume_string()
        item = SFTPServerObject(filename, os.lstat)
        msg = struct.pack('>BI', SSH2_FXP_ATTRS, sid)
        msg += item.attrs
        self.send_msg(msg)

    def _opendir(self, sid):
        filename = self.consume_string()
        handle = SFTPServerHandle(self, filename)
        msg = struct.pack('>BII', SSH2_FXP_HANDLE, sid, len(handle.id))
        msg += handle.id
        self.send_msg(msg)

    def _readdir(self, sid):
        handle_id = self.consume_string()
        handle = self.handles[handle_id]
        if not handle.is_reading:
            handle.items = ['.', '..'] + os.listdir(handle.name)
            handle.is_reading = True
        items = []
        if not handle.items:
            self.is_reading = False
            self.send_status(sid, SSH2_FX_EOF)
            return
        for name in handle.items:
            true_path = SFTPServerObject(os.path.join(handle.name, name))
            items.append(true_path)
            handle.items.remove(name)
            if len(items) >= 100:
                self.send_names(sid, items, True)
                items = []
        if len(items) > 0:
            self.send_names(sid, items, True)

    def _close(self, sid):
        handle_id = self.consume_string()
        handle = self.handles[handle_id]
        handle.close()
        self.send_status(sid, SSH2_FX_OK)

if __name__ == '__main__':
    SFTPServer('.').run()
