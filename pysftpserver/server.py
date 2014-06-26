import os
import sys
import select
import struct
import os.path
import errno

SSH2_FX_OK = 0
SSH2_FX_EOF = 1
SSH2_FX_NO_SUCH_FILE = 2
SSH2_FX_PERMISSION_DENIED = 3
SSH2_FX_FAILURE = 4
SSH2_FX_OP_UNSUPPORTED = 8

SSH2_FXP_INIT = 1
SSH2_FXP_VERSION = 2
SSH2_FXP_OPEN = 3
SSH2_FXP_CLOSE = 4
SSH2_FXP_READ = 5
SSH2_FXP_WRITE = 6
SSH2_FXP_LSTAT = 7
SSH2_FXP_FSTAT = 8
SSH2_FXP_FSETSTAT = 10
SSH2_FXP_OPENDIR = 11
SSH2_FXP_READDIR = 12
SSH2_FXP_MKDIR = 14
SSH2_FXP_RMDIR = 15
SSH2_FXP_REALPATH = 16
SSH2_FXP_STAT = 17

SSH2_FXP_STATUS = 101
SSH2_FXP_HANDLE = 102
SSH2_FXP_DATA = 103
SSH2_FXP_NAME = 104
SSH2_FXP_ATTRS = 105

SSH2_FXP_EXTENDED = 200

SSH2_FILEXFER_VERSION = 3

SSH2_FXF_READ = 0x00000001
SSH2_FXF_WRITE = 0x00000002
SSH2_FXF_APPEND = 0x00000004
SSH2_FXF_CREAT = 0x00000008
SSH2_FXF_TRUNC = 0x00000010

SSH2_FILEXFER_ATTR_SIZE = 0x00000001
SSH2_FILEXFER_ATTR_UIDGID = 0x00000002
SSH2_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH2_FILEXFER_ATTR_ACMODTIME = 0x00000008
SSH2_FILEXFER_ATTR_EXTENDED = 0x80000000

class SFTPException(Exception):
    def __init__(self, msg=None):
        self.msg = msg

class SFTPForbidden(SFTPException):
    pass

class SFTPNotFound(SFTPException):
    pass

class SFTPServerObject(object):
    def __init__(self, server, name, cmd=os.stat, force_name=None):
        self.server = server
        self.server.log('%s == %s' % (name, self.server.home))
        self.name = os.path.realpath(name)
        if not self.name.startswith(self.server.home + '/') and self.name != self.server.home:
            self.server.log('%s == %s / %s' % (self.name, self.server.home, self.server.parent))
            if not (force_name == '..' and self.name == self.server.parent):
                raise SFTPForbidden()
        self.stat = cmd(self.name)
        self.flags = SSH2_FILEXFER_ATTR_SIZE | SSH2_FILEXFER_ATTR_UIDGID | SSH2_FILEXFER_ATTR_PERMISSIONS | SSH2_FILEXFER_ATTR_ACMODTIME
        self.attrs = struct.pack('>IQIIIII', self.flags, self.stat.st_size,
                         self.stat.st_uid,
                         self.stat.st_gid,
                         self.stat.st_mode,
                         self.stat.st_atime,
                         self.stat.st_mtime)
        self.rel_name = os.path.split(self.name)[1]
        if force_name:
            self.rel_name = force_name
        self.long_name = self.name
        

class SFTPServerHandle(object):
    def __init__(self, server, filename, flags=0, attrib={}):
        self.name = os.path.realpath(filename)
        self.server = server
        if self.server.handle_cnt == 0xffffffffffffffff:
            raise OverflowError()
        self.server.handle_cnt+=1
        # we use a string as the handle key
        self.id = str(self.server.handle_cnt)
        self.server.handles[self.id] = self
        self.isdir = False
        self.isfile = False
        self.is_reading = False
        if os.path.isdir(self.name):
            self.isdir = True
        if os.path.isfile(self.name) or not os.path.exists(self.name):
            mode = 'r'
            if flags & SSH2_FXF_WRITE:
                mode = 'w'
            if flags & SSH2_FXF_APPEND:
                mode = 'a'
            if flags & SSH2_FXF_TRUNC:
                mode = 'w+'
            if flags & SSH2_FXF_CREAT:
                mode = 'w'
            self.file = open(self.name, mode)
            self.fd = self.file.fileno()
            self.isfile = True

    def close(self):
        if self.isfile:
            self.file.close() 
        del(self.server.handles[self.id])
    

class SFTPServer(object):
    def __init__(self, home, logfile=None, fd_in=0,fd_out=1,raise_on_error=False):
        self.input_queue = ''
        self.output_queue = ''
        self.payload = ''
        self.fd_in = fd_in
        self.fd_out = fd_out
        self.buffer_size = 8192
        self.home = os.path.realpath(home)
        self.parent = os.path.split(self.home)[0]
        self.handles = {}
        self.handle_cnt = 0
        self.raise_on_error = raise_on_error
        os.chdir(self.home)
        self.logfile = None
        if logfile:
            self.logfile = open(logfile, 'a')
            sys.stderr = self.logfile

    def log(self, txt):
        if not self.logfile: return
        self.logfile.write(txt + '\n')
        self.logfile.flush()

    def consume_int(self):
        value, = struct.unpack('>I', self.payload[0:4])
        self.payload = self.payload[4:]
        return value

    def consume_int64(self):
        value, = struct.unpack('>Q', self.payload[0:8])
        self.payload = self.payload[8:]
        return value
        
    def consume_string(self):
        slen = self.consume_int()
        s = self.payload[0:slen]
        self.payload = self.payload[slen:]
        return s

    def consume_attrib(self):
        attrib = {}
        flags = self.consume_int()
        if flags & SSH2_FILEXFER_ATTR_SIZE:
            attrib['size'] = self.consume_int64()
        if flags & SSH2_FILEXFER_ATTR_UIDGID:
            attrib['uid'] = self.consume_int()
            attrib['gid'] = self.consume_int()
        if flags & SSH2_FILEXFER_ATTR_PERMISSIONS:
            attrib['perm'] = self.consume_int()
        if flags & SSH2_FILEXFER_ATTR_ACMODTIME:
            attrib['atime'] = self.consume_int()
            attrib['mtime'] = self.consume_int()
        if flags & SSH2_FILEXFER_ATTR_EXTENDED:
            count = self.consume_int()
            if count > 0: attrib['extended'] = []
            for i in range(0, count):
                attrib['extended'].append({ self.consume_string(): self.consume_string()})   
        return attrib

    def send_msg(self, msg):
        msg_len = struct.pack('>I', len(msg))
        self.output_queue += msg_len + msg

    def send_status(self, sid, status, exc=None):
        if status != SSH2_FX_OK and self.raise_on_error:
            if exc:
                raise exc
            raise SFTPException()
        self.log("sending status %d" % status)
        msg = struct.pack('>BII', SSH2_FXP_STATUS, sid, status)
        if exc:
            msg += struct.pack('>I', len(exc)) + exc.msg 
            msg += struct.pack('>I', 0)
        self.send_msg(msg)

    def send_data(self, sid, buf, size):
        msg = struct.pack('>BII', SSH2_FXP_DATA, sid, size)
        msg += buf
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
        while True:
            if len(self.input_queue) < 5: return
            msg_len, msg_type = struct.unpack('>IB', self.input_queue[0:5])
            if len(self.input_queue) < msg_len + 4: return
            self.payload = self.input_queue[5:4+msg_len]
            self.input_queue = self.input_queue[msg_len + 4:]
            if msg_type == SSH2_FXP_INIT:
                msg = struct.pack('>BI', SSH2_FXP_VERSION, SSH2_FILEXFER_VERSION)
                self.send_msg(msg)
            else:
                msg_id = self.consume_int()
                if msg_type in self.table.keys():
                    try:
                        self.table[msg_type](self, msg_id)
                    except SFTPForbidden as e:
                        self.send_status(msg_id, SSH2_FX_PERMISSION_DENIED, e)
                    except SFTPNotFound as e:
                        self.send_status(msg_id, SSH2_FX_NO_SUCH_FILE, e)
                    except OSError as e:
                        if e.errno == errno.ENOENT:
                            self.send_status(msg_id, SSH2_FX_NO_SUCH_FILE, SFTPNotFound())
                        else:
                            self.send_status(msg_id, SSH2_FX_FAILURE)
                    except:
                        self.send_status(msg_id, SSH2_FX_FAILURE)
                else:
                    self.send_status(msg_id, SSH2_FX_OP_UNSUPPORTED)

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
        if len(filename) == 0: filename = '.'
        self.send_names(sid, [SFTPServerObject(self, filename)])

    def _stat(self, sid):
        filename = self.consume_string()
        try:
            item = SFTPServerObject(self, filename)
            msg = struct.pack('>BI', SSH2_FXP_ATTRS, sid)
            msg += item.attrs
            self.send_msg(msg) 
        except SFTPForbidden as e:
            raise e
        except:
            self.send_status(sid, SSH2_FX_NO_SUCH_FILE)

    def _lstat(self, sid):
        filename = self.consume_string()
        try:
            item = SFTPServerObject(self, filename, os.lstat)
            msg = struct.pack('>BI', SSH2_FXP_ATTRS, sid)
            msg += item.attrs
            self.send_msg(msg)
        except SFTPForbidden as e:
            raise e
        except:
            self.send_status(sid, SSH2_FX_NO_SUCH_FILE)

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
            if name in ('.', '..'):
                true_path = SFTPServerObject(self, os.path.join(handle.name, name), force_name=name)
            else:
                true_path = SFTPServerObject(self, os.path.join(handle.name, name))
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

    def _open(self, sid):
        filename = self.consume_string()
        flags = self.consume_int()
        attrib = self.consume_attrib()
        handle = SFTPServerHandle(self, filename, flags, attrib)
        msg = struct.pack('>BII', SSH2_FXP_HANDLE, sid, len(handle.id))
        msg += handle.id
        self.send_msg(msg)

    def _read(self, sid):
        handle_id = self.consume_string()
        handle = self.handles[handle_id]
        off = self.consume_int64()
        size = self.consume_int()
        os.lseek(handle.fd, off, os.SEEK_SET)
        chunk = os.read(handle.fd, size)
        if len(chunk) == 0:
            self.send_status(sid, SSH2_FX_EOF)
        elif len(chunk) > 0:
            self.send_data(sid, chunk, len(chunk))
        else:
            self.send_status(sid, SSH2_FX_FAILURE)

    def _write(self, sid):
        handle_id = self.consume_string()
        handle = self.handles[handle_id]
        off = self.consume_int64()
        chunk = self.consume_string()
        os.lseek(handle.fd, off, os.SEEK_SET)
        rlen = os.write(handle.fd, chunk)
        if rlen == len(chunk):
            self.send_status(sid, SSH2_FX_OK)
        else:
            self.send_status(sid, SSH2_FX_FAILURE)

    def _mkdir(self, sid):
        filename = self.consume_string()
        attrib = self.consume_attrib()
        os.mkdir(filename)
        self.send_status(sid, SSH2_FX_OK)

    def _rmdir(self, sid):
        filename = self.consume_string()
        os.rmdir(filename)
        self.send_status(sid, SSH2_FX_OK)

    table = {
                 SSH2_FXP_REALPATH: _realpath,
                 SSH2_FXP_LSTAT: _lstat,
                 SSH2_FXP_STAT: _stat,
                 SSH2_FXP_OPENDIR: _opendir,
                 SSH2_FXP_READDIR: _readdir,
                 SSH2_FXP_CLOSE: _close,
                 SSH2_FXP_OPEN: _open,
                 SSH2_FXP_READ: _read,
                 SSH2_FXP_WRITE: _write,
                 SSH2_FXP_MKDIR: _mkdir,
                 SSH2_FXP_RMDIR: _rmdir,
             }
