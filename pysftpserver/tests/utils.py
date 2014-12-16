"""Various utils."""

import os
import struct
import random

root_path = os.path.dirname(os.path.realpath(__file__))


def t_path(filename="."):
    """Get the path of the test file inside test directory."""
    return os.path.join(root_path, filename)


def sftpstring(s):
    return struct.pack('>I', len(s)) + s


def sftpint(n):
    return struct.pack('>I', n)


def sftpint64(n):
    return struct.pack('>Q', n)


def sftpcmd(cmd, *args):
    msg = struct.pack('>BI', cmd, random.randrange(1, 0xffffffff))
    for arg in args:
        msg += arg
    return sftpint(len(msg)) + msg


def get_sftphandle(blob):
    slen, = struct.unpack('>I', blob[9:13])
    return blob[13:13 + slen]


def get_sftpint(blob):
    value, = struct.unpack('>I', blob[5:9])
    return int(value)


def get_sftpname(blob):
    namelen, = struct.unpack('>I', blob[13:17])
    return blob[17:17 + namelen]


def get_sftpstat(blob):
    attrs = dict()
    attrs['size'], attrs['uid'], \
        attrs['gid'], attrs['mode'], \
        attrs['atime'], attrs['mtime'] \
        = struct.unpack('>QIIIII', blob[13:])
    return attrs
