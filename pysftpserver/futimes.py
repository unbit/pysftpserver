import ctypes
from ctypes.util import find_library
import sys
import os


class TIMEVAL(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long),
                ("tv_usec", ctypes.c_long)]


def futimes(fd, times):
    """futimes is missing in Python < 3.3.

    As a consequence, pass the call to the below clib.
    """
    if len(times) < 2:
        raise OSError

    if sys.version_info < (3, 3):
        stdlib = find_library("c")
        libc = ctypes.CDLL(stdlib)
        TIMEVALS = TIMEVAL * 2
        if libc.futimes(fd, TIMEVALS((times[0], 0), (times[1], 0))) == -1:
            raise OSError

    else:
        os.utime(fd, times)
