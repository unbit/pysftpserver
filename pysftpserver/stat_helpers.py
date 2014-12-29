from stat import *
import time

import pwd
import grp

_filemode_table = (
    ((S_IFLNK,         "l"),
     (S_IFREG,         "-"),
     (S_IFBLK,         "b"),
     (S_IFDIR,         "d"),
     (S_IFCHR,         "c"),
     (S_IFIFO,         "p")),

    ((S_IRUSR,         "r"),),
    ((S_IWUSR,         "w"),),
    ((S_IXUSR | S_ISUID, "s"),
     (S_ISUID,         "S"),
     (S_IXUSR,         "x")),

    ((S_IRGRP,         "r"),),
    ((S_IWGRP,         "w"),),
    ((S_IXGRP | S_ISGID, "s"),
     (S_ISGID,         "S"),
     (S_IXGRP,         "x")),

    ((S_IROTH,         "r"),),
    ((S_IWOTH,         "w"),),
    ((S_IXOTH | S_ISVTX, "t"),
     (S_ISVTX,         "T"),
     (S_IXOTH,         "x"))
)

_paddings = (  # the len of each field of the longname string
    10,
    3,
    8,
    8,
    9,
    12
)


def filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return ''.join(perm).encode()


def stat_to_longname(st, filename):
    """
    Some clients (FileZilla, I'm looking at you!)
    require 'longname' field of SSH2_FXP_NAME
    to be 'alike' to the output of ls -l.
    So, let's build it!

    Encoding side: unicode sandwich.
    """

    longname = [
        filemode(st.st_mode).decode(),
        str(st.st_nlink),
        pwd.getpwuid(st.st_uid)[0],
        grp.getgrgid(st.st_gid)[0],
        str(st.st_size),
        time.strftime("%b %d %H:%M", time.gmtime(st.st_mtime)),
    ]

    # add needed padding
    longname = [
        field + ' ' * (_paddings[i] - len(field))
        for i, field in enumerate(longname)
    ]
    longname.append(filename.decode())  # append the filename

    # and return the string
    return ' '.join(longname).encode()
