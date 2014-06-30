import sys
from pysftpserver import *

SFTPServer(SFTPServerVirtualChroot(sys.argv[1])).run()
