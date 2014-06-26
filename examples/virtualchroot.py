import sys
from pysftpserver import *

SFTPServer(sys.argv[1]).run()
