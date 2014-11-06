import sys
from pysftpserver.server import SFTPServer
from pysftpserver.virtualchroot import SFTPServerVirtualChroot

if __name__ == '__main__':
	SFTPServer(
		SFTPServerVirtualChroot(sys.argv[1])
	).run()
