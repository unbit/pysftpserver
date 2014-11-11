import argparse
from pysftpserver.server import SFTPServer
from pysftpserver.virtualchroot import SFTPServerVirtualChroot


def main():
    parser = argparse.ArgumentParser(
        description='An OpenSSH SFTP server that jails the user in a chroot directory.'
    )

    parser.add_argument('chroot', type=str,
                        help='the path of the chroot jail')
    parser.add_argument('--logfile', '-l', dest='logfile',
                        help='path to the logfile')
    parser.add_argument('--umask', '-u', dest='umask',
                        help='set the umask of the SFTP server')

    args = parser.parse_args()
    SFTPServer(
        storage=SFTPServerVirtualChroot(
            args.chroot,
            umask=args.umask
        ),
        logfile=args.logfile
    ).run()


if __name__ == '__main__':
    if not __package__:
        __package__ = "pysftpserver"
    main()
