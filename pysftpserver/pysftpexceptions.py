"""SFTP Exceptions."""


class SFTPException(Exception):

    def __init__(self, msg=None):
        self.msg = msg


class SFTPForbidden(SFTPException):
    pass


class SFTPNotFound(SFTPException):
    pass
