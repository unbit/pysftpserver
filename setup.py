from setuptools import setup, find_packages

setup(
	name='pysftpserver',
	version='0.1.0',
	description='An OpenSSH SFTP server that jails the user in a chroot directory',
	url='https://github.com/unbit/pysftpserver',
	author="Unbit",
	author_email="info@unbit.com",
	license='MIT',
	packages=find_packages(),
	zip_safe=False
)
