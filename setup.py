"""Setup configuration file."""

from setuptools import setup


def readme():
    """Open the readme."""
    with open('README.md') as f:
        return f.read()

setup(
    name='pysftpserver',
    version='1.4.0',
    description='An OpenSSH SFTP wrapper in Python.',
    long_description=readme(),
    url='https://github.com/unbit/pysftpserver',

    author="Unbit",
    author_email="info@unbit.com",
    license='MIT',

    packages=['pysftpserver'],
    scripts=['bin/pysftpjail', 'bin/pysftpproxy'],
    install_requires=['paramiko', ],
    test_suite='nose.collector',
    tests_require=['nose'],

    keywords=["pysftpserver", "sftp", "openssh", "ssh", 'jail'],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Development Status :: 6 - Mature",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Shells",
        "Topic :: System :: System Shells",
        "Topic :: Internet :: File Transfer Protocol (FTP)",
        "Topic :: Utilities"
    ],

    zip_safe=False,
    include_package_data=True,
)
