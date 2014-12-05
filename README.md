#pysftpserver
An OpenSSH SFTP wrapper written in Python.

##Features
* Possibility to [automatically jail users](#authorized_keys_magic) in a virtual chroot environment as soon as they login.
* Compatible with both Python 2 and Python 3.
* Fully extensible and customizable.
* Totally conforms to the [SFTP RFC](https://filezilla-project.org/specs/draft-ietf-secsh-filexfer-02.txt).

##Installation
Simply install pysftpserver with pip:
```bash
$ pip install pysftpserver # add the --user flag to install it just for you
```

Otherwise, you could always clone this repository and manually launch `setup.py`:
```bash
$ git clone https://github.com/unbit/pysftpserver.git
$ python setup.py install
```

##Usage
We provide, as a fully working example, an SFTP storage that jails users in a virtual chroot environment.

You can use it by launching `pysftpjail` with the following options:
```
pysftpjail -h

usage: pysftpjail [-h] [--logfile LOGFILE] [--umask UMASK] chroot

An OpenSSH SFTP server wrapper that jails the user in a chroot directory.

positional arguments:
  chroot                the path of the chroot jail

optional arguments:
  -h, --help            show this help message and exit
  --logfile LOGFILE, -l LOGFILE
                        path to the logfile
  --umask UMASK, -u UMASK
                        set the umask of the SFTP server
```

###authorized_keys magic
With `pysftpjail` you can jail any user in the virtual chroot as soon as she connects to the SFTP server.
You can do it by simply prepending the `pysftpjail` command to the user entry in your SSH `authorized_keys` file, e.g.:
```
command="pysftpjail path_to_your_jail" ssh-rsa AAAAB3[... and so on]
```

Probably, you'll want to add the following options too:
```
no-port-forwarding,no-x11-forwarding,no-agent-forwarding
```

Achieving as final result:
```
command="pysftpjail path_to_your_jail",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-rsa AAAAB3[... and so on]
```

##Customization
We provide two examples of SFTP storage: simple and jailed.
Anyway, you can subclass our [generic storage](pysftpserver/storage.py) and you can adapt it to your needs.
Any contribution is welcomed, as always.

##Tests
You can use [nose](https://nose.readthedocs.org/en/latest/) for tests.
From the project directory, simply run:
```bash
$ nosetests
$ python setup.py test # alternatively
```

