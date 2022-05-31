Digital Preservation Signature
==============================
This module is used for creating signed SMIME manifests and verifying existing signed manifest files.

Installation
------------

Installation and usage requires Python 2.7, or 3.6 or newer.
The software is tested with Python 3.6 on Centos 7.x release. Python 2.7 support will be removed in the future.

Packages openssl-devel, swig and gcc are required in your system to install M2Crypto,
which is used for signing the packages with digital signature.

For Python 3.6 or newer, create a virtual environment::
    
    python3 -m venv venv

For Python 2.7, get python-virtualenv software and create a virtual environment::

    sudo yum install python-virtualenv
    virtualenv venv

Run the following to activate the virtual environment::

    source venv/bin/activate

Install the required software with commands::

    pip install --upgrade pip==20.2.4 setuptools  # Only for Python 3.6 or newer
    pip install --upgrade pip setuptools          # Only for Python 2.7
    pip install -r requirements_dev.txt
    pip install .
    make install

To deactivate the virtual environment, run ``deactivate``.
To reactivate it, run the ``source`` command above.

Usage
-----
Verify digital signature file with command ::

    verify-signed-file -s <signture_path> [-k <public_key_directory>] [<manifest_file1 manifest_file2 ...>]

In the arguments, a list of manifest files will verify that given files are found in the manifest in the signature file.
If public key directory is not given, path /etc/ssl/certs is used.

Create digital signature file for a list of files with command ::

    sign-file -s <signature_path> -k <private_key_path> -c <cert_path> <target1 target2 ...>

Copyright
---------
Copyright (C) 2018 CSC - IT Center for Science Ltd.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.
