Digital Preservation Signature
==============================
This module is used for creating signed SMIME manifests and verifying existing signed manifest files.

Installation
------------

This software is tested with Python 2.7 with Centos 7.x / RHEL 7.x releases.

Installation and usage requires additional software in system $PATH:

    * Python 2.7
    * pip
    * GNU Make

Install requirements and scripts with commands::

    pip install -r requirements_dev.txt
    make install

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
