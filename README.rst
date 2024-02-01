Digital Preservation Signature
==============================
This module is used for creating signed SMIME manifests and verifying existing signed manifest files.

Requirements
------------

Installation and usage requires Python 3.9 or newer.
The software is tested with Python 3.9 on AlmaLinux 9 release.

Installation using RPM packages (preferred)
-------------------------------------------

Installation on Linux distributions is done by using the RPM Package Manager.
See how to `configure the PAS-jakelu RPM repositories`_ to setup necessary software sources.

.. _configure the PAS-jakelu RPM repositories: https://www.digitalpreservation.fi/user_guide/installation_of_tools 

After the repository has been added, the package can be installed by running the following command::

    sudo dnf install python3-dpres-signature

Usage
-----
Verify digital signature file with command ::

    verify-signed-file -s <signture_path> [-k <public_key_directory>] [<manifest_file1 manifest_file2 ...>]

In the arguments, a list of manifest files will verify that given files are found in the manifest in the signature file.
If public key directory is not given, path /etc/ssl/certs is used.

Create digital signature file for a list of files with command ::

    sign-file -s <signature_path> -k <private_key_path> -c <cert_path> <target1 target2 ...>

Installation using Python Virtualenv for development purposes
-------------------------------------------------------------

Packages openssl-devel, swig and gcc are required in your system to install M2Crypto,
which is used in this software.

Create a virtual environment::
    
    python3 -m venv venv

Run the following to activate the virtual environment::

    source venv/bin/activate

Install the required software with commands::

    pip install --upgrade pip==20.2.4 setuptools
    pip install -r requirements_dev.txt
    pip install .
    make install

To deactivate the virtual environment, run ``deactivate``.
To reactivate it, run the ``source`` command above.

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
