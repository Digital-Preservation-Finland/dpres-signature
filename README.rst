Digital Preservation Signature
==============================
This module is used for creating signed SMIME manifests and verifying existing signed manifest files.

Installation
------------

Install with command::

    pip install -r requirements_dev.txt

Usage
-----
Verify digital signature file with command ::

    python dpres_signature/scripts/verify_signed_file.py -s <signture_path> [-k <public_key_directory>] [<manifest_file1 manifest_file2 ...>]

In the arguments, a list of manifest files will verify that given files are found in the manifest in the signature file.
If public key directory is not given, path /etc/ssl/certs is used.

Create digital signature file for a list of files with command ::

    python dpres_signature/scripts/sign_file.py -s <signature_path> -k <private_key_path> -c <cert_path> <target1 target2 ...>

Copyright
=========
All rights reserved to CSC - IT Center for Science Ltd.
