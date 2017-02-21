Digital Preservation Signature
==============================
This module is used for creating signed SMIME manifests and verifying existing signed manifest files. Two commandline tools are provided, sign-file and verify-file.

Installation
------------
yum install -y dpres-signature

Usage
-----
Verify digital signature file for a file(s) with command ::

    verify-file <signture_path> [rsa-public-key.pem]

Create digital signature file for a list of files with command ::

    sign-file <target1 target2 ...> [rsa-private-key.pem] [signture_path]

See more usage documetnation from ::

    sign-file --help

and ::

    verify-file --help

Contribution
------------
All contribution is welcome. Pull requests are handled according our schedule by our specialists and we aim to be fairly active on this. Most on the development takes place in `CSC - IT Center for Science <www.csc.fi>`_. 

