#!/usr/bin/python
# vim:ft=python
"""
To create digital signature you need valid RSA private key. Filename to private
key is passed as command line parameter.

On succesful signing command returns exit status 0. On failure it returns error
code.

As a requirement, all files for signing have to be in the directory or
subdirectory of signature file.

To authenticate creator of manifest it is signed with OpenSSL / SMIME digital
signature.

For more information about OpenSSL/SMIME signatures and RSA public/private
keypairs see:

    * http://www.openssl.org/docs/apps/req.html
    * http://www.madboa.com/geek/openssl/

"""

import argparse
import os
import sys

import dpres_signature.signature


def parse_arguments(arguments):
    """Parse commandline arguments."""
    description = "Tool for creating a signature for a file"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        'targets', nargs='*',
        help=("File list of files to be signed separated with whitespace."))
    parser.add_argument(
        "-c", "--ca-path",
        metavar="CAPATH",
        default="/etc/ssl/certs",
        help=("Path to OpenSSL certificates"))
    parser.add_argument(
        "-k", "--key-path",
        metavar="KEYPATH",
        required=True,
        help=("Path to private key"))
    parser.add_argument(
        "-s", "--signature-path",
        metavar="SIGNATUREPATH",
        required=True,
        help=("Signature path"))

    args = parser.parse_args(arguments[1:])
    return args


def main(arguments=None):
    """main."""
    if arguments is None:
        arguments = sys.argv
    args = parse_arguments(arguments)
    signature = dpres_signature.signature.create_signature(
        base_path=os.path.dirname(args.signature_path),
        key_path=args.key_path,
        include_patterns=args.targets,
        cert_path=args.ca_path
    )

    with open(args.signature_path, 'wb') as outfile:
        outfile.write(signature)

    return 0


if __name__ == '__main__':
    RETVAL = main()
    sys.exit(RETVAL)
