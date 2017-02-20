#!/usr/bin/python
# vim:ft=python
"""
Create digital signature file for a file(s) with command::

    sign-file <target1 target2 ...> [rsa-private-key.pem] [signture_path]

To create digital signature you need valid RSA private key. Filename to private
key is passed as command line parameter.

On succesful signing command returns exit status 0. On failure returns error
code.

Digital signature a manifest file :file:`varmiste.sig` that lists all files,
that are to be signed. As a requirement, all files for signing have to be in
the directory or subdirectory of varmiste.sig given in arguments.

To authenticate creator of manifest it is signed with OpenSSL / SMIME digital
signature.

For more information about OpenSSL/SMIME signatures and RSA public/private
keypairs see:

    * http://www.openssl.org/docs/apps/req.html
    * http://www.madboa.com/geek/openssl/

"""

import sys
import argparse
import dpres_signature.signature


def parse_arguments(arguments):
    """Parse commandline arguments."""
    description = \
        ("Tool for signing and checking signature of a file.")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        'targets', nargs='*',
        help=("File list of files to be signed separated with whitespace."))
    parser.add_argument(
        "-c", "--ca-path",
        default="/etc/ssl/certs",
        metavar="CAPATH",
        help=("Path to OpenSSL certificates"))
    parser.add_argument(
        "-k", "--key-path",
        default=None,
        metavar="KEYPATH",
        help=("Path to private key"))
    parser.add_argument(
        "-s", "--signature-path",
        default=None,
        metavar="SIGNATUREPATH",
        help=("Signature path"))

    args = parser.parse_args(arguments[1:])
    if args.key_path is None or args.signature_path is None:
        raise RuntimeError("Missing arguments %s" % args)
    return args


def main(arguments):
    """main."""
    if arguments is None:
        arguments = sys.argv
    args = parse_arguments(arguments)
    return dpres_signature.signature.signature_write(
        signature_path=args.signature_path,
        key_path=args.key_path,
        cert_path=args.ca_path,
        include_patterns=args.targets)


if __name__ == '__main__':
    RETVAL = main()
    sys.exit(RETVAL)
