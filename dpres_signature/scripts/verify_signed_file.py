#!/usr/bin/python
# vim:ft=python
"""
Verify digital signature file for a file(s) with command::

    verify-signed-file <signture_path> [rsa-public-key.pem]

To verify digital signature you need valid RSA public key. Filename to public
key is passed as command line parameter.

On succesful signing command returns exit status 0. On failure returns error
code.

Digital signature is a manifest file that lists all files,
that are signed. As a requirement, all signed files have to be in
the directory or subdirectory of varmiste.sig given in arguments.

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
        '-s', '--signature-path',
        help=("Signature files full path"))
    parser.add_argument(
        "-k", "--key-path",
        default="/etc/ssl/certs",
        metavar="KEYPATH",
        help=("Path to public key"))
    args = parser.parse_args(arguments[1:])

    if args.signature_path is None or args.key_path is None:
        raise RuntimeError("Missing argument(s): targets")
    return args


def main(arguments=None):
    """main."""
    if arguments is None:
        arguments = sys.argv
    args = parse_arguments(arguments)
    return dpres_signature.signature.signature_verify(
        signature_path=args.signature_path,
        ca_path=args.key_path)


if __name__ == '__main__':
    RETVAL = main()
    sys.exit(RETVAL)
