#!/usr/bin/python
# vim:ft=python
"""
To verify digital signature you need valid RSA public key. Filename to public
key is passed as command line parameter.

On succesful signing command returns exit status 0. On failure returns error
code.

Digital signature is a manifest file that lists all files,
that are signed. As a requirement, all signed files have to be in
the directory or subdirectory of the signature file.

"""
from __future__ import print_function
import sys
import argparse
import dpres_signature.signature


def parse_arguments(arguments):
    """Parse commandline arguments."""
    description = "Tool for checking signature of a file."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        'files', nargs='*',
        default='',
        help=("Files to be checked from manifest, separated with whitespace."))
    parser.add_argument(
        '-s', '--signature-path',
        required=True,
        help=("Signature files full path"))
    parser.add_argument(
        "-k", "--key-path",
        default="/etc/ssl/certs",
        metavar="KEYPATH",
        help=("Path to public key"))
    args = parser.parse_args(arguments[1:])
    return args


def main(arguments=None):
    """main."""
    if arguments is None:
        arguments = sys.argv
    args = parse_arguments(arguments)
    try:
        return dpres_signature.signature.signature_verify(
            signature_path=args.signature_path,
            ca_path=args.key_path, filelist=args.files)
    except Exception as err:  # pylint: disable=broad-except
        print(str(err), file=sys.stderr)
        return 117


if __name__ == '__main__':
    RETVAL = main()
    sys.exit(RETVAL)
