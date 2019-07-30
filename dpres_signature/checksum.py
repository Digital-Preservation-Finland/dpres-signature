"""Calculate file checksums"""
from __future__ import unicode_literals

import hashlib
from io import open


def sha1_hexdigest(path):
    """Calculate and return SHA1 digest as hexadecimal ASCII representation.

    :path: Filename to calculate digest
    :returns: HEX digest as strings

    """
    sha1 = hashlib.sha1()
    with open(path, "rb") as infile:
        while True:
            buf = infile.read(0x100000)
            if not buf:
                break
            sha1.update(buf)

        return sha1.hexdigest()
