"""Calculate file checksums"""

import os
import hashlib


def sha1_hexdigest(file_path, base_path):
    """Calculate and return SHA1 digest as hexadecimal ASCII representation.

    :path: Filename to calculate digest
    :returns: HEX digest as strings

    """
    sha1 = hashlib.sha1()
    full_path = os.path.join(base_path, file_path)
    infile = open(full_path)
    while True:
        buf = infile.read(0x100000)
        if not buf:
            break
        sha1.update(buf)
    infile.close()
    return sha1.hexdigest()
