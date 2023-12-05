"""Calculate file checksums"""

import hashlib


def _hashlib_hexdigest(path, hash_object):
    """Calculate and return digest as hexadecimal ASCII representation using
    hashlib library.

    :path: Filename to calculate digest
    :hash_object: hashlib hash object used in calculation

    :returns: HEX digest as strings

    """
    with open(path, "rb") as infile:
        while True:
            buf = infile.read(0x100000)
            if not buf:
                break
            hash_object.update(buf)

        return hash_object.hexdigest()


def sha1_hexdigest(path):
    """Calculate and return SHA1 digest as hexadecimal ASCII representation.

    :path: Filename to calculate digest
    :returns: HEX digest as strings

    """
    sha1 = hashlib.sha1()
    return _hashlib_hexdigest(path, sha1)


def sha256_hexdigest(path):
    """Calculate and return SHA256 digest as hexadecimal ASCII representation.

    :path: Filename to calculate digest
    :returns: HEX digest as strings

    """
    sha256 = hashlib.sha256()
    return _hashlib_hexdigest(path, sha256)
