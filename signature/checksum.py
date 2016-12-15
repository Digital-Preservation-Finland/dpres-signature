"""Module for checksum verification."""
import hashlib


class BigFile(object):
    """
    A util class for handling large file checksums.
    """
    def __init__(self, algorithm='sha1'):
        """init"""
        # Accept MD5 and different SHA variations
        algorithm = algorithm.lower().replace('-', '').strip()
        self.checksum = hashlib.new(algorithm)

    def hexdigest(self, filename):
        """Calculate hexdigest"""
        with open(filename, 'rb') as input_file:
            for chunk in iter(lambda: input_file.read(1024 * 1024), b''):
                self.checksum.update(chunk)
        return self.checksum.hexdigest()

    def verify_file(self, filename, hexdigest):
        """Verify file"""
        file_hexdigest = self.hexdigest(filename)
        return checksums_match(file_hexdigest, hexdigest)


def checksums_match(checksum_expected, checksum_to_test):
    """Check checksums"""
    return ((len(checksum_expected) > 0) and
            (checksum_expected == checksum_to_test))
