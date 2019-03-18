"""Write and verify manifest files"""

import os
import six

from dpres_signature.checksum import sha1_hexdigest


class ManifestError(Exception):
    """Manifest errors"""


class FileEntry:
    """Manifest entries"""

    checksum_functions = {
        'sha1': sha1_hexdigest
    }

    def __init__(self, filename, algorithm, hex_digest, base_path):
        """init entry"""
        self.filename = six.ensure_str(filename)
        self.algorithm = six.ensure_str(algorithm)
        if hex_digest is not None:
            self.hex_digest = six.ensure_str(hex_digest)
        self.base_path = base_path

    @classmethod
    def from_string(cls, line, base_path):
        """Parse manifest entry from string"""
        fields = line.rstrip().split(b':')
        if len(fields) != 3:
            raise ManifestError
        return cls(
            filename=fields[0],
            algorithm=fields[1],
            hex_digest=fields[2],
            base_path=base_path)

    @classmethod
    def from_file(cls, filename, algorithm='sha1', base_path=None):
        """Read manifest entry from filename"""
        entry = cls(
            filename=filename, algorithm=algorithm,
            hex_digest=None, base_path=base_path)
        entry.hex_digest = entry.file_hex_digest()
        return entry

    def file_hex_digest(self):
        """Return hex_digest from entry file"""
        path = os.path.join(self.base_path, self.filename)
        return self.checksum_functions[self.algorithm](path)

    def verify(self):
        """Verify file checksum"""
        file_hex_digest = self.file_hex_digest()
        if six.ensure_str(self.hex_digest) != file_hex_digest:
            raise ManifestError("Checksum mismatch %s: %s != %s" % (
                self.filename, self.hex_digest, file_hex_digest))

    def __str__(self):
        return ":".join([self.filename, self.algorithm, self.hex_digest])


class Manifest:
    """Generate and verify manifest files"""

    def __init__(self, base_path=None):
        """Initialize the class"""
        self.entries = []
        self.base_path = base_path

    def add_file(self, filename):
        """Add file to manifest"""
        self.entries.append(
            FileEntry.from_file(filename=filename, base_path=self.base_path))

    def verify(self):
        """Verify all files in manifest"""
        for entry in self.entries:
            entry.verify()

    @classmethod
    def from_string(cls, manifest_in, base_path):
        """Load manifest from string"""
        manifest = cls()
        for line in manifest_in.splitlines():
            manifest.entries.append(
                FileEntry.from_string(line, base_path=base_path))
        return manifest

    def __str__(self):
        """Return string representation of the manifest"""
        lines = []
        for entry in self.entries:
            lines.append(str(entry))
        return "\n".join(lines)


# pylint: disable=invalid-name, no-else-return
# These pylint warnings were from the original six-developer.
def _patch_six():
    """Ensure the given six-package contains the mandatory
    ensure_str-functions.
    """

    def _ensure_str(s, encoding='utf-8', errors='strict'):
        """Coerce *s* to `str`.

        For Python 2:
          - `unicode` -> encoded to `str`
          - `str` -> `str`

        For Python 3:
          - `str` -> `str`
          - `bytes` -> decoded to `str`

        Direct copy from release 1.12::

            https://github.com/benjaminp/six/blob/master/six.py#L892
        """
        if not isinstance(s, (six.text_type, six.binary_type)):
            raise TypeError("not expecting type '%s'" % type(s))
        if six.PY2 and isinstance(s, six.text_type):
            s = s.encode(encoding, errors)
        elif six.PY3 and isinstance(s, six.binary_type):
            s = s.decode(encoding, errors)
        return s

    six_funcs = {
        'ensure_str': _ensure_str
    }
    for attr_name, new_func in six_funcs.items():
        if not hasattr(six, attr_name):
            setattr(six, attr_name, new_func)


_patch_six()
