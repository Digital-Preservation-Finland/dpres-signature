"""Write and verify manifest files"""

import os

from dpres_signature.checksum import sha1_hexdigest, sha256_hexdigest


class ManifestError(Exception):
    """Manifest errors"""


class FileEntry:
    """Manifest entries"""

    checksum_functions = {
        'sha1': sha1_hexdigest,
        'sha256': sha256_hexdigest
    }

    def __init__(self, filename, algorithm, hex_digest, base_path):
        """init entry"""
        self.filename = filename
        self.algorithm = algorithm
        self.hex_digest = hex_digest
        self.base_path = base_path

    @classmethod
    def from_string(cls, line, base_path):
        """Parse manifest entry from string"""
        fields = line.rstrip().split(':')
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
        if self.hex_digest != file_hex_digest:
            raise ManifestError("Checksum mismatch {}: {} != {}".format(
                self.filename, self.hex_digest, file_hex_digest))

    def __str__(self):
        """Return Unicode string representation of the file entry"""
        return ":".join([self.filename, self.algorithm, self.hex_digest])

    def __bytes__(self):
        """Return byte string representation of the file entry"""
        return str(self).encode("utf-8")


class Manifest:
    """Generate and verify manifest files"""

    def __init__(self, base_path=None):
        """Initialize the class"""
        self.entries = []
        self.base_path = base_path

    def add_file(self, filename, algorithm='sha1'):
        """Add file to manifest"""
        self.entries.append(
            FileEntry.from_file(
                filename=filename,
                base_path=self.base_path,
                algorithm=algorithm
            )
        )

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
        """Return Unicode string representation of the manifest"""
        return "\n".join([str(line) for line in self.entries])

    def __bytes__(self):
        """Return byte string representation of the manifest"""
        return str(self).encode("utf-8")
