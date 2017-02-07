"""Write and verify manifest files"""

from dpres_signature.checksum import sha1_hexdigest


class ManifestError(Exception):
    """Manifest errors"""
    pass


class FileEntry(object):
    """Manifest entries"""

    checksum_functions = {
        'sha1': sha1_hexdigest
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
        return self.checksum_functions[self.algorithm](
            self.filename, self.base_path)

    def verify(self):
        """Verify file checksum"""
        file_hex_digest = self.file_hex_digest()
        if self.hex_digest != file_hex_digest:
            raise ManifestError("Checksum mismatch %s: %s != %s" % (
                self.filename, self.hex_digest, file_hex_digest))

    def __str__(self):
        return ":".join([self.filename, self.algorithm, self.hex_digest])


class Manifest(object):
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