"""
This is a module for creating and verifying SMIME certificates and
signing keys.
"""

import hashlib
import glob
from random import randint

from OpenSSL import crypto
from M2Crypto import BIO, Rand, SMIME
from M2Crypto import X509


def sha1_hexdigest(path):
    """Calculate and return SHA1 digest as hexadecimal ASCII representation.

    :path: Filename to calculate digest
    :returns: HEX digest as strings

    """
    sha1 = hashlib.sha1()
    infile = open(path)
    while True:
        buf = infile.read(0x100000)
        if not buf:
            break
        sha1.update(buf)
    infile.close()
    return sha1.hexdigest()


class ChecksumError(Exception):
    """Manifest errors"""
    pass


class FileEntry(object):
    """Manifest entries"""

    def __init__(self, filename, algorithm, hex_digest):
        """init entry"""
        self.filename = filename
        self.algorithm = algorithm
        self.hex_digest = hex_digest

    @classmethod
    def from_string(cls, line):
        """Parse manifest entry from string"""
        fields = line.rstrip().split(':')
        return cls(fields[0], fields[1], fields[3])

    @classmethod
    def from_file(cls, filename, algorithm='shq1'):
        """Read manifest entry from filename"""
        return cls(filename, algorithm, sha1_hexdigest(filename))

    def verify(self):
        """Verify file checksum"""
        if self.hex_digest != sha1_hexdigest(self.filename):
            raise ChecksumError("Checksum mismatch %s" % self.filename)

    def __str__(self):
        return ":".join([self.filename, self.algorithm, self.hex_digest])


class Manifest(object):
    """Generate and verify manifest files"""

    def __init__(self):
        """Initialize the class"""
        self.manifest = []

    def add_file(self, filename):
        """Add file to manifest"""
        self.manifest.append(FileEntry.from_file(filename))

    def verify(self):
        """Verify all files in manifest"""
        for entry in self.manifest:
            entry.verify()

    def from_string(self, manifest_in):
        """Load manifest from string"""
        for line in manifest_in.splitlines():
            self.manifest.append(FileEntry.from_string(line))

    def to_string(self):
        """Return string representation of the manifest"""
        lines = []
        for entry in self.manifest:
            lines.append(entry.__str__())
        return "\n".join(lines)

    def __str__(self):
        """Return string representation of the manifest"""
        return self.to_string()


class Subject(object):
    """Friendly names forX509 subject names"""

    def __init__(self):
        """Setup default name values"""
        self.country = 'FI'
        self.state = 'Uusimaa'
        self.location = 'Espoo'
        self.organization = 'ACME org'
        self.organization_unit = 'ACME unit'
        self.common_name = 'localhost.local'

    @classmethod
    def from_x509(cls, x509_subject):
        """Init from m2crypto X509_Name object"""
        _cls = cls()
        _cls.country = x509_subject.C
        _cls.state = x509_subject.ST
        _cls.location = x509_subject.L
        _cls.organization = x509_subject.O
        _cls.organization_unit = x509_subject.OU
        _cls.common_name = x509_subject.CN
        return _cls

    def to_x509(self):
        """Return m2crypto X509_Name object"""
        x509_name = X509.X509_Name()
        x509_name.C = self.country
        x509_name.ST = self.state
        x509_name.L = self.location
        x509_name.O = self.organization
        x509_name.OU = self.organization_unit
        x509_name.CN = self.common_name
        return x509_name

    def __str__(self):
        """Return string Return subject as string"""
        return " ".join([
            self.country, self.state, self.location, self.organization,
            self.organization_unit, self.common_name])


def write_certificate(key_path, cert_path, subject, expiry_days=1):
    """Create X509 certificate and private key

    http://www.openssl.org/docs/apps/req.html
    http://www.madboa.com/geek/openssl/
    https://pyopenssl.readthedocs.io/en/stable/api/crypto.html#certificates

    """
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.set_serial_number(randint(1, 100000000000000))
    cert.set_subject(subject.to_x509())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(24*60*60*expiry_days)

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    with open(cert_path, 'w') as outfile:
        outfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(key_path, 'w') as outfile:
        outfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


def smime_sign(cert_path, key_path, message):
    """Sign message with given certificate and signing key"""

    # Seed the PRNG.
    Rand.load_file('.randpool.dat', -1)

    # Instantiate an SMIME object; set it up; sign the buffer.
    smime = SMIME.SMIME()
    smime.load_key(key_path, cert_path)

    message_buf = BIO.MemoryBuffer(message)
    pkcs7 = smime.sign(message_buf, SMIME.PKCS7_DETACHED)

    # Must recreate message buffer, it was consumed by smime.sign()
    message_buf = BIO.MemoryBuffer(message)

    # Destination buffer for combined message
    out = BIO.MemoryBuffer()

    # write message & signature to output buffer
    smime.write(out, pkcs7, message_buf)

    Rand.save_file('.randpool.dat')

    return ''.join([x for x in out.read()])


def smime_verify(ca_path, message):
    """Verify S/MIME pkcs7 signed message.

    :ca_path: Path to CA certificate store
    :returns: Message data on succesful verification

    """

    buf = BIO.MemoryBuffer(message)
    pkcs7, data = SMIME.smime_load_pkcs7_bio(buf)

    certificate_x509 = pkcs7.get0_signers(X509.X509_Stack())

    ca_store = X509.X509_Store()
    ca_store.load_info(ca_path)

    smime = SMIME.SMIME()
    smime.set_x509_stack(certificate_x509)
    smime.set_x509_store(ca_store)

    return smime.verify(pkcs7, data)


def signature_verify(signature_path, ca_path='/etc/ssl/certs/ca-budle.crt'):
    """Verify SIP signature files aka. signed manifest files"""
    with open(signature_path) as infile:
        manifest_data = smime_verify(ca_path, infile.read())
    manifest = Manifest()
    manifest.from_string(manifest_data)
    manifest.verify()


def signature_write(signature_path, key_path, cert_path, include_patterns):
    """Generate SIP signature files aka. signed manifest files"""
    manifest = Manifest()
    for pattern in include_patterns:
        for path in glob.glob(pattern):
            manifest.add_file(path)

    signature = smime_sign(key_path, cert_path, manifest.to_string())

    with open(signature_path, 'w') as outfile:
        outfile.write(signature)
