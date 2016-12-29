"""
This is a module for creating and verifying SMIME certificates and
signing keys.
"""

import hashlib
import glob
from random import randint
from utils import run_command

from OpenSSL import crypto
from M2Crypto import BIO, Rand, SMIME


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

    checksum_functions = {
        'sha1': sha1_hexdigest
    }

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
    def from_file(cls, filename, algorithm='sha1'):
        """Read manifest entry from filename"""
        entry = cls(filename, algorithm, None)
        entry.hex_digest = entry.file_hex_digest()
        return entry

    def file_hex_digest(self):
        """Return hex_digest from entry file"""
        return self.checksum_functions[self.algorithm](self.filename)

    def verify(self):
        """Verify file checksum"""
        if self.hex_digest != self.file_hex_digest():
            raise ChecksumError("Checksum mismatch %s" % self.filename)

    def __str__(self):
        return ":".join([self.filename, self.algorithm, self.hex_digest])


class Manifest(object):
    """Generate and verify manifest files"""

    def __init__(self):
        """Initialize the class"""
        self.entries = []

    def add_file(self, filename):
        """Add file to manifest"""
        self.entries.append(FileEntry.from_file(filename))

    def verify(self):
        """Verify all files in manifest"""
        for entry in self.entries:
            entry.verify()

    @classmethod
    def from_string(cls, manifest_in):
        """Load manifest from string"""
        manifest = cls()
        for line in manifest_in.splitlines():
            manifest.entries.append(FileEntry.from_string(line))
        return manifest

    def __str__(self):
        """Return string representation of the manifest"""
        lines = []
        for entry in self.entries:
            lines.append(entry.__str__())
        return "\n".join(lines)


def write_new_certificate(key_path, cert_path, subject, expiry_days=1):
    """Create X509 certificate and private key

    http://www.openssl.org/docs/apps/req.html
    http://www.madboa.com/geek/openssl/
    https://pyopenssl.readthedocs.io/en/stable/api/crypto.html#certificates

    """
    cert = crypto.X509()
    cert.get_subject().C = subject['C']
    cert.get_subject().ST = subject['ST']
    cert.get_subject().L = subject['L']
    cert.get_subject().O = subject['O']
    cert.get_subject().OU = subject['OU']
    cert.get_subject().CN = subject['CN']

    cert.set_serial_number(randint(1, 100000000000000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(24*60*60*expiry_days)

    cert.set_issuer(cert.get_subject())
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    pub = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    for item, path in zip([pub, pem], [key_path, cert_path]):
        with open(path, 'w') as outfile:
            outfile.write(item)
    return pub, pem


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
    manifest = Manifest.from_string(manifest_data)
    manifest.verify()


def signature_write(signature_path, key_path, cert_path, include_patterns):
    """Generate SIP signature files aka. signed manifest files"""
    manifest = Manifest()
    for pattern in include_patterns:
        for path in glob.glob(pattern):
            manifest.add_file(path)

    signature = smime_sign(key_path, cert_path, manifest)

    with open(signature_path, 'w') as outfile:
        outfile.write(signature)

def rehash_ca_path_symlinks(public_key, ca_path):
    """ Generate symlinks to public keys in ca_path so

    that openssl command can find correct public keys

        openssl verify -CApath <ca_path>

    Symlinks are in format <x509 hash for public key>.0 -> keyfile.pem

    http://www.openssl.org/docs/apps/verify.html
    http://www.openssl.org/docs/apps/x509.html

    http://stackoverflow.com/questions/9879688/\
    difference-between-cacert-and-capath-in-curl """

    cmd = ['openssl', 'x509', '-hash', '-noout', '-in', public_key]
    (_, stdout, _) = run_command(cmd)
    x509_hash_symlink = os.path.join(ca_path, '%s.0' % stdout.rstrip())
    os.symlink(public_key, x509_hash_symlink)
    return x509_hash_symlink