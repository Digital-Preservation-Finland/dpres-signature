"""
This is a module for creating and verifying SMIME certificates and
signing keys.
"""

import os
import hashlib
import time
import glob
from random import randint
from utils import run_command

from M2Crypto import BIO, Rand, SMIME, X509, ASN1, EVP, RSA


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


class ChecksumError(Exception):
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
        return cls(fields[0], fields[1], fields[3], base_path)

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
        if self.hex_digest != self.file_hex_digest():
            raise ChecksumError("Checksum mismatch %s" % self.filename)

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


def write_new_certificate(public_key_path, cert_path, subject, expiry_days=1):
    """Create X509 certificate and private key

    http://www.openssl.org/docs/apps/req.html
    http://www.madboa.com/geek/openssl/
    https://pyopenssl.readthedocs.io/en/stable/api/crypto.html#certificates

    """
    name = mk_ca_issuer(subject)
    req, pk = make_request(1024, name)
    public_key = req.get_pubkey()
    cert = X509.X509()
    set_expiry(cert, expiry_days)
    cert.set_serial_number(randint(1, 100000000000000))

    cert.set_issuer(name)
    cert.set_pubkey(public_key)
    cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
    cert.add_ext(
        X509.new_extension('subjectKeyIdentifier', cert.get_fingerprint()))
    cert.sign(pk, 'sha1')

    with open(public_key_path, 'w') as outfile:
        outfile.write(public_key.as_pem())
    with open(cert_path, 'w') as outfile:
        outfile.write(cert.as_text())
    return cert.as_text(), public_key.as_pem()


def smime_sign(key_path, cert_path, message):
    """Sign message with given certificate and signing key"""

    # Seed the PRNG.
    Rand.load_file('.randpool.dat', -1)

    # Instantiate an SMIME object; set it up; sign the buffer.
    smime = SMIME.SMIME()
    smime.load_key(
        keyfile=key_path,
        certfile=cert_path)

    message_buf = BIO.MemoryBuffer()
    message_buf.write(str(message))
    pkcs7 = smime.sign(message_buf, SMIME.PKCS7_DETACHED)

    # Must recreate message buffer, it was consumed by smime.sign()
    message_buf = BIO.MemoryBuffer()
    message_buf.write(str(message))

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


def signature_verify(
        signature_path, ca_path='/etc/ssl/certs/ca-budle.crt', base_path=None):
    """Verify SIP signature files aka. signed manifest files"""
    with open(signature_path) as infile:
        manifest_data = smime_verify(ca_path, infile.read())
    manifest = Manifest.from_string(manifest_data, base_path)
    manifest.verify()


def signature_write(signature_path, key_path, cert_path, include_patterns):
    """Generate SIP signature files aka. signed manifest files"""
    base_path = os.path.dirname(signature_path)
    manifest = Manifest(base_path)
    for pattern in include_patterns:
        manifest.add_file(pattern)
    signature = smime_sign(key_path, cert_path, manifest)

    with open(signature_path, 'w') as outfile:
        outfile.write(signature)
    return signature


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


def set_expiry(cert, days=365):
    """
    Make a cert valid from now and til 'days' from now.
    Args:
       cert -- cert to make valid
       days -- number of days cert is valid for from now.
    """
    time_now = long(time.time())
    now = ASN1.ASN1_UTCTIME()
    now.set_time(time_now)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time(time_now + days * 24 * 60 * 60)
    cert.set_not_before(now)
    cert.set_not_after(expire)


def mk_ca_issuer(subject):
    """
    Our default CA issuer name.
    """
    name = X509.X509_Name()
    name.C = subject['C']
    name.ST = subject['ST']
    name.L = subject['L']
    name.O = subject['O']
    name.OU = subject['OU']
    name.CN = subject['CN']
    return name
