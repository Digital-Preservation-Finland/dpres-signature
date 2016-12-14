"""
This is a module for creating and verifying SMIME certificates and
signing keys.
"""

from utils import run_command
import os
import fnmatch
import tempfile
from ipt.fileutils.checksum import BigFile

PRIVATE_KEY = \
    '/usr/share/information-package-tools/ssl/keys/kdk-pas-sip-signing-key.pem'
PUBLIC_KEY = \
    '/usr/share/information-package-tools/ssl/keys/kdk-pas-sip-signing-key.pub'
INVALID_SIGNATURE_ERROR = 'Invalid signature on signature file. Exitcode: %s\n%s\n%s'
SMIME_READ_ERROR = 'Unable to read S/MIME. Exitcode: %s\nStdout: %s\nStderr: %s'
UNEXPECTED_ERROR = 'Unexpected error: Exitcode: %s\n Stdout: %s\n Stderr: %s'


class InvalidSignatureError(Exception):

    """Raised when signature is not valid."""
    pass


class UnexpectedError(Exception):

    """Raised when unexpected error occurs."""
    pass


class InvalidChecksumError(Exception):

    """Raised when checksum is not valid."""
    pass


class SMIMEReadError(Exception):

    """Raised when SMIME reading fails."""
    pass


class ManifestSMIME(object):

    """
    Class for SMIME manifest
    """

    def __init__(
            self, signature_file='signature.sig', ca_path='/etc/ssl/certs',
            target_path=None, expiry_days='365', country='FI', state='Uusimaa',
            location='Helsinki', common_name='ingest.local',
            private_key=PRIVATE_KEY, public_key=PUBLIC_KEY):

        self.signature_file = signature_file
        self.ca_path = ca_path
        self.private_key = private_key
        self.public_key = public_key
        self.target_path = target_path
        self.expiry_days = expiry_days
        self.country = country
        self.state = state
        self.location = location
        self.common_name = common_name
        self.manifest_base_path = os.path.abspath(
            os.path.dirname(self.signature_file))

    def new_signing_key(self):
        """Create a private/public key pair used to sign KDK-PAS SIPs

           http://www.openssl.org/docs/apps/req.html
           http://www.madboa.com/geek/openssl/ """

        if not os.path.exists(os.path.dirname(self.private_key)):
            os.makedirs(os.path.dirname(self.private_key))

        if not os.path.exists(os.path.dirname(self.public_key)):
            os.makedirs(os.path.dirname(self.public_key))

        # Note, this may not be safe for UTF-8 strings in self.country etc.
        cmd = ['openssl', 'req', '-x509', '-nodes', '-days', self.expiry_days,
               '-newkey', 'rsa:2048', '-subj', '/C=%s/ST=%s/L=%s/CN=%s' % (
                   self.country, self.state, self.location, self.common_name),
               '-keyout', self.private_key, '-out', self.public_key]
        (_, stdout, stderr) = run_command(cmd)

        cmd = ['openssl', 'x509', '-text', '-in', self.public_key]
        (_, stdout, stderr) = run_command(cmd)

        return str(stdout), str(stderr)

    def write_signature_file(self):
        """ Write SIP signature file varmiste.sig/signature.sig with checksums
        of all .xml files in manifest_base_path

        Signature file is formatted as following:

        ### Signature file starts with S/MIME container header
        MIME-Version: 1.0
        Content-Type: multipart/signed;
        protocol="application/x-pkcs7-signature"; micalg="sha1";
        boundary="----39E2251AA194465CC9D401144063F2D3"

        This is an S/MIME signed message

        ------39E2251AA194465CC9D401144063F2D3
        mets.xml:sha1:ab16aee4eb1eda360ed5d1b59d18bf4cf144f8fc

        ------39E2251AA194465CC9D401144063F2D3
        Content-Type: application/x-pkcs7-signature; name="smime.p7s"
        Content-Transfer-Encoding: base64
        Content-Disposition: attachment; filename="smime.p7s"

        MIIF+QYJKoZIhvcNAQcCoIIF6jCCBeYCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3
        < ... 30 lines more of digital signature ... >
        XzTLy+drurKzEpWP2Tszo3MCsPHjHIVqK9yGn/gdPbth+C9pOVF28Ygv93yp

        ------39E2251AA194465CC9D401144063F2D3--
        ### Signature file ends here with newline"""

        matches = []
        if self.target_path is None:
            for root, _, filenames in os.walk(self.manifest_base_path):
                for filename in fnmatch.filter(filenames, '*.xml'):
                    matches.append(os.path.join(root, filename))
        else:
            matches = self.target_path.split(',')
            matches = [os.path.abspath(match) for match in matches]

        manifest_fh = tempfile.NamedTemporaryFile()
        manifest_filename = manifest_fh.name
        algorithm = 'sha1'
        checksum = BigFile(algorithm)
        for filename in matches:
            hexdigest = checksum.hexdigest(filename)
            filename_relative = filename[len(self.manifest_base_path) + 1:]
            file_checksum = "%s:%s:%s\n" % (filename_relative, algorithm,
                                            hexdigest)
            with open(manifest_filename, 'w') as outfile:
                outfile.write(file_checksum)

        sign_path = os.path.join(self.manifest_base_path, self.signature_file)
        signature_file = open(sign_path, 'w')
        cmd = ['openssl', 'smime', '-sign', '-signer', self.private_key, '-in',
               manifest_filename]
        (ret, stdout, stderr) = run_command(
            cmd, stdout=signature_file, close_fds=True)
        if ret != 0:
            raise InvalidSignatureError(INVALID_SIGNATURE_ERROR % (
                ret, stdout, stderr))

    def verify_signature_file(self):
        """ Verify SIP signature varmiste.sig/signature.sig file """

        cmd = ['openssl', 'smime', '-verify', '-in',
               os.path.join(self.manifest_base_path, self.signature_file),
               '-CApath', self.ca_path]
        (ret, stdout, stderr) = run_command(cmd, close_fds=True)
        results = (ret, stdout, stderr)
        # http://www.openssl.org/docs/apps/verify.html
        if ret == 4:
            raise InvalidSignatureError(INVALID_SIGNATURE_ERROR % results)
        if ret == 2:
            raise SMIMEReadError(SMIME_READ_ERROR % results)
        if ret != 0:
            raise UnexpectedError(UNEXPECTED_ERROR % results)
        verify_checksums(results[1], self.manifest_base_path)


def verify_checksums(lines, manifest_base_path):
    """
    Verify manifest checksums
    """
    for algorithm, hexdigest, filename in get_manifest_line(lines):
        checksum_ok = BigFile('sha1').verify_file(
            os.path.join(manifest_base_path, filename),
            hexdigest)
        if not checksum_ok:
            raise InvalidChecksumError(
                "Checksum does not match %s %s %s" %
                (algorithm, hexdigest, filename))
        print "%s %s %s OK" % (filename, algorithm, hexdigest)


def get_manifest_line(lines):
    """
    Parsing a line from a manifest file.
    """
    for line in lines.splitlines():
        fields = line.rstrip().split(':')
        if len(fields) != 3:
            continue
        filename = fields[0]
        algorithm = fields[1]
        hexdigest = fields[2]
        yield (algorithm, hexdigest, filename)
