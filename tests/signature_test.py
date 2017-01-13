"""
This is a test module for SMIME signature files verification.
"""

import os
import pytest

from dpres_signature.signature import write_new_certificate, signature_write, \
    rehash_ca_path_symlinks, signature_verify

KEY = '%s/kdk-pas-sip-signing-key.pem'
CA_PATH = '%s/kdk-pas-sip-signing-key.crt'
SIP_PATH = '%s/sip'
FILE_PATH = '%s/sip/file.xml'
SIGNATURE_PATH = '%s/sip/signature.sig'
SIGNATURE_NAME = 'signature.sig'


def get_signature(file_path, test_certs, filenames):
    """Create test signature"""
    signature_path = os.path.join(os.path.dirname(file_path), SIGNATURE_NAME)
    return signature_write(
        signature_path, test_certs["pem"],
        test_certs["pub"],
        filenames)


def test_signature_write(test_certs, tempfile):
    """
    Test for creating report signature succesfully.
    """
    file_path = tempfile("test.xml")
    filename = os.path.basename(file_path)
    signature_path = os.path.join(os.path.dirname(file_path), "signature.sig")
    signature = get_signature(file_path, test_certs, [filename])
    assert "test.xml:sha1:0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a3" in signature
    assert "/test.xml" not in signature
    assert os.path.isfile(file_path)
    assert os.path.isfile(signature_path)


def test_write_new_certificate(tempdir, x509_name):
    """
    Test new key pair creation.
    """
    directory = tempdir()
    pub, _ = write_new_certificate(
        public_key_path=KEY % directory,
        cert_path=CA_PATH % directory,
        subject=x509_name)
    assert os.path.isfile(KEY % directory)
    assert os.path.isfile(CA_PATH % directory)
    assert "Issuer: C=FI, ST=Uusimaa, L=Espoo, O=ACME org" in pub
    assert "CN=localhots.local" in pub
    assert "Signature Algorithm: sha1WithRSAEncryption" in pub


def test_verify_signature_file(test_certs, tempfile):
    """
    Test verify_signature_file()
    """
    file_path = tempfile("test.xml")
    base_path, filename = os.path.split(file_path)
    signature_path = os.path.join(os.path.dirname(file_path), "signature.sig")
    get_signature(file_path, test_certs, [filename])
    ca_path = os.path.dirname(test_certs["pem"])
    rehash_ca_path_symlinks(test_certs["pub"], ca_path)

    assert os.path.isfile(signature_path)

    signature_verify(
        signature_path=signature_path, ca_path=ca_path, base_path=base_path)


def test_missing_certificate(test_certs, tempfile):
    """
    Test missing certificate
    """
    signature_path = os.path.join(os.path.dirname(tempfile), 'foo.sig')
    tempfile("test.xml")
    ca_path = os.path.dirname(test_certs["pem"])
    with pytest.raises(OSError):
        signature_verify(
            signature_path=signature_path, ca_path=ca_path)


def test_invalid_certificate(testpath):
    """
    Test invalid certificate
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    sign.write_signature_file()
    with open(sign.signature_file, 'r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write('foo')
    rehash_ca_path_symlinks(sign)
    with pytest.raises(SMIMEReadError):
        sign.verify_signature_file()


def test_expired_certificate(testpath):
    """
    Test expired certificate
    """
    sign = get_signature(
        testpath, FILE_PATH % testpath, expiry_days='-1')
    sign.sip_path = SIP_PATH % testpath

    sign.new_signing_key()
    hash_path = rehash_ca_path_symlinks(sign)
    sign.public_key = hash_path
    sign.write_signature_file()

    assert os.path.isfile(sign.signature_file)
    with pytest.raises(InvalidSignatureError):
        sign.verify_signature_file()


def test_altered_file(testpath):
    """
    Test invalid certificate
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    sign.write_signature_file()
    with open(FILE_PATH % testpath, 'r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write('foo')
    rehash_ca_path_symlinks(sign)
    with pytest.raises(InvalidChecksumError):
        sign.verify_signature_file()
