"""
This is a test module for SMIME signature files verification.
"""

import os
import pytest

from OpenSSL.crypto import X509Name, X509
from signature.signature import SMIMEReadError, InvalidSignatureError,\
    InvalidChecksumError
from dpres_signature.signature import write_new_certificate

KEY = '%s/kdk-pas-sip-signing-key.pem'
CA_PATH = '%s/kdk-pas-sip-signing-key.crt'
SIP_PATH = '%s/sip'
FILE_PATH = '%s/sip/file.xml'
SIGNATURE_PATH = '%s/sip/signature.sig'


def x509_name():
    """Return 509 name with defaults
    """
    name = {
        'C': 'FI', 'ST': 'Uusimaa', 'L': 'Espoo', 'O': 'ACME org',
        'OU': 'ACME unit', 'CN': 'localhots.local'
    }
    return name


def test_signature_write(tempfile):
    """
    Test for creating report signature succesfully.
    """
    print tempfile()

    write_new_certificate()
    sign.write_signature_file()

    assert os.path.isfile(FILE_PATH % testpath)
    assert os.path.isfile(SIGNATURE_PATH % testpath)


def test_write_new_certificate(tempdir):
    """
    Test new key pair creation.
    """
    directory = tempdir()
    pub, pem = write_new_certificate(
        key_path=KEY % directory,
        cert_path=CA_PATH % directory,
        subject=x509_name())
    print pub
    print pem
    assert os.path.isfile(KEY % directory)
    assert os.path.isfile(CA_PATH % directory)


def test_verify_signature_file(valid_signature):
    """
    Test verify_signature_file()
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.sip_path = SIP_PATH % testpath

    sign.new_signing_key()
    hash_path = rehash_ca_path_symlinks(sign)
    sign.public_key = hash_path
    sign.write_signature_file()

    assert os.path.isfile(sign.signature_file)

    sign.verify_signature_file()


def test_missing_certificate(testpath):
    """
    Test missing certificate
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    with pytest.raises(SMIMEReadError):
        sign.verify_signature_file()


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
