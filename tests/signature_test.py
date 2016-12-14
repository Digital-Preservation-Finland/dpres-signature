"""
This is a test module for SMIME signature files verification.
"""

import os
import pytest

from signature.utils import run_command
from signature.signature import SMIMEReadError, InvalidSignatureError,\
    InvalidChecksumError
from signature import signature


KEY = '%s/kdk-pas-sip-signing-key.pem'
SIP_PATH = '%s/sip'
FILE_PATH = '%s/sip/file.xml'
SIGNATURE_PATH = '%s/sip/signature.sig'


def test_create_report_signature(testpath):
    """
    Test for creating report signature succesfully.
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    sign.write_signature_file()

    assert os.path.isfile(FILE_PATH % testpath)
    assert os.path.isfile(SIGNATURE_PATH % testpath)


def test_new_signing_key(testpath):
    """
    Test new key pair creation.
    """
    sign = get_signature(testpath)
    (stdout, stderr) = sign.new_signing_key()
    assert os.path.isfile(sign.private_key)
    assert os.path.isfile(sign.public_key)
    assert len(stderr) == 0
    assert stdout.find(
        "Subject: C=FI, ST=Uusimaa, L=Helsinki, " +
        "CN=ingest.local") > 0, "Subject was not found in the " +\
        "certificate"


def test_verify_signature_file(testpath):
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


def get_signature(test_path, file_path=None, expiry_days='365'):
    """
    utility function for creating signature.
    """
    sign = signature.ManifestSMIME(
        signature_file=SIGNATURE_PATH % test_path,
        private_key=KEY % test_path,
        public_key=KEY % test_path,
        ca_path=test_path,
        expiry_days=expiry_days)
    return sign


def rehash_ca_path_symlinks(signature_object):
    """ Generate symlinks to public keys in ca_path so

    that openssl command can find correct public keys

        openssl verify -CApath <ca_path>

    Symlinks are in format <x509 hash for public key>.0 -> keyfile.pem

    http://www.openssl.org/docs/apps/verify.html
    http://www.openssl.org/docs/apps/x509.html

    http://stackoverflow.com/questions/9879688/\
    difference-between-cacert-and-capath-in-curl """

    cmd = ['openssl', 'x509', '-hash', '-noout', '-in',
           signature_object.public_key]
    (_, stdout, _) = run_command(cmd)
    x509_hash_symlink = os.path.join(
        signature_object.ca_path, '%s.0' % stdout.rstrip())
    os.symlink(signature_object.public_key, x509_hash_symlink)
    return x509_hash_symlink
