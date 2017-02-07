"""This is a test module for SMIME signature files verification."""

import os

import pytest

from M2Crypto import SMIME

from dpres_signature.signature import signature_verify
from dpres_signature.manifest import ManifestError

from tests.conftest import write_signature


def run_verify(signature_fx):
    """Run the verify command"""

    signature_path = str(signature_fx.join('data/signature.sig'))
    ca_path = str(signature_fx.join('certs'))

    signature_verify(
        signature_path=signature_path,
        ca_path=ca_path)


def test_signature(signature_fx):
    """Test signature contents"""

    signature = signature_fx.join("data/signature.sig").read()

    assert 'MIME-Version: 1.0' in signature
    assert 'Content-Type: multipart/signed; protocol="application' in signature
    assert 'This is an S/MIME signed message' in signature

    assert "test.txt:sha1:70abb39c88f7c99c353ee79000cb4e1301e420" in signature
    assert "/test.txt" not in signature

    assert 'Content-Type: application/x-pkcs7-signature; name="sm' in signature
    assert 'Content-Transfer-Encoding: base64' in signature
    assert 'Content-Disposition: attachment; filename="smime.p7s"' in signature


def test_keypair(signature_fx):
    """Test new key pair creation."""

    key_data = signature_fx.join('keys/rsa_keypair.key').read()

    assert '-----BEGIN PRIVATE KEY-----' in key_data
    assert '-----END PRIVATE KEY-----' in key_data


def test_certificate(signature_fx):
    """Test new key pair creation."""

    certificate = signature_fx.join('certs/68b140ba.0').read()

    assert '-----BEGIN CERTIFICATE-----' in certificate
    assert '-----END CERTIFICATE-----' in certificate


def test_verify_signature_file(signature_fx):
    """Test good signature file"""

    run_verify(signature_fx)


def test_missing_ca(signature_fx):
    """Test missing CA certificate / unknown self-signed certificate on
    signature"""

    os.unlink(str(signature_fx.join('certs/68b140ba.0')))
    with pytest.raises(SMIME.PKCS7_Error):
        run_verify(signature_fx)


def test_corrupted_signature(signature_fx):
    """Test corrupted certificate file"""

    signature = signature_fx.join('data/signature.sig')
    with signature.open('r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write('foo')

    with pytest.raises(SMIME.SMIME_Error):
        run_verify(signature_fx)


def test_corrupted_file(signature_fx):
    """ Test invalid certificate """

    signed_file = signature_fx.join('data/test.txt')

    with signed_file.open('r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write('foo')

    with pytest.raises(ManifestError):
        run_verify(signature_fx)


def test_expired_certificate(tmpdir):
    """Test expired certificate"""
    write_signature(tmpdir, -1)
    with pytest.raises(SMIME.PKCS7_Error):
        run_verify(tmpdir)
