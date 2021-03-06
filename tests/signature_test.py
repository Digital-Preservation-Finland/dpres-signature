"""This is a test module for SMIME signature files verification."""
from __future__ import unicode_literals

import os

import pytest
import six

from dpres_signature.manifest import ManifestError
from dpres_signature.signature import signature_verify
from dpres_signature.smime import smime_sign
from M2Crypto import SMIME
from tests.conftest import write_signature


def run_verify(signature_fx):
    """Run the verify command"""

    signature_path = six.text_type(signature_fx.join('data/signature.sig'))
    ca_path = six.text_type(signature_fx.join('certs'))

    return signature_verify(
        signature_path=signature_path,
        ca_path=ca_path)


def test_signature(signature_fx):
    """Test signature contents"""

    signature = signature_fx.join("data/signature.sig").read_text("utf-8")

    assert 'MIME-Version: 1.0' in signature
    assert 'Content-Type: multipart/signed; protocol="application' in signature
    assert 'This is an S/MIME signed message' in signature

    assert "dir/test.txt:sha1:70abb39c88f7c99c353ee79000cb4e1301e" in signature

    assert 'Content-Type: application/x-pkcs7-signature; name="sm' in signature
    assert 'Content-Transfer-Encoding: base64' in signature
    assert 'Content-Disposition: attachment; filename="smime.p7s"' in signature


def test_keypair(signature_fx):
    """Test new key pair creation."""

    key_data = signature_fx.join('keys/rsa_keypair.key').read_text("utf-8")

    assert '-----BEGIN PRIVATE KEY-----' in key_data
    assert '-----END PRIVATE KEY-----' in key_data


def test_certificate(signature_fx):
    """Test new key pair creation."""

    certificate = signature_fx.join('certs/68b140ba.0').read_text("utf-8")

    assert '-----BEGIN CERTIFICATE-----' in certificate
    assert '-----END CERTIFICATE-----' in certificate


def test_verify_signature_file(signature_fx):
    """Test good signature file"""

    run_verify(signature_fx)


def test_missing_ca(signature_fx):
    """Test missing CA certificate / unknown self-signed certificate on
    signature"""

    os.unlink(six.text_type(signature_fx.join('certs/68b140ba.0')))
    with pytest.raises(SMIME.PKCS7_Error):
        run_verify(signature_fx)


def test_corrupted_signature(signature_fx):
    """Test corrupted certificate file"""

    signature = signature_fx.join('data/signature.sig')
    with signature.open('r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write(b'foo')

    with pytest.raises(SMIME.SMIME_Error):
        run_verify(signature_fx)


def test_corrupted_file(signature_fx):
    """ Test invalid certificate """

    signed_file = signature_fx.join('data/dir/test.txt')

    with signed_file.open('r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write(b'foo')

    with pytest.raises(ManifestError):
        run_verify(signature_fx)


def test_expired_certificate(tmpdir):
    """Test expired certificate"""
    write_signature(tmpdir, -1)
    with pytest.raises(SMIME.PKCS7_Error):
        run_verify(tmpdir)


def test_missing_signature(signature_fx):
    """Test for missing signature."""
    signature = six.text_type(signature_fx.join('data/signature.sig'))
    os.remove(signature)
    with pytest.raises(IOError):
        run_verify(signature_fx)


def test_header_in_manifest(signature_fx):
    """Test header in manifest."""
    sig_tmplate = signature_fx
    path = six.text_type(sig_tmplate)
    signature = sig_tmplate.join('data/signature.sig')
    issuer_hash = '68b140ba.0'
    key_path = os.path.join(path, 'keys', 'rsa_keypair.key')
    cert_path = os.path.join(path, 'certs', issuer_hash)
    manifest = (b'Content-Type: text/plain; charset=us-ascii\n'
                b'Content-Transfer-Encoding: 7bit\n\n'
                b'dir/test.txt:sha1:70abb39c88f7c99c353ee79000cb4e1301e4206f')
    sig = smime_sign(key_path, cert_path, manifest)
    with signature.open('wb') as outfile:
        outfile.write(sig)
    assert run_verify(signature_fx) == 0


def test_corrupted_manifest(signature_fx):
    """Test corrupted manifest"""
    sig_tmplate = signature_fx
    path = six.text_type(sig_tmplate)
    signature = sig_tmplate.join('data/signature.sig')
    issuer_hash = '68b140ba.0'
    key_path = os.path.join(path, 'keys', 'rsa_keypair.key')
    cert_path = os.path.join(path, 'certs', issuer_hash)
    manifest = b'dir/test.txt70abb39c88f7c99c353ee79000cb4e1301e'
    sig = smime_sign(key_path, cert_path, manifest)
    with signature.open('wb') as outfile:
        outfile.write(sig)
    with pytest.raises(ManifestError):
        run_verify(signature_fx)


def test_missing_file_manifest(signature_fx):
    """Test when manifest file is missing."""
    signature = signature_fx
    signature_path = six.text_type(signature.join('data/signature.sig'))
    ca_path = os.path.join(six.text_type(signature), 'certs')
    with pytest.raises(ManifestError):
        signature_verify(
            signature_path=signature_path,
            ca_path=ca_path, filelist=['mets.xml'])
