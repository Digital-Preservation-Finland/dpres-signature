"""conftest.py"""

import logging
import os
import shutil

import pytest

from dpres_signature.x509 import write_new_certificate
from dpres_signature.signature import signature_write

logging.basicConfig(level=logging.DEBUG)


@pytest.fixture(scope="function")
def signature_fx(tmpdir, request):
    """Write fresh keypair, certificates and signatures for each test"""

    def _fin():
        """delete temporary path"""
        shutil.rmtree(str(tmpdir))
    request.addfinalizer(_fin)
    return write_signature(tmpdir, 10)


def write_signature(tmpdir, expiry_days=0):
    """Write fresh keypair, certificates and signatures for each test"""

    subject = {
        'C': 'FI', 'ST': 'Uusimaa', 'L': 'Espoo', 'O': 'ACME org',
        'OU': 'ACME unit', 'CN': 'localhots.local'
    }

    issuer_hash = '68b140ba.0'

    key_path = str(tmpdir.mkdir('keys').join('rsa_keypair.key'))
    cert_path = str(tmpdir.mkdir('certs').join(issuer_hash))

    tmpdir.mkdir('data')
    signature_path = str(tmpdir.join('data/signature.sig'))
    signed_file_path = str(tmpdir.join('data/dir/test.txt'))
    signed_file_dir = str(tmpdir.join('data/dir'))

    write_new_certificate(
        public_key_path=key_path,
        cert_path=cert_path,
        subject=subject,
        expiry_days=expiry_days)

    if not os.path.exists(signed_file_dir):
        os.mkdir(signed_file_dir)
    with open(signed_file_path, 'w') as outfile:
        outfile.write('Sign me!')

    signature_write(
        signature_path=signature_path,
        key_path=key_path,
        cert_path=cert_path,
        include_patterns=['dir/test.txt'])

    return tmpdir
