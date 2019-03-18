"""conftest.py"""

import logging
import os
from io import open

import pytest

from dpres_signature.x509 import write_new_certificate
from dpres_signature.signature import create_signature

logging.basicConfig(level=logging.DEBUG)


@pytest.fixture(scope="function")
def signature_fx(tmpdir):
    """Write fresh keypair, certificates and signatures for each test"""

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
    with open(signed_file_path, 'wb') as outfile:
        outfile.write(b'Sign me!')

    signature = create_signature(signature_path=signature_path,
                                 key_path=key_path,
                                 include_patterns=['dir/test.txt'],
                                 cert_path=cert_path)

    with open(signature_path, 'wb') as outfile:
        outfile.write(signature)

    return tmpdir
