"""conftest.py"""
import shutil
import os

from tempfile import mkdtemp
from dpres_signature import signature

import pytest

TESTPATH = '/tmp/signature_test'
CERT_NAME = 'private.crt'
PUBLIC_KEY_NAME = 'public.pem'
DIR_NAME = 'sip'
FILENAME = 'tempfile.xml'
SIGNATURE_NAME = 'signature.sig'

NAME = {
    'C': 'FI', 'ST': 'Uusimaa', 'L': 'Espoo', 'O': 'ACME org',
    'OU': 'ACME unit', 'CN': 'localhots.local'
}


def _make_dir(path=""):
    """make temp directory"""

    if not os.path.exists(TESTPATH):
        os.makedirs(TESTPATH)
    temp_path = mkdtemp(dir=TESTPATH)
    new_path = os.path.join(temp_path, path)
    if not os.path.isdir(new_path):
        os.makedirs(new_path)
    return new_path


def _make_file(path=os.path.join(DIR_NAME, FILENAME)):
    """Make file"""
    dir_path = _make_dir(os.path.dirname(path))
    full_path = os.path.join(dir_path, os.path.basename(path))
    with open(full_path, 'w') as outfile:
        outfile.write("foo")
    return full_path


def _make_certificates(path="certs"):
    """Create key pair"""
    directory = _make_dir(path)
    pem_path = os.path.join(directory, PUBLIC_KEY_NAME)
    cert_path = os.path.join(directory, CERT_NAME)
    signature.write_new_certificate(
        public_key_path=pem_path,
        cert_path=cert_path,
        subject=NAME)

    return {"pub": cert_path, "pem": pem_path}


def _make_signature(path):
    """Create signature"""
    file_path = _make_file(path)
    key_path = os.path.join(_make_dir(), PUBLIC_KEY_NAME)
    signature_path = os.path.join(
        os.path.dirname(file_path), SIGNATURE_NAME)
    signature.signature_write(
        signature_path=signature_path,
        key_path=key_path,
        cert_path=key_path,
        include_patterns=file_path)
    return


@pytest.fixture(scope="session")
def tempdir(request):
    """Creates temporary directory and clean up after testing.

    :request: Pytest request fixture
    :returns: Path to temporary directory
    """
    def _makedir():
        """Create directory under temp_path"""
        return _make_dir()

    def fin():
        """remove temporary path"""
        shutil.rmtree(TESTPATH)

    request.addfinalizer(fin)

    return _makedir


@pytest.fixture(scope="session")
def tempfile(request):
    """Create temp directory"""
    def _filename(path=DIR_NAME):
        return _make_file(path)

    def fin():
        """foo"""
        if os.path.exists(TESTPATH):
            shutil.rmtree(TESTPATH)

    request.addfinalizer(fin)

    return _filename


@pytest.fixture(scope="function")
def test_certs(request):
    """Create test certificates."""
    def fin():
        """foo"""
        shutil.rmtree(TESTPATH)

    request.addfinalizer(fin)
    return _make_certificates("certs")


@pytest.fixture(scope="function")
def valid_signature(request):
    """Crate valid temp signature"""
    def _signature(path):
        return _make_signature(path)

    def fin():
        """foo"""
        if os.path.exists(TESTPATH):
            shutil.rmtree(TESTPATH)

    request.addfinalizer(fin)

    return _signature


@pytest.fixture(scope="function")
def x509_name():
    """Return 509 name with defaults"""
    def fin():
        """foo"""
        pass

    return NAME
