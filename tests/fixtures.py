""" Test fixtures. """
import pytest
import shutil
import os

from tempfile import mkdtemp


@pytest.fixture(scope="function")
def testpath(request):
    """Creates temporary directory and clean up after testing.

    :request: Pytest request fixture
    :returns: Path to temporary directory

    """

    temp_dir = request.config.getoption('--test-path')
    temp_path = mkdtemp(prefix='tmp.signature.test.', dir=temp_dir)
    os.makedirs(os.path.join(temp_path, 'sip'))
    os.system("echo 'foo' >> " + os.path.join(temp_path, 'sip', 'file.xml'))

    def fin():
        """remove temporary path"""
        shutil.rmtree(temp_path)

    request.addfinalizer(fin)

    return temp_path