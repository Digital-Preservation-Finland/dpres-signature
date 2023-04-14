"""Test for command line interface of signature module."""
from __future__ import unicode_literals

import os

import pytest
import six
from pytest import raises

from dpres_signature.scripts.verify_signed_file import main, parse_arguments
from tests.conftest import write_signature


def test_parse_arguments():
    """test for argument parser."""
    args = parse_arguments(
        ['foo.py', '-s=/tmp/foo/signature.sig', '-k=/etc/foo'])
    assert args.key_path == "/etc/foo"
    assert args.signature_path == "/tmp/foo/signature.sig"

    args = parse_arguments(
        ['foo.py', '-s=/tmp/foo/signature.sig', '-k=/etc/foo', 'mets.xml'])
    assert args.files == ['mets.xml']

    with raises(SystemExit):
        args = parse_arguments(
            ['foo.py', '-c=/etc/foo', '-k=/etc/foo2', '-s=foo'])

    with raises(SystemExit):
        args = parse_arguments(['foo.py', '-k=/etc/foo'])


@pytest.mark.parametrize("algorithm", ("sha1", "sha256"))
def test_main_verify(tmpdir, algorithm):
    """Test for commandline script main."""
    signature = write_signature(tmpdir, 10, algorithm)
    signature_path = os.path.join(
        six.text_type(signature), 'data/signature.sig')
    cert_path = os.path.join(six.text_type(signature), 'certs')
    main(['foo.py', '-k=%s' % cert_path, '-s=%s' % signature_path])


def test_none_argument():
    """Test when no arguments are given."""
    with raises(SystemExit):
        main(arguments=None)


def test_no_signature():
    """Test when non-existing signature file given."""
    main(['foo.py', '-s=%s' % 'does/not/exists'])
