"""Test for command line interface of signature module."""
import os

from pytest import raises
from dpres_signature.scripts.verify_signed_file import parse_arguments, main


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


def test_main_verify(signature_fx):
    """Test for commandline script main."""
    signature_path = os.path.join(str(signature_fx), 'data/signature.sig')
    cert_path = os.path.join(str(signature_fx), 'certs')
    main(['foo.py', '-k=%s' % cert_path, '-s=%s' % signature_path])
