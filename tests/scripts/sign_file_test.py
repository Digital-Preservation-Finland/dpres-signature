"""Test for command line interface of signature module."""
import os

from pytest import raises
from dpres_signature.scripts.sign_file import parse_arguments, main


def test_parse_arguments():
    """test for argument parser."""
    args = parse_arguments(
        ['foo.py', 'dir/file1', 'dir/dir2/file2', '-c=/etc/foo',
         '-s=/tmp/foo/signature.sig', '--write=True'])
    assert args.targets == ['dir/file1', 'dir/dir2/file2']
    assert args.ca_path == "/etc/foo"
    assert args.signaturepath == "/tmp/foo/signature.sig"
    assert args.write == "True"

    with raises(RuntimeError):
        args = parse_arguments(
            ['foo.py', '-c=/etc/foo', '-k=/etc/foo2', '-s=foo', '-write=True'])

    with raises(RuntimeError):
        args = parse_arguments(['foo.py', '-c=/etc/foo', '-w='])


def test_main_write(signature_fx):
    """Test for commandline script main."""
    signature_path = os.path.join(str(signature_fx), 'data/signature.sig')
    key_path = os.path.join(str(signature_fx), 'keys/rsa_keypair.key')
    cert_path = os.path.join(str(signature_fx), 'certs/68b140ba.0')
    os.remove(signature_path)
    main(['foo.py', 'test.txt', '-c=%s' % cert_path, '-k=%s' % key_path,
          '-s=%s' % signature_path, '--write=True'])


def test_main_verify(signature_fx):
    """Test for commandline script main."""
    signature_path = os.path.join(str(signature_fx), 'data/signature.sig')
    cert_path = os.path.join(str(signature_fx), 'certs')
    main(['foo.py', '-c=%s' % cert_path, '-s=%s' % signature_path])
