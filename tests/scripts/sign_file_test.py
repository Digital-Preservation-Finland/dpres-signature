"""Test for command line interface of signature module."""
import os

from pytest import raises
from dpres_signature.scripts.sign_file import parse_arguments, main
from dpres_signature.manifest import ManifestError


def test_parse_arguments():
    """test for argument parser."""
    args = parse_arguments(
        ['foo.py', 'dir/file1', 'dir/dir2/file2', '-c=/etc/foo',
         '-s=/tmp/foo/signature.sig', '-k=/etc/bar'])
    assert args.targets == ['dir/file1', 'dir/dir2/file2']
    assert args.ca_path == "/etc/foo"
    assert args.signature_path == "/tmp/foo/signature.sig"

    with raises(RuntimeError):
        args = parse_arguments(['foo.py', '-c=/etc/foo'])


def test_main_write(signature_fx):
    """Test for commandline script main."""
    signature_path = os.path.join(str(signature_fx), 'data/signature.sig')
    key_path = os.path.join(str(signature_fx), 'keys/rsa_keypair.key')
    cert_path = os.path.join(str(signature_fx), 'certs/68b140ba.0')
    os.remove(signature_path)
    main(['foo.py', 'dir/test.txt', '-c=%s' % cert_path, '-k=%s' % key_path,
          '-s=%s' % signature_path])


def test_illegal_path(signature_fx):
    """Test illegal paths, prevent script escaping from signature directory."""
    signature_path = os.path.join(str(signature_fx), 'data/signature.sig')
    key_path = os.path.join(str(signature_fx), 'keys/rsa_keypair.key')
    cert_path = os.path.join(str(signature_fx), 'certs/68b140ba.0')
    os.remove(signature_path)
    with raises(ManifestError):
        main(
            ['foo.py', '../test.txt', '-c=%s' % cert_path, '-k=%s' % key_path,
             '-s=%s' % signature_path])
    with raises(ManifestError):
        main(
            ['foo.py', cert_path, '-c=%s' % cert_path, '-k=%s' % key_path,
             '-s=%s' % signature_path])
