"""
This is a test module for SMIME signature files verification.
"""

import os
import pytest

from signature.utils import run_command
from signature.signature import SMIMEReadError, InvalidSignatureError,\
    InvalidChecksumError
from signature import signature


KEY = '%s/kdk-pas-sip-signing-key.pem'
SIP_PATH = '%s/sip'
FILE_PATH = '%s/sip/file.xml'
SIGNATURE_PATH = '%s/sip/signature.sig'


def test_create_report_signature(testpath):
    """
    Test for creating report signature succesfully.
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    sign.write_signature_file()

    assert os.path.isfile(FILE_PATH % testpath)
    assert os.path.isfile(SIGNATURE_PATH % testpath)


def test_new_signing_key(testpath):
    """
    Test new key pair creation.
    """
    sign = get_signature(testpath)
    (stdout, stderr) = sign.new_signing_key()
    assert os.path.isfile(sign.private_key)
    assert os.path.isfile(sign.public_key)
    assert len(stderr) == 0
    assert stdout.find(
        "Subject: C=FI, ST=Uusimaa, L=Helsinki, " +
        "CN=ingest.local") > 0, "Subject was not found in the " +\
        "certificate"


def test_verify_signature_file(testpath):
    """
    Test verify_signature_file()
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.sip_path = SIP_PATH % testpath

    sign.new_signing_key()
    hash_path = rehash_ca_path_symlinks(sign)
    sign.public_key = hash_path
    sign.write_signature_file()

    assert os.path.isfile(sign.signature_file)

    sign.verify_signature_file()


def test_missing_certificate(testpath):
    """
    Test missing certificate
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    with pytest.raises(SMIMEReadError):
        sign.verify_signature_file()


def test_invalid_certificate(testpath):
    """
    Test invalid certificate
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    sign.write_signature_file()
    with open(sign.signature_file, 'r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write('foo')
    rehash_ca_path_symlinks(sign)
    with pytest.raises(SMIMEReadError):
        sign.verify_signature_file()


def test_expired_certificate(testpath):
    """
    Test expired certificate
    """
    sign = get_signature(
        testpath, FILE_PATH % testpath, expiry_days='-1')
    sign.sip_path = SIP_PATH % testpath

    sign.new_signing_key()
    hash_path = rehash_ca_path_symlinks(sign)
    sign.public_key = hash_path
    sign.write_signature_file()

    assert os.path.isfile(sign.signature_file)
    with pytest.raises(InvalidSignatureError):
        sign.verify_signature_file()


def test_altered_file(testpath):
    """
    Test invalid certificate
    """
    sign = get_signature(testpath, FILE_PATH % testpath)
    sign.new_signing_key()
    sign.write_signature_file()
    with open(FILE_PATH % testpath, 'r+b') as outfile:
        outfile.seek(600, 0)
        outfile.write('foo')
    rehash_ca_path_symlinks(sign)
    with pytest.raises(InvalidChecksumError):
        sign.verify_signature_file()


def get_signature(test_path, file_path=None, expiry_days='365'):
    """
    utility function for creating signature.
    """
    sign = signature.ManifestSMIME(
        signature_file=SIGNATURE_PATH % test_path,
        private_key=KEY % test_path,
        public_key=KEY % test_path,
        ca_path=test_path,
        expiry_days=expiry_days,
        target_path=FILE_PATH % test_path)
    return sign


def rehash_ca_path_symlinks(signature_object):
    """ Generate symlinks to public keys in ca_path so

    that openssl command can find correct public keys

        openssl verify -CApath <ca_path>

    Symlinks are in format <x509 hash for public key>.0 -> keyfile.pem

    http://www.openssl.org/docs/apps/verify.html
    http://www.openssl.org/docs/apps/x509.html

    http://stackoverflow.com/questions/9879688/\
    difference-between-cacert-and-capath-in-curl """

    cmd = ['openssl', 'x509', '-hash', '-noout', '-in',
           signature_object.public_key]
    (_, stdout, _) = run_command(cmd)
    x509_hash_symlink = os.path.join(
        signature_object.ca_path, '%s.0' % stdout.rstrip())
    os.symlink(signature_object.public_key, x509_hash_symlink)
    return x509_hash_symlink


def test_testify():
    """testtest"""

    # OpenSSL for certificate and private key generation
    from OpenSSL import crypto

    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "FI"
    cert.get_subject().ST = "Espoo"
    cert.get_subject().L = "Uusimaa"
    cert.get_subject().O = "my company"
    cert.get_subject().OU = "my organization"
    cert.get_subject().CN = 'localhost.local'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    # Dump certificate to file
    if not os.path.isdir('.tmp'):
        os.makedirs('.tmp')

    with open('.tmp/cert.pem', 'w') as outfile:
        outfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open('.tmp/key.pem', 'w') as outfile:
        outfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # M2Crypto for generating SMIME/pkcs7 signed messages

    from M2Crypto import BIO, Rand, SMIME

    # Seed the PRNG.
    Rand.load_file('.tmp/randpool.dat', -1)

    # Instantiate an SMIME object; set it up; sign the buffer.
    smime = SMIME.SMIME()
    smime.load_key('.tmp/key.pem', '.tmp/cert.pem')

    message = "sign me please"
    message_buf = BIO.MemoryBuffer(message)
    pkcs7 = smime.sign(message_buf, SMIME.PKCS7_DETACHED)

    # Must recreate message buffer, it was consumed by smime.sign()
    message_buf = BIO.MemoryBuffer(message)

    # Destination buffer for combined message
    out = BIO.MemoryBuffer()

    # write message & signature to output buffer
    smime.write(out, pkcs7, message_buf)

    message_pkcs7 = ''.join([x for x in out.read()])

    print message_pkcs7

    assert 'please' in message_pkcs7
    assert '--\n' in message_pkcs7

    # Save the signed message

    with open('.tmp/signature.sig', 'w') as outfile:
        outfile.write(message_pkcs7)

    Rand.save_file('.tmp/randpool.dat')

    # Verification process for SMIME/pkcs7 signed messages

    from M2Crypto import X509

    smime = SMIME.SMIME()

    # Load the signer's certificate
    x509 = X509.load_cert('.tmp/cert.pem')
    certificate = X509.X509_Stack()
    certificate.push(x509)
    smime.set_x509_stack(certificate)

    # Load the signer's CA cert. In this case, because the signer's
    # cert is self-signed, it is the signer's cert itself.
    ca_store = X509.X509_Store()
    ca_store.load_info('.tmp/cert.pem')
    smime.set_x509_store(ca_store)

    # Load the signed message and verify it.

    pkcs7, data = SMIME.smime_load_pkcs7('.tmp/signature.sig')
    verified_message = smime.verify(pkcs7, data)
    print verified_message
    print data
    print data.read()

    # Test verification with unknown certificate
    # We do no load any CA's to verify, and smime
    # should raise exception

    ca_store = X509.X509_Store()
    smime.set_x509_store(ca_store)

    pkcs7, data = SMIME.smime_load_pkcs7('.tmp/signature.sig')
    with pytest.raises(SMIME.PKCS7_Error):
        verified_message = smime.verify(pkcs7, data)

    # Test certification with another key / changed certificate
    # Here we generate another certificate, remember that
    # message was signed with different certificate

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.get_subject().C = "FI"
    cert.get_subject().ST = "Espoo"
    cert.get_subject().L = "Uusimaa"
    cert.get_subject().O = "my company"
    cert.get_subject().OU = "my organization"
    cert.get_subject().CN = 'localhost.local'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    with open('.tmp/another_cert.pem', 'w') as outfile:
        outfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open('.tmp/another_key.pem', 'w') as outfile:
        outfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # Verify signature.sig file with another
    # Load the another signing certificates

    x509 = X509.load_cert('/etc/ssl/certs/server.crt')
    certificate = X509.X509_Stack()
    certificate.push(x509)
    smime.set_x509_stack(certificate)

    # Load the another CA cert (same as signing certificate)
    ca_store = X509.X509_Store()
    ca_store.load_info('/etc/ssl/certs/ca-bundle.crt')
    smime.set_x509_store(ca_store)

    pkcs7, data = SMIME.smime_load_pkcs7('.tmp/signature.sig')

    with pytest.raises(SMIME.PKCS7_Error):
        verified_message = smime.verify(pkcs7, data)

    # test that the another certificate works
    # sign with another certificate and verify it
    # Same process as for previous stave

    Rand.load_file('.tmp/randpool.dat', -1)

    smime.load_key('.tmp/another_key.pem', '.tmp/another_cert.pem')

    message = "sign me please another time"
    message_buf = BIO.MemoryBuffer(message)
    pkcs7 = smime.sign(message_buf, SMIME.PKCS7_DETACHED)
    message_buf = BIO.MemoryBuffer(message)
    out = BIO.MemoryBuffer()
    smime.write(out, pkcs7, message_buf)
    message_pkcs7 = ''.join([x for x in out.read()])
    with open('.tmp/signature.sig', 'w') as outfile:
        outfile.write(message_pkcs7)
    Rand.save_file('.tmp/randpool.dat')

    # Verify message with another certificate
    pkcs7, data = SMIME.smime_load_pkcs7('.tmp/signature.sig')

    # Load x509 signature / certificate stack from
    # message itself instead of stored another_key.pem
    # This corresponds to "openssl smime -verify" functionality
    certificate_x509 = pkcs7.get0_signers(X509.X509_Stack())

    smime = SMIME.SMIME()
    smime.set_x509_stack(certificate_x509)

    ca_store = X509.X509_Store()
    ca_store.load_info('.tmp/another_cert.pem')
    smime.set_x509_store(ca_store)

    verified_message = smime.verify(pkcs7, data)
    assert verified_message == message
