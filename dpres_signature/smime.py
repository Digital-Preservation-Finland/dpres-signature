"""Write and verify SMIME signatures"""
from __future__ import unicode_literals

import logging

import six

from dpres_signature.util import ensure_binary, ensure_text

from M2Crypto import BIO, SMIME, SSL, X509

LOGGER = logging.getLogger('dpres_signature.smime')


def _to_str_path(path):
    """
    Convert string to version-specific 'str'.
    Path strings accepted by M2Crypto classes only accept byte strings
    on Python 2 and Unicode strings on Python 3.

    :param path: String to convert
    :type path: str or bytes

    :return: Byte string on Python 2, Unicode string on Python 3
    :rtype: str
    """
    if six.PY2:
        return ensure_binary(path)
    else:
        return ensure_text(path)


def smime_sign(key_path, cert_path, message):
    """
    Sign message with given certificate and signing key

    :param str key_path: Path to the key file
    :param cert_path: Optional path to the certificate file
    :type cert_path: str or None

    :param message: Message to sign
    :type message: bytes or :class:`dpres_signature.manifest.Manifest`

    :returns: Signature
    :rtype: bytes
    """
    # Instantiate an SMIME object; set it up; sign the buffer.

    key_path = _to_str_path(key_path)

    if cert_path:
        cert_path = _to_str_path(cert_path)

    # 'message' can be a byte string or a Manifest instance
    message = six.binary_type(message)

    smime = SMIME.SMIME()
    smime.load_key(
        keyfile=key_path,
        certfile=cert_path)

    message_buf = BIO.MemoryBuffer()
    message_buf.write(message)
    pkcs7 = smime.sign(message_buf, SMIME.PKCS7_DETACHED)

    # Must recreate message buffer, it was consumed by smime.sign()
    message_buf = BIO.MemoryBuffer()
    message_buf.write(message)

    # Destination buffer for combined message
    out = BIO.MemoryBuffer()

    # write message & signature to output buffer
    smime.write(out, pkcs7, message_buf)
    return out.read()


def smime_verify(ca_path, message):
    """Verify S/MIME pkcs7 signed message.

    You may debug certificate errors with command::

        openssl smime -verify -in
            .tmp/test_verify_signature_file0/signed/signature.sig -CApath
            .tmp/test_verify_signature_file0/certs

    :param str ca_path: Path to CA certificate store
    :param bytes message: Message to verify

    :returns: Message data on succesful verification
    :rtype: bytes
    """

    # SSLContext expects a byte string on Python 2 and Unicode on Python 3
    ca_path = _to_str_path(ca_path)

    buf = BIO.MemoryBuffer(message)
    pkcs7, data = SMIME.smime_load_pkcs7_bio(buf)

    certificate_x509 = pkcs7.get0_signers(X509.X509_Stack())

    context = SSL.Context()
    context.load_verify_locations(capath=ca_path)
    ca_store = context.get_cert_store()

    smime = SMIME.SMIME()

    smime.set_x509_store(ca_store)
    smime.set_x509_stack(certificate_x509)

    return smime.verify(pkcs7, data)
