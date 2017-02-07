"""Write and verify SMIME signatures"""

import logging

from M2Crypto import BIO, SMIME, X509, SSL

LOGGER = logging.getLogger('dpres_signature.smime')


def smime_sign(key_path, cert_path, message):
    """Sign message with given certificate and signing key"""

    # Instantiate an SMIME object; set it up; sign the buffer.
    smime = SMIME.SMIME()
    smime.load_key(
        keyfile=key_path,
        certfile=cert_path)

    message_buf = BIO.MemoryBuffer()
    message_buf.write(str(message))
    pkcs7 = smime.sign(message_buf, SMIME.PKCS7_DETACHED)

    # Must recreate message buffer, it was consumed by smime.sign()
    message_buf = BIO.MemoryBuffer()
    message_buf.write(str(message))

    # Destination buffer for combined message
    out = BIO.MemoryBuffer()

    # write message & signature to output buffer
    smime.write(out, pkcs7, message_buf)

    return ''.join([x for x in out.read()])


def smime_verify(ca_path, message):
    """Verify S/MIME pkcs7 signed message.

    You may debug certificate errors with command::

        openssl smime -verify -in
            .tmp/test_verify_signature_file0/signed/signature.sig -CApath
            .tmp/test_verify_signature_file0/certs

    :ca_path: Path to CA certificate store
    :returns: Message data on succesful verification

    """

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
