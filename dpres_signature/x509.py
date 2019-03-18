"""Write X509 certificates"""

import time

from M2Crypto import X509, ASN1, EVP, RSA


def write_new_certificate(
        public_key_path, cert_path, subject, expiry_days=3560):
    """Create X509 certificate and private key

    http://www.openssl.org/docs/apps/req.html
    http://www.madboa.com/geek/openssl/
    https://pyopenssl.readthedocs.io/en/stable/api/crypto.html#certificates

    """

    rsa = RSA.gen_key(2048, 65537, lambda: None)

    public_key = EVP.PKey()
    public_key.assign_rsa(rsa)
    public_key.save_key(public_key_path, cipher=None)

    cert = X509.X509()

    cert.set_serial_number(1)
    cert.set_version(2)

    cert.set_not_before(asn_expiry(0))
    cert.set_not_after(asn_expiry(expiry_days))

    cert.set_pubkey(public_key)

    name = dict_to_x509_name(subject)
    cert.set_issuer(name)
    cert.set_subject(name)

    cert.sign(public_key, 'sha1')

    cert.save(cert_path)


def asn_expiry(days=365):
    """Return ASN1 timestamp with now + days"""
    time_now = int(time.time())
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time(time_now + days * 24 * 60 * 60)
    return expire


def dict_to_x509_name(subject):
    """Our default CA issuer name."""
    name = X509.X509_Name()
    name.C = subject['C']
    name.ST = subject['ST']
    name.L = subject['L']
    name.O = subject['O']
    name.OU = subject['OU']
    name.CN = subject['CN']
    return name
