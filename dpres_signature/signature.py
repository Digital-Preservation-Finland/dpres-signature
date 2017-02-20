"""Create and verify SMIME/X509 signed manifest files"""

import os

from dpres_signature.smime import smime_verify, smime_sign
from dpres_signature.manifest import Manifest, ManifestError


def signature_verify(signature_path, ca_path='/etc/ssl/certs'):
    """Verify SMIME/X509 signed manifest"""
    if not os.path.isfile(signature_path):
        return 117
    with open(signature_path) as infile:
        manifest_data = smime_verify(ca_path, infile.read())

    base_path = os.path.dirname(signature_path)
    manifest = Manifest.from_string(manifest_data, base_path)
    manifest.verify()
    return 0


def signature_write(signature_path, key_path, cert_path, include_patterns):
    """Write SMIME/X509 signed manifest"""

    base_path = os.path.dirname(signature_path)
    manifest = Manifest(base_path)

    for pattern in include_patterns:
        if pattern[0] == '/' or pattern.find("..") != -1:
            raise ManifestError("Path %s is illegal" % pattern)
        manifest.add_file(pattern)

    signature = smime_sign(key_path, cert_path, manifest)

    with open(signature_path, 'w') as outfile:
        outfile.write(signature)
    return 0
