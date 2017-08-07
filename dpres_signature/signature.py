"""Create and verify SMIME/X509 signed manifest files"""

import os
import sys

from dpres_signature.smime import smime_verify, smime_sign
from dpres_signature.manifest import Manifest, ManifestError
from M2Crypto import SMIME


def check_filelist(manifest, files):
    """Verify that manifest includes given files
    """
    if files == None or files == '':
        return True
    manifest_files = []
    for line in manifest:
        manifest_files.append(line.split(':')[0])
    for ind, name in enumerate(manifest_files):
        manifest_files[ind] = os.path.normpath(name)
    for name in files:
        if not name in manifest_files:
            raise ManifestError(
                'Required file %s missing from manifest' % name)
    return


def signature_verify(signature_path, ca_path='/etc/ssl/certs', filelist=None):
    """Verify SMIME/X509 signed manifest"""
    with open(signature_path) as infile:
        manifest_data = smime_verify(ca_path, infile.read())

    manifest_data = manifest_data.strip().splitlines()
    if '' in manifest_data:
        manifest_data = manifest_data[(manifest_data.index('') + 1):]
    if len(manifest_data) == 0:
        raise ManifestError('Empty manifest data')

    check_filelist(manifest_data, filelist)

    base_path = os.path.dirname(signature_path)
    for line in manifest_data:
        manifest = Manifest.from_string(line, base_path)
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

