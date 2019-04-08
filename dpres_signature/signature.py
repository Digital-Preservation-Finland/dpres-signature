"""Create and verify SMIME/X509 signed manifest files"""

import os
import six
from io import open
from dpres_signature.smime import smime_verify, smime_sign
from dpres_signature.manifest import Manifest, ManifestError


def check_filelist(manifest, files):
    """Verify that manifest includes given files"""
    if not files:
        return
    manifest_files = []
    for line in manifest:
        manifest_files.append(line.split(':')[0])
    for ind, name in enumerate(manifest_files):
        manifest_files[ind] = os.path.normpath(name)
    for name in files:
        if name not in manifest_files:
            raise ManifestError(
                'Required file %s missing from manifest' % name)
    return


def signature_verify(signature_path, ca_path='/etc/ssl/certs', filelist=None):
    """Verify SMIME/X509 signed manifest"""
    with open(signature_path, 'rb') as infile:
        manifest_data = smime_verify(ca_path, infile.read())

    # For signature verification, the manifest_data is handled as string.
    manifest_data = _ensure_str(manifest_data.strip()).splitlines()
    if '' in manifest_data:
        manifest_data = manifest_data[(manifest_data.index('') + 1):]
    if not manifest_data:
        raise ManifestError('Empty manifest data')

    check_filelist(manifest_data, filelist)

    base_path = os.path.dirname(signature_path)
    for line in manifest_data:
        manifest = Manifest.from_string(line, base_path)
        manifest.verify()
    return 0


def create_signature(signature_path, key_path, include_patterns,
                     cert_path=None):
    """Create SMIME/X509 signed manifest"""

    base_path = os.path.dirname(signature_path)
    manifest = Manifest(base_path)

    for pattern in include_patterns:
        if pattern[0] == '/' or pattern.find("..") != -1:
            raise ManifestError("Path %s is illegal" % pattern)
        manifest.add_file(pattern)

    return smime_sign(key_path, cert_path, manifest)


def _ensure_str(s, encoding='utf-8', errors='strict'):
    """Coerce *s* to `str`.

    For Python 2:
      - `unicode` -> encoded to `str`
      - `str` -> `str`

    For Python 3:
      - `str` -> `str`
      - `bytes` -> decoded to `str`

    Direct copy from release 1.12::

        https://github.com/benjaminp/six/blob/1.12.0/six.py#L872
    """
    if not isinstance(s, (six.text_type, six.binary_type)):
        raise TypeError("not expecting type '%s'" % type(s))
    if six.PY2 and isinstance(s, six.text_type):
        s = s.encode(encoding, errors)
    elif six.PY3 and isinstance(s, six.binary_type):
        s = s.decode(encoding, errors)
    return s
