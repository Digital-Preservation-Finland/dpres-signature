"""Create and verify SMIME/X509 signed manifest files"""

import os


from dpres_signature.manifest import Manifest, ManifestError
from dpres_signature.smime import smime_sign, smime_verify


def check_filelist(manifest, files):
    """
    Verify that manifest includes given files

    :param list manifest: List of files read from the manifest
    :param list files: List of files provided separately from the manifest

    :raises ManifestError: If a required file is missing
    """
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
    """
    Verify SMIME/X509 signed manifest

    :param str signature_path: Path to the signature file
    :param str ca_path: path to the CA directory
    :param list filelist: List of file paths associated with the manifest

    :raises ManifestError: If the manifest is invalid
    """
    with open(signature_path, 'rb') as infile:
        manifest_data = smime_verify(ca_path, infile.read())

    # For signature verification, the manifest_data is handled as string.
    manifest_data = manifest_data.decode("utf-8")
    manifest_data = manifest_data.strip().splitlines()
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


def create_signature(base_path, key_path, include_patterns,
                     cert_path=None, algorithm='sha1'):
    """Create SMIME/X509 signed manifest

    :param str base_path: Base path of files
    :param str key_path: Path to the key file
    :param list include_patterns: List of files to sign
    :param str cert_path: Path to the certificate file
    :param str algorithm: The used algorithm (e.g. 'sha256')

    :returns: Created signature
    :rtype: bytes
    """

    manifest = Manifest(base_path)

    for pattern in include_patterns:
        if pattern[0] == '/' or pattern.find("..") != -1:
            raise ManifestError("Path %s is illegal" % pattern)
        manifest.add_file(pattern, algorithm)

    return smime_sign(key_path, cert_path, manifest, algorithm)
