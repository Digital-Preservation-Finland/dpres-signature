"""Create and verify SMIME/X509 signed manifest files

Specific functions have been adapted from a MIT licensed open source solution:

Copyright (c) 2018 Benjamin Peterson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import unicode_literals

import io
import os

import six

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


def create_signature(signature_path, key_path, include_patterns,
                     cert_path=None):
    """Create SMIME/X509 signed manifest

    :param str signature_path: Path to the signature file
    :param str key_path: Path to the key file
    :param list include_patterns: List of files to sign
    :param str cert_path: Path to the certificate file

    :returns: Created signature
    :rtype: bytes
    """

    base_path = os.path.dirname(signature_path)
    manifest = Manifest(base_path)

    for pattern in include_patterns:
        if pattern[0] == '/' or pattern.find("..") != -1:
            raise ManifestError("Path %s is illegal" % pattern)
        manifest.add_file(pattern)

    return smime_sign(key_path, cert_path, manifest)
