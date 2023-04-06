import os
from contextlib import contextmanager

import six

ENABLE_SHA1_ENV_VAR = "OPENSSL_ENABLE_SHA1_SIGNATURES"


def ensure_binary(text):
    """
    Encode given string to a byte string if it's Unicode or return
    it unchanged if it's a byte string
    """
    if isinstance(text, six.text_type):
        return text.encode("utf-8")
    elif isinstance(text, six.binary_type):
        return text
    else:
        raise TypeError("Expected a (byte) string, got {}".format(type(text)))


def ensure_text(text):
    """
    Encode given string to an Unicode string from UTF-8 if it's a byte string
    or return it unchanged if it's a byte string
    """
    if isinstance(text, six.binary_type):
        return text.decode("utf-8")
    elif isinstance(text, six.text_type):
        return text
    else:
        raise TypeError("Expected a (byte) string, got {}".format(type(text)))


# TODO: SHA1 and this function enabling it should be deprecated.
@contextmanager
def enable_insecure_sha1_crypto():
    """
    Context manager for enabling SHA1 in Fedora-based distros.

    Sets the environment variable OPENSSL_ENABLE_SHA1_SIGNATURES to "1",
    enabling SHA1 although from from v.3.0 onward OpenSSL forbids SHA1 by
    default in osme contexts. The environment variable is set for the duration
    of the context manager, setting it back to the initial value when exiting
    the context manager. The environment variable is only available in
    Fedora-based distros, so this function might not work in other
    environments.
    """
    old_value = os.environ.get(ENABLE_SHA1_ENV_VAR)
    os.environ[ENABLE_SHA1_ENV_VAR] = "1"

    try:
        yield None
    finally:
        if old_value is None:
            del os.environ[ENABLE_SHA1_ENV_VAR]
        else:
            os.environ[ENABLE_SHA1_ENV_VAR] = old_value
