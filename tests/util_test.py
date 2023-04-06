"""Tests for util.py"""
import os

import pytest

from dpres_signature import util


@pytest.mark.parametrize(
    "initial_value",
    (
        (None),
        ("0"),
        ("1")
    )
)
def test_enabling_sha1(initial_value):
    """Test that sha1 is enabled during the context manager, and set to old
    value when exiting the context manager.
    """
    enable_sha1_env_var = "OPENSSL_ENABLE_SHA1_SIGNATURES"

    if initial_value is None:
        if os.environ.get(enable_sha1_env_var):
            del os.environ[enable_sha1_env_var]
    else:
        os.environ[enable_sha1_env_var] = initial_value

    assert os.environ.get(enable_sha1_env_var) == initial_value
    with util.enable_insecure_sha1_crypto():
        assert os.environ.get(enable_sha1_env_var) == "1"
    assert os.environ.get(enable_sha1_env_var) == initial_value
