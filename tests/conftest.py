"""conftest.py"""
import pytest
from tests.fixtures import *

def pytest_addoption(parser):
    """add option"""
    parser.addoption(
        "--test-path", action="store",
        help="Use given directory for storing temporary test files "
        "(default: system tempdir)",
        default="/tmp/")
