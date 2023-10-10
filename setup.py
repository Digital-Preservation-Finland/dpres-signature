"""Setup.py installation."""
import os
import sys

from setuptools import setup, find_packages
from version import get_version


def main():
    """Install dpres_signature Python libraries"""
    setup(
        name='dpres_signature',
        packages=find_packages(exclude=['tests', 'tests.*']),
        include_package_data=True,
        version=get_version(),
        entry_points={
            'console_scripts': [
                'sign-file = dpres_signature.scripts.sign_file:main',
                ('verify-signed-file = '
                 'dpres_signature.scripts.verify_signed_file:main')
            ]
        },
        install_requires=[
            'M2Crypto'
        ]
    )


if __name__ == '__main__':
    main()
