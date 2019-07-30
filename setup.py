"""Setup.py installation."""
import os
import sys

from setuptools import setup, find_packages
from version import get_version


def scripts_list():
    """Return list of command line tools from package
    dpres_signature.scripts"""
    scripts = []
    for modulename in os.listdir('dpres_signature/scripts'):
        if modulename == '__init__.py':
            continue
        if not modulename.endswith('.py'):
            continue
        modulename = modulename.replace('.py', '')
        scriptname = modulename.replace('_', '-')
        scripts.append(
            '%s = dpres_signature.scripts.%s:main' % (scriptname, modulename))
    print(scripts)
    return scripts


def main():
    """Install dpres_signature Python libraries"""
    setup(
        name='dpres_signature',
        packages=find_packages(exclude=['tests', 'tests.*']),
        include_package_data=True,
        version=get_version(),
        entry_points={'console_scripts': scripts_list()},
        install_requires=['M2Crypto']
    )
    return 0


if __name__ == '__main__':
    RETVAL = main()
    sys.exit(RETVAL)
