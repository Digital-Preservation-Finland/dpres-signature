"""Setup.py installation."""
from setuptools import setup, find_packages


def main():
    """Install dpres_signature Python libraries"""
    setup(
        name='dpres_signature',
        packages=find_packages(exclude=['tests', 'tests.*']),
        include_package_data=True,
        entry_points={
            'console_scripts': [
                'sign-file = dpres_signature.scripts.sign_file:main',
                ('verify-signed-file = '
                 'dpres_signature.scripts.verify_signed_file:main')
            ]
        },
        setup_requires=["setuptools-scm"],
        use_scm_version={
            "write_to": "dpres_signature/_version.py"
        },
        install_requires=[
            'M2Crypto'
        ]
    )


if __name__ == '__main__':
    main()
