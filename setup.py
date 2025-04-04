#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from os import path

# from requirementslib import Lockfile
from setuptools import find_packages

from setuptools import setup


root_path = path.dirname(path.realpath(__file__))


def get_version_and_cmdclass(package_path):
    """Load version.py module without importing the whole package.

    Template code from miniver
    """
    import os
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("version", os.path.join(package_path, "_version.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__version__, module.cmdclass


version, cmdclass = get_version_and_cmdclass("yawast")


def get_long_description():
    """Convert the README file into the long description."""
    with open(path.join(root_path, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
    return long_description


def get_install_reqs():
    # TODO: Do something useful here.
    return []


setup(
    name="yawast-ng",
    version=version,
    cmdclass=cmdclass,
    description="The YAWAST Antecedent Web Application Security Toolkit",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/Numorian/yawast-ng",
    project_urls={
        "Bug Reports": "https://github.com/Numorian/yawast-ng/issues",
        "Source": "https://github.com/Numorian/yawast-ng",
        "Changelog": "https://github.com/Numorian/yawast-ng/blob/master/CHANGELOG.md",
    },
    author="Adam Caudill",
    author_email="adam@adamcaudill.com",
    license="MIT",
    packages=find_packages(exclude=["tests"]),
    entry_points={"console_scripts": ["yawast = yawast.__main__:main"]},
    install_requires=[
        "sslyze==6.0.0",
        "requests-mock>=1.12,<2.0.0",
        "jsonschema>=4.0,<5.0.0",
        "validator-collection>=1.5.0,<2.0.0",
        "requests",
        "publicsuffixlist>=1.0.0,<2.0.0",
        "dnspython>=2.7,<3.0.0",
        "urllib3",
        "colorama>=0.4.0,<0.5.0",
        "nassl>=5.2,<6",
        "cryptography>42,<43",
        "packaging>=24.2,<25.0",
        "beautifulsoup4>=4.13.0,<5.0.0",
        "psutil>=7.0,<8.0.0",
        "selenium>=4.30,<5.0.0",
        "setuptools>=78.1,<79.0.0",
        "ordered-set>=4.1.0,<5.0.0",
        "python-dateutil>=2.9.0,<3.0.0",
        "webdriver-manager",
    ],
    include_package_data=True,
    package_data={"yawast.resources": ["resources/*"]},
    zip_safe=False,
    python_requires=">=3.9",
    keywords="security tls ssl dns http scan vulnerability",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Natural Language :: English",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
)
