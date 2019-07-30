import sys
from setuptools import find_packages
from cx_Freeze import Executable
from os import path

if "build_exe" in sys.argv:
    from cx_Freeze import setup
else:
    from setuptools import setup

# Dependencies are automatically detected.
# I'm not sure about the *version.py files, but this hack works.
build_exe_options = {
    "packages": ["os", "dns"],
    "include_files": [
        "yawast\_static_version.py",
        ("yawast\_version.py", "lib/validator_collection/_version.py"),
    ],
    "includes": [
        "six",
        "appdirs",
        "packaging.version",
        "packaging.specifiers",
        "packaging.requirements",
        "html.parser",
        "setuptools.msvc",
        "psutil",
        "colorama",
        "validator_collection",
        "jsonschema",
        "cryptography",
        "_cffi_backend",
        "requests",
        "requests.packages.idna",
        "requests.packages.idna.idnadata",
        "idna.idnadata",
        "publicsuffixlist",
        "sslyze",
        "bs4",
        "selenium",
    ],
    "excludes": ["tkinter"],
}
bdist_msi_options = {"add_to_path": True}

if getattr(sys, "frozen", False):
    # frozen
    root_path = path.dirname(sys.executable)
else:
    # unfrozen
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
    """Convert the README file into the long description.
    """
    with open(path.join(root_path, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
    return long_description


setup(
    name="yawast",
    version=version,
    cmdclass=cmdclass,
    description="The YAWAST Antecedent Web Application Security Toolkit",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/adamcaudill/yawast",
    project_urls={
        "Bug Reports": "https://github.com/adamcaudill/yawast/issues",
        "Source": "https://github.com/adamcaudill/yawast",
        "Changelog": "https://github.com/adamcaudill/yawast/blob/master/CHANGELOG.md",
    },
    author="Adam Caudill",
    author_email="adam@adamcaudill.com",
    license="MIT",
    options={"build_exe": build_exe_options, "build_msi": bdist_msi_options},
    executables=[Executable("bin/yawast", base=None)],
    packages=find_packages(exclude=["tests"]),
    scripts=["bin/yawast"],
    install_requires=[
        "validator-collection",
        "requests",
        "publicsuffixlist",
        "dnspython",
        "urllib3",
        "colorama",
        "sslyze==2.1.3",
        "nassl",
        "cryptography==2.5",
        "packaging",
        "beautifulsoup4",
        "psutil",
        "pipenv",
        "requests-mock",
    ],
    include_package_data=True,
    package_data={"yawast": ["resources/*"]},
    zip_safe=False,
    python_requires=">=3.6",
    keywords="security tls ssl dns http scan vulnerability",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Natural Language :: English",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
)
