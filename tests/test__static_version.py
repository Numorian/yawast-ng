# Copyright (c) 2025 Adam Caudill and Contributors.
# Unit test for yawast/_static_version.py
import importlib
import sys
import types


def test_static_version_attributes():
    mod = importlib.import_module("yawast._static_version")
    assert hasattr(mod, "version")
    assert hasattr(mod, "refnames")
    assert hasattr(mod, "git_hash")
    assert isinstance(mod.version, str)
    assert isinstance(mod.refnames, str)
    assert isinstance(mod.git_hash, str)
    # Check the default values
    assert mod.version == "__use_git__"
    assert mod.refnames.startswith("$Format:")
    assert mod.git_hash.startswith("$Format:")
