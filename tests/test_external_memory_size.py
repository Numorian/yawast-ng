import pytest

from yawast.external.memory_size import Size


def test_size_numeric_formats():
    s = Size(1024)
    assert format(s, "d") == "1024"
    assert format(s, "x") == format(1024, "x")
    assert format(s, "") == "1024"


def test_size_em_format():
    s = Size(128)
    # 128 bytes = 1024 bits = 1Kib
    assert "Kib" in format(s, "em")
    # With width and precision
    assert format(s, "10.1em").strip().endswith("Kib")


def test_size_eM_format():
    s = Size(1024)
    # 1024 bytes = 1KiB
    assert "KiB" in format(s, "eM")


def test_size_sm_format():
    s = Size(125)
    # 125 bytes = 1000 bits = 1kb
    assert "kb" in format(s, "sm")


def test_size_sM_format():
    s = Size(1000)
    # 1000 bytes = 1KB
    assert "KB" in format(s, "sM")


def test_size_cm_format():
    s = Size(128)
    # 128 bytes = 1024 bits = 1Kb
    assert "Kb" in format(s, "cm")


def test_size_cM_format():
    s = Size(1024)
    # 1024 bytes = 1KB
    assert "KB" in format(s, "cM")


def test_size_non_special_format():
    s = Size(123)
    # Should fallback to str formatting
    assert format(s, "s") == str(s)
