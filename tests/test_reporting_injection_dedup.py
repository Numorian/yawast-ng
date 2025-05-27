import importlib

import pytest

import yawast.reporting.reporter as reporter
from yawast.reporting.injection import InjectionPoint


def setup_function():
    # Reset reporter module state before each test
    importlib.reload(reporter)
    reporter._output_file = "dummy.json"  # Enable output
    reporter._domain = "testdomain"
    reporter._injection_points.clear()


def test_register_injection_points_deduplication():
    setup_function()
    point1 = InjectionPoint("url", "field", "GET", "val")
    point2 = InjectionPoint("url", "field", "GET", "val")  # Duplicate of point1
    point3 = InjectionPoint("url", "field", "POST", "val")

    # Add first point
    reporter.register_injection_points([point1])
    assert len(reporter._injection_points["testdomain"]) == 1

    # Add duplicate point
    reporter.register_injection_points([point2])
    assert len(reporter._injection_points["testdomain"]) == 1  # Should not increase

    # Add a different point
    reporter.register_injection_points([point3])
    assert len(reporter._injection_points["testdomain"]) == 2
    assert point1 in reporter._injection_points["testdomain"]
    assert point3 in reporter._injection_points["testdomain"]
